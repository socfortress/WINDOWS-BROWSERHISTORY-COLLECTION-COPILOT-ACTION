[CmdletBinding()]
param(
  [string]$LogPath="$env:TEMP\BrowserHistory-script.log",
  [string]$ARLog='C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [int]$LookbackHours=24,
  [switch]$NoProgress
)

if ($Arg1 -and -not $LookbackHours) { $LookbackHours = $Arg1 }

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN'{Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath." + ($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Ensure-SqliteModule {
  if(-not(Get-Module -ListAvailable -Name PSSQLite)){
    Write-Log "PSSQLite module not found. Installing..." 'INFO'
    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    Install-Module -Name PSSQLite -Scope CurrentUser -Force -ErrorAction Stop
    Write-Log "PSSQLite installed successfully." 'INFO'
  }
  Import-Module PSSQLite -Force
}

function Copy-LockedFile {
  param([string]$Source,[string]$Dest,[int]$Retries=6,[int]$DelayMs=150)
  for($i=0;$i -lt $Retries;$i++){
    try{
      Copy-Item $Source $Dest -Force -ErrorAction Stop
      return $true
    }catch{
      try{
        $in=[System.IO.File]::Open($Source,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        try{
          $out=[System.IO.File]::Open($Dest,[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
          try{
            $buf=New-Object byte[] 1048576
            while(($read=$in.Read($buf,0,$buf.Length)) -gt 0){$out.Write($buf,0,$read)}
            return $true
          }finally{$out.Dispose()}
        }finally{$in.Dispose()}
      }catch{
        if($i -eq 0){ Write-Log ("Copy-LockedFile warning for {0}: {1}" -f $Source,$_.Exception.Message) 'WARN' }
        Start-Sleep -Milliseconds $DelayMs
      }
    }
  }
  Write-Log ("Copy-LockedFile gave up for {0}" -f $Source) 'WARN'
  return $false
}

function Query-Sqlite {
  param([string]$DbPath,[string]$Query)
  if(-not(Test-Path $DbPath)){ return @() }
  $temp=Join-Path $env:TEMP ([IO.Path]::GetFileName($DbPath) + '.' + [guid]::NewGuid().ToString('N') + '.sqlite')
  if(-not (Copy-LockedFile -Source $DbPath -Dest $temp)){
    Write-Log ("Query-Sqlite skip (locked) {0}" -f $DbPath) 'WARN'
    return @()
  }
  try{
    Invoke-SqliteQuery -DataSource $temp -Query $Query
  }catch{
    Write-Log ("Query-Sqlite failed {0}: {1}" -f $DbPath,$_.Exception.Message) 'WARN'
    @()
  }finally{
    try{ Remove-Item $temp -Force -ErrorAction SilentlyContinue }catch{}
  }
}

function Now-Timestamp {
  $tz=(Get-Date).ToString('zzz').Replace(':','')
  (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')+$tz
}

function Write-NDJSONLines {
  param([string[]]$JsonLines)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try{Move-Item -Path $tmp -Destination $ARLog -Force}catch{Move-Item -Path $tmp -Destination ($ARLog+'.new') -Force}
}

Rotate-Log
Write-Log "=== SCRIPT START : Collect Browser History and Artifacts ==="

try {
  Ensure-SqliteModule

  # Auto-close Chrome to ensure full access to its SQLite DBs
  Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700

  $ts=Now-Timestamp
  $sinceSql = "datetime('now','-{0} hours')" -f ([int]$LookbackHours)

  $lines=@()
  $total=@{chrome=@{history=0;downloads=0;cookies=0;bookmarks=0};edge=@{history=0;downloads=0;cookies=0;bookmarks=0};firefox=@{history=0;downloads=0;cookies=0;bookmarks=0}}

  # Chrome (use visits for complete last-N-hours history)
  $chromeBase="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
  if(Test-Path $chromeBase){
    $qHist=@"
SELECT u.url, u.title,
       datetime(v.visit_time/1000000-11644473600,'unixepoch') AS t
FROM visits v
JOIN urls u ON u.id = v.url
WHERE datetime(v.visit_time/1000000-11644473600,'unixepoch') >= $sinceSql
ORDER BY v.visit_time DESC
LIMIT 50000
"@
    $qDown="SELECT target_path,tab_url,datetime(start_time/1000000-11644473600,'unixepoch') as t FROM downloads WHERE datetime(start_time/1000000-11644473600,'unixepoch') >= $sinceSql ORDER BY start_time DESC LIMIT 50000"
    $qCook="SELECT host_key,name,value,datetime(expires_utc/1000000-11644473600,'unixepoch') as expires FROM cookies LIMIT 20000"
    $hist=Query-Sqlite "$chromeBase\History" $qHist
    $dwn =Query-Sqlite "$chromeBase\History" $qDown
    $cks =Query-Sqlite "$chromeBase\Network\Cookies" $qCook
    foreach($r in $hist){ $total.chrome.history++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='history';browser='chrome';url=$r.url;title=$r.title;time=$r.t}|ConvertTo-Json -Compress -Depth 4) }
    foreach($r in $dwn){ $total.chrome.downloads++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='download';browser='chrome';path=$r.target_path;source=$r.tab_url;time=$r.t}|ConvertTo-Json -Compress -Depth 4) }
    foreach($r in $cks){ $total.chrome.cookies++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='cookie';browser='chrome';cookie_host=$r.host_key;name=$r.name;value=$r.value;expires=$r.expires}|ConvertTo-Json -Compress -Depth 4) }
    $bmFile="$chromeBase\Bookmarks"
    if(Test-Path $bmFile){
      try{
        $bm=Get-Content $bmFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $stack=@($bm.roots.bookmark_bar.children + $bm.roots.other.children + $bm.roots.synced.children) | Where-Object { $_ -ne $null }
        foreach($b in $stack){
          if($b.type -eq 'url'){ $total.chrome.bookmarks++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='bookmark';browser='chrome';name=$b.name;url=$b.url}|ConvertTo-Json -Compress -Depth 4) }
          elseif($b.children){
            foreach($c in $b.children){
              if($c.type -eq 'url'){ $total.chrome.bookmarks++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='bookmark';browser='chrome';name=$c.name;url=$c.url}|ConvertTo-Json -Compress -Depth 4) }
            }
          }
        }
      }catch{ Write-Log ("Chrome bookmarks parse failed: {0}" -f $_.Exception.Message) 'WARN' }
    }
  }

  # Edge (also switch to visits join so last-N-hours is complete)
  $edgeBase="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
  if(Test-Path $edgeBase){
    $qHist=@"
SELECT u.url, u.title,
       datetime(v.visit_time/1000000-11644473600,'unixepoch') AS t
FROM visits v
JOIN urls u ON u.id = v.url
WHERE datetime(v.visit_time/1000000-11644473600,'unixepoch') >= $sinceSql
ORDER BY v.visit_time DESC
LIMIT 50000
"@
    $qDown="SELECT target_path,tab_url,datetime(start_time/1000000-11644473600,'unixepoch') as t FROM downloads WHERE datetime(start_time/1000000-11644473600,'unixepoch') >= $sinceSql ORDER BY start_time DESC LIMIT 50000"
    $qCook="SELECT host_key,name,value,datetime(expires_utc/1000000-11644473600,'unixepoch') as expires FROM cookies LIMIT 20000"
    $hist=Query-Sqlite "$edgeBase\History" $qHist
    $dwn =Query-Sqlite "$edgeBase\History" $qDown
    $cks =Query-Sqlite "$edgeBase\Network\Cookies" $qCook
    foreach($r in $hist){ $total.edge.history++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='history';browser='edge';url=$r.url;title=$r.title;time=$r.t}|ConvertTo-Json -Compress -Depth 4) }
    foreach($r in $dwn){ $total.edge.downloads++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='download';browser='edge';path=$r.target_path;source=$r.tab_url;time=$r.t}|ConvertTo-Json -Compress -Depth 4) }
    foreach($r in $cks){ $total.edge.cookies++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='cookie';browser='edge';cookie_host=$r.host_key;name=$r.name;value=$r.value;expires=$r.expires}|ConvertTo-Json -Compress -Depth 4) }
    $bmFile="$edgeBase\Bookmarks"
    if(Test-Path $bmFile){
      try{
        $bm=Get-Content $bmFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $stack=@($bm.roots.bookmark_bar.children + $bm.roots.other.children + $bm.roots.synced.children) | Where-Object { $_ -ne $null }
        foreach($b in $stack){
          if($b.type -eq 'url'){ $total.edge.bookmarks++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='bookmark';browser='edge';name=$b.name;url=$b.url}|ConvertTo-Json -Compress -Depth 4) }
          elseif($b.children){
            foreach($c in $b.children){
              if($c.type -eq 'url'){ $total.edge.bookmarks++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='bookmark';browser='edge';name=$c.name;url=$c.url}|ConvertTo-Json -Compress -Depth 4) }
            }
          }
        }
      }catch{ Write-Log ("Edge bookmarks parse failed: {0}" -f $_.Exception.Message) 'WARN' }
    }
  }

  # Firefox
  $ffProfiles=Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
  foreach($profile in $ffProfiles){
    $p=$profile.FullName
    $places="$p\places.sqlite";$cookies="$p\cookies.sqlite";$downloads="$p\downloads.sqlite"
    if(Test-Path $places){
      $q="SELECT url,title,datetime(last_visit_date/1000000,'unixepoch') as t FROM moz_places WHERE datetime(last_visit_date/1000000,'unixepoch') >= $sinceSql ORDER BY last_visit_date DESC LIMIT 50000"
      $r=Query-Sqlite $places $q
      foreach($x in $r){ $total.firefox.history++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='history';browser='firefox';url=$x.url;title=$x.title;time=$x.t}|ConvertTo-Json -Compress -Depth 4) }
    }
    if(Test-Path $downloads){
      $q="SELECT name,source,datetime(endTime/1000000,'unixepoch') as t FROM moz_downloads WHERE datetime(endTime/1000000,'unixepoch') >= $sinceSql ORDER BY t DESC LIMIT 50000"
      $r=Query-Sqlite $downloads $q
      foreach($x in $r){ $total.firefox.downloads++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='download';browser='firefox';name=$x.name;source=$x.source;time=$x.t}|ConvertTo-Json -Compress -Depth 4) }
    }
    if(Test-Path $cookies){
      $q="SELECT host,name,value,datetime(expiry,'unixepoch') as expires FROM moz_cookies LIMIT 20000"
      $r=Query-Sqlite $cookies $q
      foreach($x in $r){ $total.firefox.cookies++; $lines+=([pscustomobject]@{timestamp=$ts;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;type='cookie';browser='firefox';cookie_host=$x.host;name=$x.name;value=$x.value;expires=$x.expires}|ConvertTo-Json -Compress -Depth 4) }
    }
    break
  }

  $dur=[math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  $summary=[pscustomobject]@{
    timestamp=$ts
    host=$HostName
    action='collect_browser_artifacts'
    copilot_action=$true
    type='summary'
    lookback_hours=$LookbackHours
    counts=[pscustomobject]@{chrome=$total.chrome;edge=$total.edge;firefox=$total.firefox}
    duration_s=$dur
  }
  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 6 )) + $lines

  if(-not $NoProgress){Write-Host ("Wrote {0} NDJSON lines" -f $lines.Count)}
  Write-NDJSONLines -JsonLines $lines
  Write-Log ("NDJSON written to {0}" -f $ARLog) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp=Now-Timestamp
    host=$HostName
    action='collect_browser_artifacts'
    copilot_action=$true
    type='error'
    error=$_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(($err|ConvertTo-Json -Compress -Depth 4))
}
finally {
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
