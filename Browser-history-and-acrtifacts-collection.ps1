[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\BrowserHistory-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [int]   $LookbackHours = 24,
  [switch]$NoProgress,
  [int]   $Arg1
)

if ($PSBoundParameters.ContainsKey('Arg1') -and -not $PSBoundParameters.ContainsKey('LookbackHours')) {
  $LookbackHours = [int]$Arg1
}

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$runStart  = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 { param($dt) if($dt -and $dt -is [datetime] -and $dt.Year -gt 1900){ $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Ensure-SqliteModule {
  if(-not(Get-Module -ListAvailable -Name PSSQLite)){
    Write-Log "PSSQLite module not found. Installing to temp location..." 'INFO'
    
    try {
        # Use a unique temp path to avoid conflicts
        $uniqueId = [guid]::NewGuid().ToString('N').Substring(0,8)
        $tempModPath = Join-Path $env:TEMP "PSModules_$uniqueId"
        if (-not (Test-Path $tempModPath)) { 
            New-Item -Path $tempModPath -ItemType Directory -Force | Out-Null 
        }
        
        # Download the module package directly
        $packageUrl = "https://www.powershellgallery.com/api/v2/package/PSSQLite"
        $zipPath = Join-Path $env:TEMP "PSSQLite_$uniqueId.zip"
        
        Write-Log "Downloading PSSQLite..." 'INFO'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $packageUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        
        # Extract
        $extractPath = Join-Path $tempModPath "PSSQLite"
        
        # Clean up any existing extraction
        if (Test-Path $extractPath) { 
            try {
                Remove-Item $extractPath -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Log "Warning: Could not clean existing module path: $($_.Exception.Message)" 'WARN'
                # Try alternative path
                $extractPath = Join-Path $tempModPath "PSSQLite_$uniqueId"
            }
        }
        
        Write-Log "Extracting to: $extractPath" 'INFO'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
        
        # Find the actual module directory (may be nested)
        $psd1File = Get-ChildItem -Path $extractPath -Filter "PSSQLite.psd1" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($psd1File) {
            $moduleRoot = $psd1File.DirectoryName
            Write-Log "Found module at: $moduleRoot" 'INFO'
        } else {
            $moduleRoot = $extractPath
        }
        
        # Import
        Import-Module $moduleRoot -Force -ErrorAction Stop
        Write-Log "PSSQLite loaded successfully" 'INFO'
        
        # Cleanup zip only (keep extracted module for the session)
        try { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue } catch {}
        
    } catch {
        Write-Log "Failed to install PSSQLite: $($_.Exception.Message)" 'ERROR'
        throw "Unable to install or load PSSQLite module"
    }
  } else {
    Import-Module PSSQLite -Force
  }
}

function Query-Sqlite {
  param([string]$DbPath,[string]$Query)
  if(-not(Test-Path $DbPath)){ return @() }
  
  $temp=Join-Path $env:TEMP ([IO.Path]::GetFileName($DbPath) + '.' + [guid]::NewGuid().ToString('N') + '.sqlite')
  if(-not (Copy-LockedFile -Source $DbPath -Dest $temp)){
    Write-Log ("Query-Sqlite skip (locked) {0}" -f $DbPath) 'WARN'
    return @()
  }
  
  try {
    if ($script:UseSQLiteDirect) {
      # Direct SQLite query without PSSQLite module
      $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$temp;Version=3;Read Only=True;")
      $conn.Open()
      $cmd = $conn.CreateCommand()
      $cmd.CommandText = $Query
      $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)
      $dataset = New-Object System.Data.DataSet
      [void]$adapter.Fill($dataset)
      $conn.Close()
      return $dataset.Tables[0].Rows
    } else {
      # Use PSSQLite module
      Invoke-SqliteQuery -DataSource $temp -Query $Query
    }
  } catch {
    Write-Log ("Query-Sqlite failed {0}: {1}" -f $DbPath,$_.Exception.Message) 'WARN'
    @()
  } finally { 
    try { Remove-Item $temp -Force -ErrorAction SilentlyContinue } catch {}
  }
}

function Copy-LockedFile {
  param([string]$Source,[string]$Dest,[int]$Retries=6,[int]$DelayMs=150)
  for($i=0;$i -lt $Retries;$i++){
    try{ Copy-Item $Source $Dest -Force -ErrorAction Stop; return $true }catch{
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
  try{ Invoke-SqliteQuery -DataSource $temp -Query $Query }catch{
    Write-Log ("Query-Sqlite failed {0}: {1}" -f $DbPath,$_.Exception.Message) 'WARN'
    @()
  }finally{ try{ Remove-Item $temp -Force -ErrorAction SilentlyContinue }catch{} }
}

Rotate-Log
Write-Log "=== SCRIPT START : Collect Browser History and Artifacts ==="

$tsNow = To-ISO8601 (Get-Date)
$lines = New-Object System.Collections.ArrayList

try{
  Ensure-SqliteModule

  Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700

  $summary = @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'collect_browser_artifacts'
    copilot_action = $true
    item           = 'summary'
    description    = 'Run summary and counts'
    lookback_hours = $LookbackHours
    counts         = @{ chrome=@{history=0;downloads=0;cookies=0;bookmarks=0}; edge=@{history=0;downloads=0;cookies=0;bookmarks=0}; firefox=@{history=0;downloads=0;cookies=0;bookmarks=0} }
    duration_s     = $null
  }

  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'collect_browser_artifacts'
    copilot_action = $true
    item           = 'verify_source'
    description    = 'Input parameters and environment'
    computer       = $HostName
    lookback_hours = $LookbackHours
    pssqlite_loaded= [bool](Get-Module PSSQLite)
  }) )

  $sinceSql = "datetime('now','-{0} hours')" -f ([int]$LookbackHours)

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

    foreach($r in $hist){ $summary.counts.chrome.history++; [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='history';description='Chrome history visit';browser='chrome';url=$r.url;title=$r.title;time=$r.t}) ) }
    foreach($r in $dwn ){ $summary.counts.chrome.downloads++; [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='download';description='Chrome download entry';browser='chrome';path=$r.target_path;source=$r.tab_url;time=$r.t}) ) }
    foreach($r in $cks ){ $summary.counts.chrome.cookies++;   [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='cookie';description='Chrome cookie snapshot (value may be encrypted/newer Chromium)';browser='chrome';cookie_host=$r.host_key;name=$r.name;value=$r.value;expires=$r.expires}) ) }

    $bmFile="$chromeBase\Bookmarks"
    if(Test-Path $bmFile){
      try{
        $bm=Get-Content $bmFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $stack=@($bm.roots.bookmark_bar.children + $bm.roots.other.children + $bm.roots.synced.children) | Where-Object { $_ -ne $null }
        foreach($b in $stack){
          if($b.type -eq 'url'){
            $summary.counts.chrome.bookmarks++
            [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='bookmark';description='Chrome bookmark';browser='chrome';name=$b.name;url=$b.url}) )
          }elseif($b.children){
            foreach($c in $b.children){
              if($c.type -eq 'url'){
                $summary.counts.chrome.bookmarks++
                [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='bookmark';description='Chrome bookmark';browser='chrome';name=$c.name;url=$c.url}) )
              }
            }
          }
        }
      }catch{ Write-Log ("Chrome bookmarks parse failed: {0}" -f $_.Exception.Message) 'WARN' }
    }
  }

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

    foreach($r in $hist){ $summary.counts.edge.history++; [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='history';description='Edge history visit';browser='edge';url=$r.url;title=$r.title;time=$r.t}) ) }
    foreach($r in $dwn ){ $summary.counts.edge.downloads++; [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='download';description='Edge download entry';browser='edge';path=$r.target_path;source=$r.tab_url;time=$r.t}) ) }
    foreach($r in $cks ){ $summary.counts.edge.cookies++;   [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='cookie';description='Edge cookie snapshot (value may be encrypted/newer Chromium)';browser='edge';cookie_host=$r.host_key;name=$r.name;value=$r.value;expires=$r.expires}) ) }

    $bmFile="$edgeBase\Bookmarks"
    if(Test-Path $bmFile){
      try{
        $bm=Get-Content $bmFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $stack=@($bm.roots.bookmark_bar.children + $bm.roots.other.children + $bm.roots.synced.children) | Where-Object { $_ -ne $null }
        foreach($b in $stack){
          if($b.type -eq 'url'){
            $summary.counts.edge.bookmarks++
            [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='bookmark';description='Edge bookmark';browser='edge';name=$b.name;url=$b.url}) )
          }elseif($b.children){
            foreach($c in $b.children){
              if($c.type -eq 'url'){
                $summary.counts.edge.bookmarks++
                [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='bookmark';description='Edge bookmark';browser='edge';name=$c.name;url=$c.url}) )
              }
            }
          }
        }
      }catch{ Write-Log ("Edge bookmarks parse failed: {0}" -f $_.Exception.Message) 'WARN' }
    }
  }

  $ffProfiles=Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
  foreach($profile in $ffProfiles){
    $p=$profile.FullName
    $places="$p\places.sqlite";$cookies="$p\cookies.sqlite";$downloads="$p\downloads.sqlite"

    if(Test-Path $places){
      $q="SELECT url,title,datetime(last_visit_date/1000000,'unixepoch') as t FROM moz_places WHERE datetime(last_visit_date/1000000,'unixepoch') >= $sinceSql ORDER BY last_visit_date DESC LIMIT 50000"
      $r=Query-Sqlite $places $q
      foreach($x in $r){ $summary.counts.firefox.history++; [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='history';description='Firefox history visit';browser='firefox';url=$x.url;title=$x.title;time=$x.t}) ) }
    }
    if(Test-Path $downloads){
      $q="SELECT name,source,datetime(endTime/1000000,'unixepoch') as t FROM moz_downloads WHERE datetime(endTime/1000000,'unixepoch') >= $sinceSql ORDER BY t DESC LIMIT 50000"
      $r=Query-Sqlite $downloads $q
      foreach($x in $r){ $summary.counts.firefox.downloads++; [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='download';description='Firefox download entry';browser='firefox';name=$x.name;source=$x.source;time=$x.t}) ) }
    }
    if(Test-Path $cookies){
      $q="SELECT host,name,value,datetime(expiry,'unixepoch') as expires FROM moz_cookies LIMIT 20000"
      $r=Query-Sqlite $cookies $q
      foreach($x in $r){ $summary.counts.firefox.cookies++; [void]$lines.Add( (New-NdjsonLine @{timestamp=$tsNow;host=$HostName;action='collect_browser_artifacts';copilot_action=$true;item='cookie';description='Firefox cookie snapshot';browser='firefox';cookie_host=$x.host;name=$x.name;value=$x.value;expires=$x.expires}) ) }
    }
    break
  }

  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'collect_browser_artifacts'
    copilot_action = $true
    item           = 'channel_status'
    description    = 'Detected browser profile locations'
    chrome_present = (Test-Path $chromeBase)
    edge_present   = (Test-Path $edgeBase)
    firefox_profiles = @($ffProfiles | ForEach-Object { $_.Name })
  }) )

  $summary.duration_s = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  $lines = ,(New-NdjsonLine $summary) + $lines

  if(-not $NoProgress){ Write-Host ("Wrote {0} NDJSON lines" -f $lines.Count) }
  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0}" -f $ARLog) 'INFO'
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = 'collect_browser_artifacts'
    copilot_action = $true
    item           = 'error'
    description    = 'Unhandled error during browser artifact collection'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
