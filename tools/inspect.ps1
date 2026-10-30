$ErrorActionPreference = 'Stop'
$root = Join-Path ${env:ProgramFiles(x86)} 'UniVPN'
$records = @()
$stateRoot = Join-Path $root '.univpn-multi'
if (Test-Path -LiteralPath $stateRoot) {
    foreach ($file in @(Get-ChildItem -LiteralPath $stateRoot -Filter 'instance-*.json' -File)) {
        try {
            $value = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            $records += [ordered]@{ index=[int]$value.Number; tapGuid=[string]$value.TapGuid; status=[string]$value.Status }
        } catch {}
    }
}
$adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like 'TAP-Windows Adapter V9*' } | ForEach-Object {
    $adapter = $_
    $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -ExpandProperty IPAddress)
    [ordered]@{ guid=([guid]$adapter.InterfaceGuid).ToString('B').ToUpperInvariant(); up=([string]$adapter.Status -eq 'Up'); addresses=$addresses }
})
$processes = @(Get-CimInstance Win32_Process -Property Name,ProcessId,ParentProcessId,SessionId,CreationDate | Where-Object { $_.Name -match '^(UniVPN|UVP\d{3})(CS)?\.exe$' } | ForEach-Object {
    [ordered]@{ name=($_.Name -replace '\.exe$',''); pid=$_.ProcessId; parent=$_.ParentProcessId; session=$_.SessionId; created=$_.CreationDate.ToUniversalTime().ToString('o') }
})
$services = @(Get-CimInstance Win32_Service -Property Name,State,ProcessId,PathName,StartName | Where-Object { $_.Name -match '^(UniVPN|UVP\d{3})Service$' } | ForEach-Object {
    $serviceProcess=Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
    $serviceSession=if($serviceProcess){[int]$serviceProcess.SessionId}else{$null}
    [ordered]@{ name=$_.Name; state=$_.State; pid=$_.ProcessId; path=$_.PathName; account=$_.StartName; session=$serviceSession }
})
$backends = @($processes | Where-Object { $_.name -like '*CS' })
$peers = @()
$listeners = @()
foreach ($line in @(& (Join-Path ([Environment]::SystemDirectory) 'netstat.exe') -ano)) {
    if ($line -match '^\s*TCP\s+(\S+):([0-9]+)\s+\S+\s+LISTENING\s+([0-9]+)\s*$') {
        $listeners += [ordered]@{address=$Matches[1].Trim('[',']');port=[int]$Matches[2];pid=[int]$Matches[3]}
    }
    if ($line -match '^\s*TCP\s+\S+\s+([0-9.]+):([0-9]+)\s+ESTABLISHED\s+([0-9]+)\s*$') {
        $address = $Matches[1]; $port = [int]$Matches[2]; $ownerId = [int]$Matches[3]
        if ($address -notlike '127.*') {
            $backend = @($backends | Where-Object { $_.pid -eq $ownerId })
            if ($backend.Count -eq 1) { $peers += [ordered]@{ process=$backend[0].name; gateway=$address; port=$port } }
        }
    }
}
[ordered]@{ installed=(Test-Path -LiteralPath (Join-Path $root 'UniVPN.exe')); sourceDirectory=$root; records=$records; adapters=$adapters; processes=$processes; services=$services; peers=$peers; listeners=$listeners } | ConvertTo-Json -Depth 7 -Compress
