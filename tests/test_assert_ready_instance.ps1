#requires -Version 5.1
# Synthetic metadata and command results only. No vendor script or binary runs.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Load built-ins before mocks so Windows PowerShell module autoload cannot
# replace the synthetic Get-FileHash when Write-Output or JSON runs later.
Import-Module Microsoft.PowerShell.Utility
$root=Split-Path $PSScriptRoot -Parent
$runtime=Join-Path $root 'vendor\multi-src\src\Runtime.ps1'
$tokens=$null
$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($runtime,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Runtime syntax is invalid.'}
foreach($name in @('Assert-ServiceOwner','Assert-ReadyInstance')){
    $node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $name},$true)
    if(-not $node){throw "Missing runtime function $name"}
    . ([scriptblock]::Create($node.Extent.Text))
}

$fixture=Join-Path ([IO.Path]::GetTempPath()) 'univpn-ready-synthetic-fixture'
$info=[pscustomobject]@{
    Number=4;Product='UVP004';Service='UVP004Service';VnicPort=36010
    Directory=(Join-Path $fixture 'UniVPN4');Alias=(Join-Path $fixture 'alias')
}
$tapGuid='{11111111-2222-3333-4444-555555555555}'
$targets=@('UVP004.exe','promote\UVP004PromoteService.exe','serviceclient\UVP004CS.exe')
$script:passed=0

function Assert-True([bool]$Condition,[string]$Name){
    if(-not $Condition){throw "FAIL $Name"}
    $script:passed++
    Write-Output "PASS $Name"
}
function Assert-Throws([scriptblock]$Body,[string]$Expected,[string]$Name){
    $caught=$false
    try{& $Body|Out-Null}catch{$caught=$_.Exception.Message -like "*$Expected*"}
    Assert-True $caught $Name
}
function Reset-Fixture([bool]$Legacy){
    $script:expectedLegacy=$Legacy
    $script:observedLegacy=@()
    $script:hashReads=0
    $script:serviceReads=0
    $script:badHash=$false
    $script:servicePath='"'+(Join-Path $info.Alias 'promote\UVP004PromoteService.exe')+'"'
}
function New-Record([string]$Shape,[bool]$Legacy){
    $record=[ordered]@{Status='Ready';TapGuid=$tapGuid}
    if(-not $Legacy){$record['VnicPort']=$info.VnicPort}
    switch($Shape){
        'ordered' {return $record}
        'hashtable' {return [hashtable]$record}
        'loaded' {return ($record|ConvertTo-Json|ConvertFrom-Json)}
        default {throw 'Unsupported synthetic record shape.'}
    }
}

# Shadow every external dependency used by the extracted production functions.
function Get-TapAdapters { [pscustomobject]@{InterfaceGuid=$tapGuid} }
function Get-Item {
    param([string]$LiteralPath,[switch]$Force)
    if($LiteralPath -ne $info.Alias){throw 'Unexpected fixture path.'}
    [pscustomobject]@{LinkType='Junction';Target=@($info.Directory)}
}
function Get-Images {
    param($Info,[string]$Guid,[switch]$LegacyVnic)
    if($Info.Number -ne 4 -or $Guid -ne $tapGuid){throw 'Unexpected fixture image request.'}
    $script:observedLegacy+=[bool]$LegacyVnic
    $mode=if($LegacyVnic){'legacy'}else{'modern'}
    foreach($target in $targets){[pscustomobject]@{Target=$target;Hash="$mode/$target"}}
}
function Get-FileHash {
    param([string]$LiteralPath)
    $relative=$LiteralPath.Substring($info.Directory.Length).TrimStart('\')
    if($relative -notin $targets){throw 'Unexpected fixture hash request.'}
    $script:hashReads++
    $mode=if($script:expectedLegacy){'legacy'}else{'modern'}
    [pscustomobject]@{Hash=if($script:badHash){'mismatched'}else{"$mode/$relative"}}
}
function Get-CimInstance {
    param([string]$ClassName,[string]$Filter)
    if($ClassName -ne 'Win32_Service' -or $Filter -ne "Name='UVP004Service'"){throw 'Unexpected fixture service request.'}
    $script:serviceReads++
    [pscustomobject]@{Name='UVP004Service';PathName=$script:servicePath;State='Stopped'}
}

foreach($shape in @('ordered','hashtable','loaded')){
    foreach($legacy in @($false,$true)){
        Reset-Fixture $legacy
        $record=New-Record $shape $legacy
        $service=Assert-ReadyInstance $info $record
        Assert-True ($script:observedLegacy.Count -eq 1 -and $script:observedLegacy[0] -eq $legacy) "$shape selects the expected legacy mode ($legacy)"
        Assert-True ($script:hashReads -eq 3 -and $script:serviceReads -eq 1 -and $service.Name -eq $info.Service) "$shape verifies all three images and service ownership ($legacy)"
    }
    foreach($invalidPort in @($null,0,49327,36015)){
        Reset-Fixture $false
        $record=New-Record $shape $false
        $record.VnicPort=$invalidPort
        Assert-Throws {Assert-ReadyInstance $info $record} 'VNIC port metadata does not match' "$shape rejects an invalid present VNIC port ($invalidPort)"
        Assert-True ($script:observedLegacy.Count -eq 0 -and $script:hashReads -eq 0 -and $script:serviceReads -eq 0) "$shape rejects invalid metadata before image or service checks"
    }
}
foreach($legacy in @($false,$true)){
    Reset-Fixture $legacy
    $script:badHash=$true
    $record=New-Record 'ordered' $legacy
    Assert-Throws {Assert-ReadyInstance $info $record} 'binary verification failed' "A binary hash mismatch is rejected ($legacy)"
    Assert-True ($script:serviceReads -eq 0) 'Binary mismatch prevents service access'
}
Reset-Fixture $false
$script:servicePath='"unrelated-fixture-service.exe"'
Assert-Throws {Assert-ReadyInstance $info (New-Record 'ordered' $false)} 'Service path does not match' 'Service ownership remains exact'
Write-Output "$script:passed assertions passed. Synthetic records only."
