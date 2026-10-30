#requires -Version 5.1
<#
Narrow privileged native actions. Disconnect only stops the selected UI/CS.
EnsureService only creates/starts the selected verified LocalSystem service and
grants this user START|QUERY_STATUS; it never stops a service or a process.
CreateInstance invokes only the pinned bundled multi-instance script's CreateOnly
mode, while all clients/TAPs are idle, then authorizes its single new service.
No credentials or vendor configuration/AppData/logs are accepted or read.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Disconnect','EnsureService','CreateInstance','QuiesceOwned','Probe')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidateRange(1,999)][int]$Index,
    [Parameter(Mandatory=$true)][string]$SourceDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce,
    [ValidatePattern('^S-1-5-[0-9-]+$')][string]$CallerSid,
    [uint32]$ExpectedPid,
    [long]$ExpectedCreatedUs
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Mode = switch ($Mode.ToLowerInvariant()) {
    'disconnect' {'Disconnect'}
    'ensureservice' {'EnsureService'}
    'createinstance' {'CreateInstance'}
    'quiesceowned' {'QuiesceOwned'}
    'probe' {'Probe'}
    default { throw [ArgumentException]::new('Unsupported native action mode.') }
}

function Fail([string]$Message) { throw [InvalidOperationException]::new($Message) }
function Assert-NotReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail 'Reparse points are not allowed here.' }
}
function Assert-Protected([string]$Path) {
    Assert-NotReparse $Path
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $ownerSid) { Fail 'The native client location is not owned by a trusted system principal.' }
    $writeMask = [int][Security.AccessControl.FileSystemRights]::Write -bor
        [int][Security.AccessControl.FileSystemRights]::Delete -bor
        [int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [int][Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        0x10000000 -bor 0x40000000 # GENERIC_ALL and GENERIC_WRITE are write grants too.
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if (([int]$rule.FileSystemRights -band $writeMask) -ne 0 -and $trusted -notcontains $rule.IdentityReference.Value) {
            Fail 'The native client location permits writes by an untrusted principal.'
        }
    }
}
function Assert-OfficialSource([string]$Path) {
    $canonical = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $roots = @([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86),
               [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) |
        Where-Object { $_ } | Select-Object -Unique
    $matched = $null
    foreach ($root in $roots) {
        if ($canonical -ieq (Join-Path $root 'UniVPN')) { $matched = $root; break }
    }
    if (-not $matched) { Fail 'SourceDirectory must be the direct UniVPN directory in a protected Program Files folder.' }
    Assert-Protected $matched
    Assert-Protected $canonical
    $expected = [ordered]@{
        'UniVPN.exe'='24f90f30309ad4bcd6c2e81adf39e44a690c648d13455194971c01a08ad0d0b1'
        'promote\UniVPNPromoteService.exe'='e038021b055e659430876a7e270c6ef8e8f32346155c3197cc6e539477141b10'
        'serviceclient\UniVPNCS.exe'='cf07de7e0ffeb470859a5df8cbc33915ef642b407c7b42627ced94f5e166ec39'
    }
    foreach ($name in $expected.Keys) {
        $file = Join-Path $canonical $name
        Assert-Protected ([IO.Path]::GetDirectoryName($file))
        Assert-Protected $file
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected[$name]) {
            Fail 'Unsupported official UniVPN build. Existing client was retained.'
        }
    }
    return $canonical
}
function Ensure-ResultDirectory([string]$Source) {
    $state = Join-Path $Source '.univpn-multi'
    if (-not (Test-Path -LiteralPath $state)) { $null = New-Item -ItemType Directory -Path $state }
    Assert-Protected $state
    $results = Join-Path $state 'manager-results'
    if (-not (Test-Path -LiteralPath $results)) { $null = New-Item -ItemType Directory -Path $results }
    Assert-Protected $results
    return $results
}
function Save-Result([string]$Directory,$Value) {
    Assert-Protected $Directory
    $target = Join-Path $Directory ($Nonce + '.json')
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 5 -Compress))
    # CreateNew refuses pre-existing files/symlinks; no arbitrary output path is accepted.
    $stream = [IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
function Assert-CreationIdle {
    $clients = @(Get-Process | Where-Object { $_.ProcessName -match '^(UniVPN|UniVP2|UVP\d{3})(CS)?$' })
    $activeTaps = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like 'TAP-Windows Adapter V9*' -and $_.Status -eq 'Up' })
    if ($clients.Count -or $activeTaps.Count) { Fail 'Creation requires every VPN client/backend exited and every TAP offline. Existing connections were not stopped.' }
}
function Assert-QuiesceIdle {
    if ($ExpectedPid -lt 1 -or $ExpectedCreatedUs -lt 1) { Fail 'An owned process identity is required.' }
    $clients = @(Get-Process | Where-Object { $_.ProcessName -match '^(UniVPN|UniVP2|UVP\d{3})$' })
    $activeTaps = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like 'TAP-Windows Adapter V9*' -and $_.Status -eq 'Up' })
    if ($clients.Count -or $activeTaps.Count) { Fail 'The owned backend is retained until all clients and tunnels are offline.' }
    foreach ($line in @(& (Join-Path ([Environment]::SystemDirectory) 'netstat.exe') -ano)) {
        if ($line -match '^\s*TCP\s+\S+\s+(\S+):([0-9]+)\s+ESTABLISHED\s+([0-9]+)\s*$' -and [uint32]$Matches[3] -eq $ExpectedPid) {
            $remote = $null
            if (-not [Net.IPAddress]::TryParse($Matches[1].Trim('[',']'),[ref]$remote) -or -not [Net.IPAddress]::IsLoopback($remote)) {
                Fail 'The owned backend still has a remote connection.'
            }
        }
    }
}
function Get-PinnedVendorBytes {
    # No parameter can choose executable code. Hash the same bytes later written
    # into the protected installation, avoiding a bundle-path read/copy race.
    $expected = 'e89190659105f451829bf67f5a0a8d609be120e01a484176a17f88ae64577230'
    $vendor = Join-Path (Split-Path $PSScriptRoot -Parent) 'vendor\UniVPN-Multi.ps1'
    Assert-NotReparse ([IO.Path]::GetDirectoryName($vendor))
    Assert-NotReparse $vendor
    if ((Get-Item -LiteralPath $vendor).Length -gt 1048576) { Fail 'Invalid bundled creation script.' }
    $bytes = [IO.File]::ReadAllBytes($vendor)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($actual -cne $expected) { Fail 'The bundled creation script does not match its reviewed SHA256.' }
    return [pscustomobject]@{Bytes=$bytes;Hash=$expected}
}
function Get-ProtectedCreationScript([string]$Source) {
    $pinned = Get-PinnedVendorBytes
    $directory = Join-Path (Join-Path $Source '.univpn-multi') 'manager-runtime'
    if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory }
    Assert-Protected $directory
    $target = Join-Path $directory ('UniVPN-Multi-'+$pinned.Hash+'.ps1')
    if (-not (Test-Path -LiteralPath $target)) {
        $stream = [IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($pinned.Bytes,0,$pinned.Bytes.Length) } finally { $stream.Dispose() }
    }
    Assert-Protected $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $pinned.Hash) { Fail 'The protected creation script was not overwritten because its hash differs.' }
    return $target
}
function Get-InstanceRecordNames([string]$Source) {
    $state = Join-Path $Source '.univpn-multi'
    Assert-Protected $state
    $names = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $state -Filter 'instance-*.json' -File)) {
        Assert-Protected $file.FullName
        $names[$file.Name] = $file.FullName
    }
    return $names
}

$resultDirectory = $null
$creationMutex = $null
$creationHeld = $false
$actionPhase = 'platform'
$actionExitCode = 1
$languageMode = [string]$ExecutionContext.SessionState.LanguageMode
if ($languageMode -notin @('FullLanguage','ConstrainedLanguage','RestrictedLanguage','NoLanguage')) { $languageMode='NoLanguage' }
try {
    $actionPhase = 'platform'
    if ([IntPtr]::Size -ne 8 -or -not [Environment]::Is64BitOperatingSystem) { Fail 'Windows x64 is required.' }
    $actionPhase = 'identity'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $actualSid = $identity.User.Value
    $callerSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($CallerSid -and $CallerSid -cne $actualSid) { Fail 'Elevation must keep the same Windows user.' }
    $CallerSid = $actualSid
    $administrator = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $actionPhase = 'source_preflight'
    # Some captured/hidden Windows PowerShell subprocesses do not load these
    # commands by default. Load only the current engine's trusted manifests,
    # never a similarly named module from a user-controlled PSModulePath.
    # This runs again in an elevated child without changing execution policy.
    Import-Module -Name ($PSHOME+'\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Scope Local -ErrorAction Stop
    Import-Module -Name ($PSHOME+'\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Scope Local -ErrorAction Stop
    $source = Assert-OfficialSource $SourceDirectory
    if ($Mode -ceq 'Probe') {
        [ordered]@{ok=$true;phase='complete';isAdministrator=[bool]$administrator;bitness=([IntPtr]::Size*8);languageMode=$languageMode} | ConvertTo-Json -Compress | Write-Output
        exit 0
    }
    if ($Mode -ceq 'CreateInstance') { Assert-CreationIdle; $null=Get-PinnedVendorBytes }
    if ($Mode -ceq 'QuiesceOwned') { Assert-QuiesceIdle }
    if (-not $administrator) {
        $actionPhase = 'elevation'
        $shell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        if ($PSCommandPath.Contains('"')) { Fail 'Invalid helper path.' }
        $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),
                       '-Mode',$Mode,'-Index',[string]$Index,'-SourceDirectory',('"'+$source+'"'),
                       '-Nonce',$Nonce,'-CallerSid',$CallerSid)
        if ($Mode -ceq 'QuiesceOwned') { $arguments += @('-ExpectedPid',[string]$ExpectedPid,'-ExpectedCreatedUs',[string]$ExpectedCreatedUs) }
        $child = Start-Process -FilePath $shell -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        $actionExitCode = $child.ExitCode
        if ($child.ExitCode -ne 0) { Fail 'The elevated native action did not complete.' }
        exit $child.ExitCode
    }
    # All validation is repeated after UAC in the elevated process.
    $source = Assert-OfficialSource $source
    $actionPhase = 'results'
    $resultDirectory = Ensure-ResultDirectory $source
    if (Test-Path -LiteralPath (Join-Path $resultDirectory ($Nonce+'.json'))) { Fail 'This action nonce has already been used.' }
    if ($Mode -ceq 'CreateInstance') {
        $actionPhase = 'creation'
        Assert-CreationIdle
        # The upstream script recursively acquires this same thread-owned mutex.
        # Holding it across the before/after snapshot prevents claiming another
        # concurrent upstream invocation's Ready record.
        $creationMutex = [Threading.Mutex]::new($false,'Global\UniVPNMultiInstaller10781')
        try { $creationHeld=$creationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $creationHeld=$true }
        if (-not $creationHeld) { Fail 'Another native instance creation is already in progress.' }
        $creationScript = Get-ProtectedCreationScript $source
        $beforeRecords = Get-InstanceRecordNames $source
        Assert-CreationIdle
        $null = & $creationScript -SourceDirectory $source -CreateOnly
        Assert-CreationIdle
        $afterRecords = Get-InstanceRecordNames $source
        $addedRecords = @($afterRecords.Keys | Where-Object { -not $beforeRecords.ContainsKey($_) })
        if ($addedRecords.Count -ne 1) { Fail 'Creation did not produce exactly one new owned instance record; no retry or cleanup was attempted.' }
        $createdPath = [string]$afterRecords[$addedRecords[0]]
        if ((Get-Item -LiteralPath $createdPath).Length -gt 65536) { Fail 'Invalid new instance record.' }
        $createdRecord = Get-Content -LiteralPath $createdPath -Raw | ConvertFrom-Json
        $Index = [int]$createdRecord.Number
        if ($Index -lt 2 -or $Index -gt 999 -or [string]$createdRecord.Status -cne 'Ready' -or
            [IO.Path]::GetFileName($createdPath) -cne ('instance-{0:D3}.json' -f $Index)) { Fail 'The new instance record is not uniquely Ready.' }
    }
    $actionPhase = 'instance_preflight'
    $product = if ($Index -eq 1) { 'UniVPN' } else { 'UVP{0:D3}' -f $Index }
    $real = $source
    $alias = $source
    if ($Index -ne 1) {
        $recordPath = Join-Path (Join-Path $source '.univpn-multi') ('instance-{0:D3}.json' -f $Index)
        Assert-Protected $recordPath
        if ((Get-Item -LiteralPath $recordPath).Length -gt 65536) { Fail 'Invalid instance metadata.' }
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        if ([int]$record.Number -ne $Index -or [string]$record.Status -cne 'Ready') { Fail 'Instance metadata does not match the requested ready index.' }
        $real = Join-Path ([IO.Path]::GetDirectoryName($source)) ('UniVPN'+$Index)
        Assert-Protected $real
        $alias = Join-Path (Join-Path $source '.univpn-multi') $product
        $link = Get-Item -LiteralPath $alias -Force
        if ($link.LinkType -ne 'Junction' -or @($link.Target).Count -ne 1 -or
            [IO.Path]::GetFullPath([string]$link.Target).TrimEnd('\') -ine $real) { Fail 'Instance junction does not match its protected installation.' }
        $expectedTargets = @(($product+'.exe'), ('promote\'+$product+'PromoteService.exe'), ('serviceclient\'+$product+'CS.exe'))
        if (@($record.Files).Count -ne 3) { Fail 'Instance file ownership metadata must contain exactly three executable hashes.' }
        foreach ($relative in $expectedTargets) {
            $entries = @($record.Files | Where-Object { [string]$_.Target -ceq $relative })
            if ($entries.Count -ne 1 -or [string]$entries[0].Hash -cnotmatch '^[a-fA-F0-9]{64}$') { Fail 'Instance executable hash metadata is incomplete or ambiguous.' }
            $file = Join-Path $real $relative
            Assert-Protected ([IO.Path]::GetDirectoryName($file))
            Assert-Protected $file
            if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine [string]$entries[0].Hash) {
                Fail 'A generated executable does not match its protected instance record.'
            }
        }
    }
    Assert-Protected (Join-Path $real 'serviceclient')
    foreach ($relative in @(($product+'.exe'), ('serviceclient\'+$product+'CS.exe'))) {
        Assert-Protected (Join-Path $real $relative)
    }
    if (-not ('UniVpnManager.RestrictedDisconnect' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
namespace UniVpnManager {
 public static class RestrictedDisconnect {
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
  [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref uint size);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int informationClass,out uint information,uint length,out uint returnLength);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint exitCode);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  public sealed class ValidatedProcess : IDisposable {
   internal IntPtr Handle;
   internal ValidatedProcess(IntPtr handle) { Handle=handle; }
   public void Dispose() { if(Handle!=IntPtr.Zero) { CloseHandle(Handle); Handle=IntPtr.Zero; } }
  }
  public static ValidatedProcess Validate(uint pid,string pathA,string pathB,string sid,int callerSession,bool allowSystem) {
   // Pin each process before any termination: PID reuse cannot broaden the target.
   IntPtr handle=OpenProcess(0x00101001,false,pid),token=IntPtr.Zero;
   if(handle==IntPtr.Zero) { if(Marshal.GetLastWin32Error()==87) return null; throw new Win32Exception(); }
   try {
    var path=new StringBuilder(32768); uint size=(uint)path.Capacity;
    if(!QueryFullProcessImageName(handle,0,path,ref size)) throw new Win32Exception();
    if(!String.Equals(path.ToString(),pathA,StringComparison.OrdinalIgnoreCase) &&
       !String.Equals(path.ToString(),pathB,StringComparison.OrdinalIgnoreCase))
       throw new InvalidOperationException("A target process path does not match the protected instance.");
    if(!OpenProcessToken(handle,0x0008,out token)) throw new Win32Exception();
    using(var owner=new WindowsIdentity(token)) {
     if(owner.User==null || (owner.User.Value!=sid && !(allowSystem && owner.User.Value=="S-1-5-18")))
      throw new InvalidOperationException("A target process belongs to another Windows user.");
    }
    uint sessionId,returned;
    if(!GetTokenInformation(token,12,out sessionId,4,out returned)) throw new Win32Exception();
    if(sessionId!=(uint)callerSession) throw new InvalidOperationException("A target process belongs to another Windows session.");
    var target=new ValidatedProcess(handle); handle=IntPtr.Zero; return target;
   } finally { if(token!=IntPtr.Zero) CloseHandle(token); if(handle!=IntPtr.Zero) CloseHandle(handle); }
  }
  public static bool Stop(ValidatedProcess target) {
   if(target==null || target.Handle==IntPtr.Zero) throw new InvalidOperationException("A validated target handle is required.");
   if(WaitForSingleObject(target.Handle,0)==0) return false;
   if(!TerminateProcess(target.Handle,0)) {
    if(WaitForSingleObject(target.Handle,0)==0) return false;
    throw new Win32Exception();
   }
   if(WaitForSingleObject(target.Handle,5000)!=0) throw new InvalidOperationException("The target process has not exited.");
   return true;
  }
  public static ValidatedProcess ValidateOwned(uint pid,string pathA,string pathB,string sid,int callerSession,long expectedCreatedUs) {
   var target=Validate(pid,pathA,pathB,sid,callerSession,true);
   if(target==null) return null;
   try {
    long creation,exit,kernel,user;
    if(!GetProcessTimes(target.Handle,out creation,out exit,out kernel,out user)) throw new Win32Exception();
    if(creation/10!=expectedCreatedUs) throw new InvalidOperationException("The backend process identity changed.");
    var result=target; target=null; return result;
   } finally { if(target!=null) target.Dispose(); }
  }
 }
 public static class RestrictedService {
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr OpenSCManagerW(string machine,string database,uint access);
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr OpenServiceW(IntPtr manager,string name,uint access);
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateServiceW(IntPtr manager,string name,string displayName,uint access,uint type,uint start,uint error,string binary,string group,IntPtr tag,string dependencies,string account,string password);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceConfigW(IntPtr service,IntPtr config,uint length,out uint needed);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceObjectSecurity(IntPtr service,uint information,byte[] descriptor,uint length,out uint needed);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetServiceObjectSecurity(IntPtr service,uint information,byte[] descriptor);
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool StartServiceW(IntPtr service,uint argumentCount,IntPtr arguments);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceStatusEx(IntPtr service,int level,out ServiceStatus status,uint length,out uint needed);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
  [StructLayout(LayoutKind.Sequential)] struct ServiceConfig {
   public uint Type,Start,Error; public IntPtr Binary,Group; public uint Tag; public IntPtr Dependencies,Account,DisplayName;
  }
  [StructLayout(LayoutKind.Sequential)] struct ServiceStatus {
   public uint Type,State,Controls,ExitCode,SpecificExitCode,Checkpoint,WaitHint,ProcessId,Flags;
  }
  public sealed class EnsureResult { public bool Created,GrantAdded; public string ServiceName; }

  // Pure binary-SDDL transformation, separately tested without opening any service.
  // Existing ACEs, owner/group and control flags are retained byte-for-byte.
  public static byte[] AddStartQuery(byte[] original,string currentUserSid) {
   var sid=new SecurityIdentifier(currentUserSid);
   if(sid.IsWellKnown(WellKnownSidType.WorldSid) || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid) ||
      sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
      throw new InvalidOperationException("A specific current-user SID is required.");
   var descriptor=new RawSecurityDescriptor(original,0);
   if(descriptor.DiscretionaryAcl==null) throw new InvalidOperationException("A non-null service DACL is required.");
   int allowed=0,insert=descriptor.DiscretionaryAcl.Count;
   for(int i=0;i<descriptor.DiscretionaryAcl.Count;i++) {
    var ace=descriptor.DiscretionaryAcl[i];
    if((ace.AceFlags&AceFlags.Inherited)!=0 && insert==descriptor.DiscretionaryAcl.Count) insert=i;
    var qualified=ace as QualifiedAce; var known=ace as KnownAce;
    if(qualified==null || known==null || !known.SecurityIdentifier.Equals(sid)) continue;
    if(qualified.AceQualifier==AceQualifier.AccessDenied && (known.AccessMask&0x14)!=0)
     throw new InvalidOperationException("An existing user denial is retained; authorization refused.");
    if(qualified.AceQualifier==AceQualifier.AccessAllowed) allowed|=known.AccessMask;
   }
   if((allowed&0x14)==0x14) return (byte[])original.Clone();
   descriptor.DiscretionaryAcl.InsertAce(insert,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,0x14,sid,false,null));
   byte[] result=new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(result,0); return result;
  }
  static void VerifyConfig(IntPtr service,string expectedBinary,bool requireManual) {
   uint needed;
   QueryServiceConfigW(service,IntPtr.Zero,0,out needed);
   if(needed==0 || needed>65536) throw new InvalidOperationException("Service configuration could not be safely queried.");
   IntPtr buffer=Marshal.AllocHGlobal((int)needed);
   try {
    if(!QueryServiceConfigW(service,buffer,needed,out needed)) throw new Win32Exception();
    var config=(ServiceConfig)Marshal.PtrToStructure(buffer,typeof(ServiceConfig));
    if(!String.Equals(Marshal.PtrToStringUni(config.Binary),expectedBinary,StringComparison.OrdinalIgnoreCase) ||
       !String.Equals(Marshal.PtrToStringUni(config.Account),"LocalSystem",StringComparison.OrdinalIgnoreCase) ||
       (config.Type&0x30)!=0x10 || (config.Type&~0x110U)!=0)
      throw new InvalidOperationException("Service ownership does not match the protected instance; it was not overwritten.");
    if(requireManual && config.Start!=3) throw new InvalidOperationException("A newly created instance service must be Manual; it was not reconfigured.");
    // Existing start type is deliberately retained, including the original Auto service.
   } finally { Marshal.FreeHGlobal(buffer); }
  }
  static bool GrantStartQuery(IntPtr service,string sid) {
   uint needed;
   QueryServiceObjectSecurity(service,4,null,0,out needed);
   if(needed==0 || needed>8192) throw new InvalidOperationException("Service DACL could not be safely queried.");
   byte[] original=new byte[needed];
   if(!QueryServiceObjectSecurity(service,4,original,needed,out needed)) throw new Win32Exception();
   byte[] updated=AddStartQuery(original,sid);
   bool same=original.Length==updated.Length;
   if(same) for(int i=0;i<original.Length;i++) if(original[i]!=updated[i]) { same=false; break; }
   if(same) return false;
   // DACL only: no owner/group, config, stop, delete, or SCM ACL is changed.
   if(!SetServiceObjectSecurity(service,4,updated)) throw new Win32Exception();
   return true;
  }
  public static EnsureResult Ensure(string name,string expectedBinary,string currentUserSid,bool requireManual) {
   if(!System.Text.RegularExpressions.Regex.IsMatch(name,"^(UniVPNService|UVP[0-9]{3}Service)$"))
    throw new InvalidOperationException("Service name is outside the dedicated instance namespace.");
   // Service handle requests no CHANGE_CONFIG, STOP, DELETE or generic access.
   const uint access=0x00060015; // READ_CONTROL|WRITE_DAC|QUERY_CONFIG|QUERY_STATUS|START.
   IntPtr manager=OpenSCManagerW(null,null,3),service=IntPtr.Zero;
   if(manager==IntPtr.Zero) throw new Win32Exception();
   bool created=false;
   try {
    service=OpenServiceW(manager,name,access);
    if(service==IntPtr.Zero) {
     int error=Marshal.GetLastWin32Error();
     if(error!=1060) throw new Win32Exception(error);
     // Create only this missing service, own-process, Manual, normal error, LocalSystem.
     service=CreateServiceW(manager,name,name,access,0x10,3,1,expectedBinary,null,IntPtr.Zero,null,null,null);
     if(service==IntPtr.Zero) {
      error=Marshal.GetLastWin32Error();
      if(error!=1073) throw new Win32Exception(error);
      service=OpenServiceW(manager,name,access); // A racing creator is still verified below.
      if(service==IntPtr.Zero) throw new Win32Exception();
     } else created=true;
    }
    VerifyConfig(service,expectedBinary,requireManual); // Same pinned service object for check/grant/start.
    bool granted=GrantStartQuery(service,currentUserSid);
    if(!StartServiceW(service,0,IntPtr.Zero) && Marshal.GetLastWin32Error()!=1056) throw new Win32Exception();
    DateTime deadline=DateTime.UtcNow.AddSeconds(15);
    while(true) {
     ServiceStatus status; uint needed;
     if(!QueryServiceStatusEx(service,0,out status,(uint)Marshal.SizeOf(typeof(ServiceStatus)),out needed)) throw new Win32Exception();
     if(status.State==4) break;
     if(status.State==1 || DateTime.UtcNow>=deadline) throw new InvalidOperationException("The requested service did not reach Running; no restart was attempted.");
     System.Threading.Thread.Sleep(200);
    }
    return new EnsureResult {Created=created,GrantAdded=granted,ServiceName=name};
   } finally { if(service!=IntPtr.Zero) CloseServiceHandle(service); CloseServiceHandle(manager); }
  }
 }
}
'@
    }
    if ($Mode -in @('EnsureService','CreateInstance')) {
        $actionPhase = 'service'
        $serviceName = $product+'Service'
        $binary = '"'+(Join-Path $alias ('promote\'+$product+'PromoteService.exe'))+'"'
        if ($Mode -ceq 'CreateInstance') { Assert-CreationIdle }
        $ensured = [UniVpnManager.RestrictedService]::Ensure($serviceName,$binary,$CallerSid,($Mode -ceq 'CreateInstance'))
        if ($Mode -ceq 'CreateInstance') {
            Assert-CreationIdle
            Save-Result $resultDirectory ([ordered]@{ok=$true;index=$Index})
        } else {
            Save-Result $resultDirectory ([ordered]@{ok=$true;mode='EnsureService';index=$Index;service=$serviceName;created=$ensured.Created;startQueryGranted=$ensured.GrantAdded})
        }
        exit 0
    }
    if ($Mode -ceq 'QuiesceOwned') {
        $actionPhase = 'quiesce_owned'
        Assert-QuiesceIdle
        $relative = 'serviceclient\'+$product+'CS.exe'
        $target = [UniVpnManager.RestrictedDisconnect]::ValidateOwned($ExpectedPid,(Join-Path $real $relative),(Join-Path $alias $relative),$CallerSid,$callerSession,$ExpectedCreatedUs)
        try {
            # Stop only this pinned, already logged-out CS handle. Never enumerate
            # new candidates, stop a service, remove an adapter, or touch a UI.
            Assert-QuiesceIdle
            if ($target) { $null=[UniVpnManager.RestrictedDisconnect]::Stop($target) }
        } finally { if ($target) { $target.Dispose() } }
        Save-Result $resultDirectory ([ordered]@{ok=$true;mode='QuiesceOwned';index=$Index})
        exit 0
    }
    $stopped = @()
    $validated = @()
    $actionPhase = 'disconnect'
    try {
        # Validate ALL candidates before terminating ANY candidate.
        foreach ($name in @(($product+'.exe'), ($product+'CS.exe'))) {
            $relative = if ($name -ceq ($product+'.exe')) { $name } else { Join-Path 'serviceclient' $name }
            $pathA = Join-Path $real $relative
            $pathB = Join-Path $alias $relative
            foreach ($process in @(Get-CimInstance Win32_Process -Filter ("Name='"+$name+"'"))) {
                $allowSystem = $name -ceq ($product+'CS.exe')
                $target = [UniVpnManager.RestrictedDisconnect]::Validate([uint32]$process.ProcessId,$pathA,$pathB,$CallerSid,$callerSession,$allowSystem)
                if ($target) { $validated += [pscustomobject]@{target=$target;pid=[uint32]$process.ProcessId;name=$name} }
            }
        }
        # UI precedes its CS backend. No service, TAP or foreign index is included.
        foreach ($candidate in $validated) {
            if ([UniVpnManager.RestrictedDisconnect]::Stop($candidate.target)) {
                $stopped += [ordered]@{pid=$candidate.pid;name=$candidate.name}
            }
        }
    } finally {
        foreach ($candidate in $validated) { $candidate.target.Dispose() }
    }
    Save-Result $resultDirectory ([ordered]@{ok=$true;mode='Disconnect';index=$Index;stopped=$stopped})
    exit 0
} catch {
    if ($Mode -ceq 'Probe') {
        # Probe has no file output and never reaches UAC, result-directory
        # creation, driver/service/process actions, or a caller-supplied log.
        [ordered]@{ok=$false;phase=$actionPhase;errorCode=[int]$_.Exception.HResult;languageMode=$languageMode} | ConvertTo-Json -Compress | Write-Output
        exit 1
    }
    $safeFailure = [ordered]@{ok=$false;mode=$Mode;index=$Index;phase=$actionPhase;
                              errorCode=[int]$_.Exception.HResult;exitCode=[int]$actionExitCode;languageMode=$languageMode}
    # No configuration, credentials, raw native exception or vendor log is written.
    if ($resultDirectory) {
        try { Save-Result $resultDirectory $safeFailure } catch {}
    }
    $safeFailure | ConvertTo-Json -Compress | Write-Output
    exit 1
} finally {
    if ($creationHeld -and $creationMutex) { $creationMutex.ReleaseMutex() }
    if ($creationMutex) { $creationMutex.Dispose() }
}
