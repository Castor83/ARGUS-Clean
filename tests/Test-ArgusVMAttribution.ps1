# Synthetic regression only: extracts functions, never executes monitor startup.
# No CIM queries, process access, VM actions, or private-file reads are performed.
#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$argusMonitorPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Measure-ArgusVM.ps1'
$argusTokens = $null; $argusParseErrors = $null
$argusTree = [Management.Automation.Language.Parser]::ParseFile($argusMonitorPath, [ref]$argusTokens, [ref]$argusParseErrors)
if (@($argusParseErrors).Count) { throw 'Monitor syntax is invalid.' }
foreach ($argusFunction in $argusTree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]}, $true)) {
    . ([scriptblock]::Create($argusFunction.Extent.Text))
}
$argusPassed = 0
function Assert-ArgusTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('REGRESSION: ' + $Message) }
    $script:argusPassed++
}
function Assert-ArgusThrows {
    param([scriptblock]$Action, [string]$Message, [string]$ExpectedError = '')
    $argusDidThrow = $false
    try { & $Action | Out-Null } catch {
        if ($ExpectedError -and $_.Exception.Message -notlike ('*' + $ExpectedError + '*')) { throw ('Unexpected rejection reason: ' + $_.Exception.Message) }
        $argusDidThrow = $true
    }
    Assert-ArgusTest $argusDidThrow $Message
}
$argusVmUuid = '5ace2701-f69f-43de-a36c-0d2b2d530a1e'
$argusUuidPattern = '(?i)(?<![0-9a-f-])' + [regex]::Escape($argusVmUuid) + '(?![0-9a-f-])'
$argusWindowsSession = 7; $argusSampleCount = 0
$argusMainIdentity = $null
$argusFakeCreated = [DateTime]::Parse('2026-10-15T17:42:25.8806406Z').ToUniversalTime()
$argusFakeHeader = @'
00:00:00.339475 Log opened 2026-10-15T17:42:28.628762500Z
00:00:00.505106 Executable: C:\Program Files\Oracle\VirtualBox\VBoxHeadless.exe
00:00:00.505106 Process ID: 4242
00:00:00.666474   Name              <string>  = "ARGUS-Offline" (cb=14)
00:00:00.666477   UUID              <bytes>   = "01 27 ce 5a 9f f6 de 43 a3 6c 0d 2b 2d 53 0a 1e" (cb=16)
'@
$argusFakeProcesses = @(
    [pscustomobject]@{Name='VBoxHeadless.exe';ProcessId=4242;SessionId=7;CommandLine=$null;CreationDate=$argusFakeCreated},
    [pscustomobject]@{Name='VBoxHeadless.exe';ProcessId=4243;SessionId=7;CommandLine=$null;CreationDate=$argusFakeCreated},
    [pscustomobject]@{Name='VBoxHeadless.exe';ProcessId=4244;SessionId=7;CommandLine='--startvm 11111111-1111-1111-1111-111111111111';CreationDate=$argusFakeCreated}
)
$argusRequestedPids = [Collections.Generic.List[int]]::new()
function Get-CimInstance {
    param($ClassName, $Property, $Filter, $OperationTimeoutSec, $ErrorAction)
    if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{TotalVisibleMemorySize=1024000;FreePhysicalMemory=512000} }
    if ($ClassName -eq 'Win32_Process') { return $script:argusFakeProcesses }
    throw 'Unexpected synthetic CIM query.'
}
function Get-Process {
    param([int]$Id, $ErrorAction)
    $script:argusRequestedPids.Add($Id)
    if ($Id -ne 4242) { throw 'Attempt to inspect an unverified process.' }
    $argusFakeProcess = [pscustomobject]@{
        Id=4242; ProcessName='VBoxHeadless'; SessionId=7; StartTime=$script:argusFakeCreated
        WorkingSet64=[long]123166720; PrivateMemorySize64=[long]3332784128; HasExited=$false
    }
    $argusFakeProcess | Add-Member ScriptMethod Refresh {}
    $argusFakeProcess | Add-Member ScriptMethod Dispose {}
    return $argusFakeProcess
}
function Get-ArgusVmLogBinding { return ConvertFrom-ArgusVmLogHeader -Text $script:argusFakeHeader }

# The original monitor reports null here merely because the hardened process hides CommandLine.
$argusSample = Read-ArgusSample -Phase 'install_3g' -PhaseError $null
Assert-ArgusTest ($argusSample.OwnVMProcessCount -eq 1) 'Current own log must attribute only the main VM PID despite a hidden CommandLine.'
Assert-ArgusTest ($argusSample.OwnVMWorkingSetBytes -eq 123166720 -and $argusSample.OwnVMPrivateBytes -eq 3332784128) 'Main-process memory must be observed, not replaced by zero/null.'
Assert-ArgusTest ($argusSample.OwnVMMeasurementScope -eq 'verified_main_VM_process_only') 'The sample must not claim whole-VM process coverage.'
Assert-ArgusTest (($argusRequestedPids -join ',') -eq '4242') 'Unknown hardened stubs and another VM must not be inspected or assigned.'
Assert-ArgusTest (-not $argusSample.HasErrors) 'Unassigned stubs must not invalidate the verified main-process measurement.'
$argusBinding = ConvertFrom-ArgusVmLogHeader -Text $argusFakeHeader
Assert-ArgusThrows { ConvertFrom-ArgusVmLogHeader -Text ($argusFakeHeader.Replace('ARGUS-Offline','OTHER-VM')) } 'Wrong VM name must be rejected.'
Assert-ArgusThrows { ConvertFrom-ArgusVmLogHeader -Text ($argusFakeHeader.Replace('01 27 ce 5a','00 27 ce 5a')) } 'Wrong UUID bytes must be rejected.'
Assert-ArgusThrows { ConvertFrom-ArgusVmLogHeader -Text ($argusFakeHeader + "`n00:00:01 Process ID: 4242") } 'Duplicate PID fields must be rejected.'
Assert-ArgusThrows { Resolve-ArgusVmMainIdentity -LogBinding $argusBinding -Processes @([pscustomobject]@{ProcessId=4242;Name='VBoxHeadless.exe';SessionId=8;CommandLine=$null;CreationDate=$argusFakeCreated}) } 'Wrong Windows session must be rejected.' 'session differs'
Assert-ArgusThrows { Resolve-ArgusVmMainIdentity -LogBinding $argusBinding -Processes @([pscustomobject]@{ProcessId=4242;Name='other.exe';SessionId=7;CommandLine=$null;CreationDate=$argusFakeCreated}) } 'Wrong executable must be rejected.' 'executable differs'
Assert-ArgusThrows { Resolve-ArgusVmMainIdentity -LogBinding $argusBinding -Processes @([pscustomobject]@{ProcessId=4242;Name='VBoxHeadless.exe';SessionId=7;CommandLine=$null;CreationDate=$argusFakeCreated.AddMinutes(-2)}) } 'Stale log/process pairing must be rejected.' 'startup times do not match'
Assert-ArgusThrows { Resolve-ArgusVmMainIdentity -LogBinding $argusBinding -Processes @([pscustomobject]@{ProcessId=4242;Name='VBoxHeadless.exe';SessionId=7;CommandLine=$null;CreationDate=$argusFakeCreated.AddSeconds(1)}) } 'PID reuse with the same log must be rejected even inside the startup-time window.' 'PID was reused'
Assert-ArgusThrows { Resolve-ArgusVmMainIdentity -LogBinding $argusBinding -Processes @() } 'A missing main PID must not be attributed to an unknown stub.' 'PID is absent'
# No verified main PID means null/error, even if several unknown hardened stubs remain.
$argusFakeProcesses = @($argusFakeProcesses | Where-Object ProcessId -ne 4242)
$argusMissingSample = Read-ArgusSample -Phase 'post_install' -PhaseError $null
Assert-ArgusTest ($null -eq $argusMissingSample.OwnVMWorkingSetBytes -and $argusMissingSample.HasErrors) 'Missing main PID must remain unknown, not become a zero or another stub.'
Assert-ArgusTest (($argusRequestedPids -join ',') -eq '4242') 'Missing-main fallback must not inspect any unknown stub.'
# After all VM process candidates exit, a main-process zero is a valid observation.
$argusFakeProcesses = @()
$argusAbsentSample = Read-ArgusSample -Phase 'post_install' -PhaseError $null
Assert-ArgusTest ($argusAbsentSample.OwnVMProcessCount -eq 0 -and $argusAbsentSample.OwnVMWorkingSetBytes -eq 0 -and -not $argusAbsentSample.HasErrors) 'Confirmed absence must stay distinguishable from attribution failure.'
Write-Output ('PASS: {0} synthetic attribution assertions; no monitor or VM started.' -f $argusPassed)
