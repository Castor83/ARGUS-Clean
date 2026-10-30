# Passive, bounded Windows memory observation for the approved ARGUS VM only.
# Does not start, stop, unload, or reconfigure any process, model, or VM.
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')]
    [string]$SessionId = ('{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), [Guid]::NewGuid().ToString('N').Substring(0, 8)),
    [ValidateRange(1, 60)]
    [int]$MaxMinutes = 60,
    [ValidateRange(1, 1800)]
    [int]$MaxSamples = 1800,
    [ValidateSet('pre_install', 'install_3g', 'post_install', 'first_boot_3g', 'boot_2g', 'after')]
    [string]$InitialPhase = 'pre_install'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath 'E:\ARGUS'
$argusLogDirectory = 'E:\ARGUS\runtime\logs'
if (-not [IO.Directory]::Exists($argusLogDirectory)) { throw 'ARGUS log directory does not exist.' }
$argusPrefix = Join-Path $argusLogDirectory ('package-b-memory-' + $SessionId)
$argusPaths = [ordered]@{
    Session = $argusPrefix + '-session.json'
    Samples = $argusPrefix + '.csv'
    Phases = $argusPrefix + '-phases.json'
    Summary = $argusPrefix + '-summary.json'
    PhaseInput = $argusPrefix + '.phase'
    StopInput = $argusPrefix + '.stop'
}
foreach ($argusPath in $argusPaths.Values) {
    if (Test-Path -LiteralPath $argusPath) { throw ('Existing session evidence/input must be preserved: ' + $argusPath) }
}
$argusEncoding = [Text.UTF8Encoding]::new($false)
$argusVmUuid = '5ace2701-f69f-43de-a36c-0d2b2d530a1e'
$argusUuidPattern = '(?i)(?<![0-9a-f-])' + [Regex]::Escape($argusVmUuid) + '(?![0-9a-f-])'
$argusWindowsSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
$argusPhaseNames = @('pre_install', 'install_3g', 'post_install', 'first_boot_3g', 'boot_2g', 'after')
$argusEvents = [Collections.Generic.List[object]]::new()
$argusOwnedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$argusClock = [Diagnostics.Stopwatch]::StartNew()
$argusSampleCount = 0
$argusActivePhase = $null
$argusMainIdentity = $null
$argusStopReason = 'not_started'
$argusFatalError = $null
$argusStarted = [DateTime]::UtcNow.ToString('o')

function New-ArgusMetrics {
    return [ordered]@{
        Observed = $false; Samples = 0; FirstSampleUtc = $null; LastSampleUtc = $null
        ValidRAMSamples = 0; ValidOwnVMSamples = 0; ErrorSamples = 0
        MinFreeRAMBytes = $null; PeakHostUsedRAMBytes = $null
        PeakOwnVMWorkingSetBytes = $null; PeakOwnVMPrivateBytes = $null
    }
}
$argusPhaseMetrics = [ordered]@{}
foreach ($argusPhaseName in $argusPhaseNames) { $argusPhaseMetrics[$argusPhaseName] = New-ArgusMetrics }
$argusMetrics = New-ArgusMetrics

function Get-ArgusErrorTag {
    param($Record)
    return ('{0}:0x{1:X8}' -f $Record.Exception.GetType().Name, $Record.Exception.HResult)
}
function Write-ArgusJson {
    param([string]$Path, $Value, [long]$ByteLimit)
    if (-not $argusOwnedPaths.Contains($Path)) { throw 'Refusing to overwrite a file not created by this monitor session.' }
    $argusJsonText = ConvertTo-Json -InputObject $Value -Depth 10
    if ($argusEncoding.GetByteCount($argusJsonText) -gt $ByteLimit) { throw 'Own JSON evidence size limit reached.' }
    [IO.File]::WriteAllText($Path, $argusJsonText, $argusEncoding)
}
function Add-ArgusPhaseEvent {
    param([string]$Kind, [AllowNull()][string]$Phase, [string]$Utc)
    if ($argusEvents.Count -ge 3602) { throw 'Phase marker count limit reached.' }
    $argusEvents.Add([ordered]@{Event=$Kind; Phase=$Phase; ObservedAtUtc=$Utc; AfterSample=$argusSampleCount})
    Write-ArgusJson -Path $argusPaths.Phases -Value @($argusEvents.ToArray()) -ByteLimit 1MB
}
function Update-ArgusMetrics {
    param($Metrics, $Sample)
    $Metrics.Observed = $true
    $Metrics.Samples++
    if ($null -eq $Metrics.FirstSampleUtc) { $Metrics.FirstSampleUtc = $Sample.Utc }
    $Metrics.LastSampleUtc = $Sample.Utc
    if ($null -ne $Sample.FreeRAMBytes) {
        $Metrics.ValidRAMSamples++
        if ($null -eq $Metrics.MinFreeRAMBytes -or $Sample.FreeRAMBytes -lt $Metrics.MinFreeRAMBytes) { $Metrics.MinFreeRAMBytes = $Sample.FreeRAMBytes }
        if ($null -eq $Metrics.PeakHostUsedRAMBytes -or $Sample.UsedRAMBytes -gt $Metrics.PeakHostUsedRAMBytes) { $Metrics.PeakHostUsedRAMBytes = $Sample.UsedRAMBytes }
    }
    if ($null -ne $Sample.OwnVMWorkingSetBytes) {
        $Metrics.ValidOwnVMSamples++
        if ($null -eq $Metrics.PeakOwnVMWorkingSetBytes -or $Sample.OwnVMWorkingSetBytes -gt $Metrics.PeakOwnVMWorkingSetBytes) { $Metrics.PeakOwnVMWorkingSetBytes = $Sample.OwnVMWorkingSetBytes }
        if ($null -eq $Metrics.PeakOwnVMPrivateBytes -or $Sample.OwnVMPrivateBytes -gt $Metrics.PeakOwnVMPrivateBytes) { $Metrics.PeakOwnVMPrivateBytes = $Sample.OwnVMPrivateBytes }
    }
    if ($Sample.HasErrors) { $Metrics.ErrorSamples++ }
}
function ConvertFrom-ArgusVmLogHeader {
    param([string]$Text)
    if ($Text.Length -gt 65536) { throw 'VM log header exceeds the bounded input size.' }
    $argusFields = @{}
    foreach ($argusField in @(
        @{Key='LogTime'; Pattern='(?m)^\S+\s+Log opened (\S+)\s*$'},
        @{Key='Executable'; Pattern='(?m)^\S+\s+Executable:\s*([^\r\n]+)\s*$'},
        @{Key='PID'; Pattern='(?m)^\S+\s+Process ID:\s*([0-9]+)\s*$'},
        @{Key='Name'; Pattern='(?m)^\S+\s+Name\s+<string>\s*=\s*"([^"]+)"[^\r\n]*$'},
        @{Key='UUID'; Pattern='(?m)^\S+\s+UUID\s+<bytes>\s*=\s*"([0-9a-fA-F ]+)"[^\r\n]*$'}
    )) {
        $argusMatches = [regex]::Matches($Text, $argusField.Pattern)
        if ($argusMatches.Count -ne 1) { throw ('Missing or duplicate VM log identity field: ' + $argusField.Key) }
        $argusFields[$argusField.Key] = $argusMatches[0].Groups[1].Value.Trim()
    }
    $argusExpectedUUIDBytes = (([Guid]$argusVmUuid).ToByteArray() | ForEach-Object { $_.ToString('x2') }) -join ' '
    if ($argusFields.Name -cne 'ARGUS-Offline' -or ($argusFields.UUID -replace '\s+', ' ').ToLowerInvariant() -cne $argusExpectedUUIDBytes) { throw 'Own VM name or UUID does not match the log header.' }
    if ($argusFields.Executable -cnotin @('C:\Program Files\Oracle\VirtualBox\VBoxHeadless.exe','C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe')) { throw 'Unexpected main VM executable in log header.' }
    $argusMainPid = 0
    if (-not [int]::TryParse($argusFields.PID, [ref]$argusMainPid) -or $argusMainPid -le 0) { throw 'Invalid main VM PID in log header.' }
    $argusLogTime = [DateTimeOffset]::Parse($argusFields.LogTime, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
    return [pscustomobject]@{
        PID=$argusMainPid; Name=[IO.Path]::GetFileName($argusFields.Executable); LogOpenedUtc=$argusLogTime
        VMUUID=$argusVmUuid; Source='fixed_own_VM_log_header'
    }
}
function Get-ArgusVmLogBinding {
    # Read at most 64 KiB / 96 lines from this VM's own current log; no private media is read.
    $argusLogStream = [IO.File]::Open('E:\ARGUS\runtime\vms\ARGUS-Offline\Logs\VBox.log', [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite,Delete')
    try {
        $argusHeaderBytes = [byte[]]::new(65536)
        $argusHeaderCount = $argusLogStream.Read($argusHeaderBytes, 0, $argusHeaderBytes.Length)
        $argusHeaderText = [Text.Encoding]::UTF8.GetString($argusHeaderBytes, 0, $argusHeaderCount)
        $argusHeaderText = (($argusHeaderText -split '\r?\n' | Select-Object -First 96) -join "`n")
        return ConvertFrom-ArgusVmLogHeader -Text $argusHeaderText
    } finally { $argusLogStream.Dispose() }
}
function Resolve-ArgusVmMainIdentity {
    param($LogBinding, [object[]]$Processes)
    $argusMainCandidates = @($Processes | Where-Object { $_.ProcessId -eq $LogBinding.PID })
    if ($argusMainCandidates.Count -ne 1) { throw 'Own log main PID is absent or ambiguous; do not assign another process.' }
    $argusMain = $argusMainCandidates[0]
    if ($argusMain.SessionId -ne $argusWindowsSession) { throw 'Main VM Windows session differs.' }
    if ($argusMain.Name -cne $LogBinding.Name) { throw 'Main VM executable differs.' }
    if ($null -eq $argusMain.CreationDate) { throw 'Main VM creation time is unavailable.' }
    $argusCreationUtc = $argusMain.CreationDate.ToUniversalTime()
    $argusStartupSeconds = ($LogBinding.LogOpenedUtc - $argusCreationUtc).TotalSeconds
    if ($argusStartupSeconds -lt 0 -or $argusStartupSeconds -gt 60) { throw 'VM log and process startup times do not match.' }
    if (-not [string]::IsNullOrWhiteSpace([string]$argusMain.CommandLine) -and [string]$argusMain.CommandLine -notmatch $argusUuidPattern) { throw 'Visible main VM command line conflicts with the UUID log.' }
    $argusLogIdentity = '{0}|{1}|{2}' -f $LogBinding.PID, $LogBinding.LogOpenedUtc.ToString('o'), $LogBinding.Name
    if ($null -ne $script:argusMainIdentity -and $script:argusMainIdentity.LogIdentity -ceq $argusLogIdentity -and $script:argusMainIdentity.CreationUtcTicks -ne $argusCreationUtc.Ticks) { throw 'Main VM PID was reused while the source log identity stayed unchanged.' }
    $script:argusMainIdentity = [pscustomobject]@{
        PID=[int]$argusMain.ProcessId; Name=[string]$argusMain.Name; SessionId=[int]$argusMain.SessionId
        CreationUtcTicks=$argusCreationUtc.Ticks; CreationUtc=$argusCreationUtc.ToString('o')
        LogIdentity=$argusLogIdentity; LogOpenedUtc=$LogBinding.LogOpenedUtc.ToString('o')
    }
    return $script:argusMainIdentity
}
function Read-ArgusSample {
    param([AllowNull()][string]$Phase, [AllowNull()][string]$PhaseError)
    $argusSampleUtc = [DateTime]::UtcNow.ToString('o')
    $argusTotal = $null; $argusFree = $null; $argusUsed = $null; $argusRamError = $null
    try {
        $argusOS = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory -OperationTimeoutSec 5 -ErrorAction Stop
        if ($null -eq $argusOS.TotalVisibleMemorySize -or $null -eq $argusOS.FreePhysicalMemory) { throw 'Missing RAM observation.' }
        $argusTotal = [long]$argusOS.TotalVisibleMemorySize * 1KB
        $argusFree = [long]$argusOS.FreePhysicalMemory * 1KB
        if ($argusTotal -le 0 -or $argusFree -lt 0 -or $argusFree -gt $argusTotal) { throw 'Invalid RAM observation.' }
        $argusUsed = $argusTotal - $argusFree
    } catch {
        $argusTotal = $null; $argusFree = $null; $argusUsed = $null
        $argusRamError = Get-ArgusErrorTag $_
    }
    $argusOwn = [Collections.Generic.List[object]]::new()
    $argusService = [Collections.Generic.List[object]]::new()
    $argusProcessError = $null
    $argusAttributionError = $null
    $argusUnattributed = $null
    $argusOwnComplete = $false
    $argusServiceComplete = $false
    try {
        # Never enumerate other executable names or another Windows session.
        $argusFilter = "SessionId=$argusWindowsSession AND (Name='VirtualBoxVM.exe' OR Name='VBoxHeadless.exe' OR Name='VBoxSVC.exe')"
        $argusProcesses = @(Get-CimInstance -ClassName Win32_Process -Filter $argusFilter -Property Name,ProcessId,SessionId,CommandLine,CreationDate -OperationTimeoutSec 5 -ErrorAction Stop)
        if ($argusProcesses.Count -gt 16) { throw 'Unexpected VirtualBox process count; observation is incomplete.' }
        $argusOwnComplete = $true; $argusServiceComplete = $true
        $argusVMs = @($argusProcesses | Where-Object { $_.Name -ine 'VBoxSVC.exe' })
        $argusUnattributed = $argusVMs.Count
        $argusVerifiedMain = $null
        if ($argusVMs.Count -gt 0) {
            try {
                $argusLogBinding = Get-ArgusVmLogBinding
                $argusVerifiedMain = Resolve-ArgusVmMainIdentity -LogBinding $argusLogBinding -Processes $argusVMs
                $argusUnattributed--
            } catch { $argusOwnComplete = $false; $argusAttributionError = Get-ArgusErrorTag $_ }
        }
        foreach ($argusProcess in $argusProcesses) {
            $argusIsService = $argusProcess.Name -ieq 'VBoxSVC.exe'
            if (-not $argusIsService -and ($null -eq $argusVerifiedMain -or $argusProcess.ProcessId -ne $argusVerifiedMain.PID)) { continue }
            $argusProcessMetric = [ordered]@{
                PID = [int]$argusProcess.ProcessId; Name = [string]$argusProcess.Name
                Attribution = $(if ($argusIsService) { 'current_session_host_service_not_VM_attributed' } else { 'UUID_log_verified_main_VM_process_only' })
                CreationUtc = $argusProcess.CreationDate.ToUniversalTime().ToString('o')
                Utc = [DateTime]::UtcNow.ToString('o'); WorkingSet64 = $null; PrivateBytes = $null; Error = $null
            }
            $argusManagedProcess = $null
            try {
                $argusManagedProcess = Get-Process -Id $argusProcess.ProcessId -ErrorAction Stop
                # CIM creation times have microsecond precision; Get-Process may retain sub-microsecond ticks.
                if ($null -eq $argusProcess.CreationDate -or [Math]::Abs(($argusManagedProcess.StartTime.ToUniversalTime() - $argusProcess.CreationDate.ToUniversalTime()).Ticks) -gt 10 -or
                    $argusManagedProcess.SessionId -ne $argusWindowsSession -or ($argusManagedProcess.ProcessName + '.exe') -ine $argusProcess.Name) { throw 'Process identity changed or could not be confirmed.' }
                $argusManagedProcess.Refresh()
                $argusProcessMetric.WorkingSet64 = [long]$argusManagedProcess.WorkingSet64
                $argusProcessMetric.PrivateBytes = [long]$argusManagedProcess.PrivateMemorySize64
                if ($argusManagedProcess.HasExited) { throw 'Process exited during memory observation.' }
            } catch {
                $argusProcessMetric.WorkingSet64 = $null; $argusProcessMetric.PrivateBytes = $null
                $argusProcessMetric.Error = Get-ArgusErrorTag $_
                if ($argusIsService) { $argusServiceComplete = $false } else { $argusOwnComplete = $false }
            } finally {
                if ($null -ne $argusManagedProcess) { $argusManagedProcess.Dispose() }
            }
            if ($argusIsService) { $argusService.Add($argusProcessMetric) } else { $argusOwn.Add($argusProcessMetric) }
        }
    } catch {
        $argusProcessError = Get-ArgusErrorTag $_
        $argusOwnComplete = $false; $argusServiceComplete = $false
    }
    $argusOwnWS = $null; $argusOwnPrivate = $null; $argusServiceWS = $null; $argusServicePrivate = $null
    if ($argusOwnComplete) {
        $argusOwnWS = [long]0; $argusOwnPrivate = [long]0
        foreach ($argusMetric in $argusOwn) { $argusOwnWS += $argusMetric.WorkingSet64; $argusOwnPrivate += $argusMetric.PrivateBytes }
    }
    if ($argusServiceComplete) {
        $argusServiceWS = [long]0; $argusServicePrivate = [long]0
        foreach ($argusMetric in $argusService) { $argusServiceWS += $argusMetric.WorkingSet64; $argusServicePrivate += $argusMetric.PrivateBytes }
    }
    return [pscustomobject][ordered]@{
        Sample = $argusSampleCount + 1; Utc = $argusSampleUtc; CompletedUtc = [DateTime]::UtcNow.ToString('o'); Phase = $Phase
        TotalRAMBytes = $argusTotal; FreeRAMBytes = $argusFree; UsedRAMBytes = $argusUsed; RAMError = $argusRamError
        OwnVMWorkingSetBytes = $argusOwnWS; OwnVMPrivateBytes = $argusOwnPrivate
        OwnVMMeasurementScope = 'verified_main_VM_process_only'
        OwnVMProcessCount = $(if ($argusOwnComplete) { $argusOwn.Count } else { $null })
        OwnVMProcessesJSON = ConvertTo-Json -InputObject @($argusOwn.ToArray()) -Depth 5 -Compress
        HostVBoxSVCWorkingSetBytes = $argusServiceWS; HostVBoxSVCPrivateBytes = $argusServicePrivate
        HostVBoxSVCProcessesJSON = ConvertTo-Json -InputObject @($argusService.ToArray()) -Depth 5 -Compress
        UnattributedVMProcessCount = $argusUnattributed; ProcessQueryError = $argusProcessError; VMAttributionError = $argusAttributionError; PhaseError = $PhaseError
        HasErrors = [bool]($argusRamError -or $argusProcessError -or $PhaseError -or -not $argusOwnComplete -or -not $argusServiceComplete)
    }
}

$argusSession = [ordered]@{
    SessionId=$SessionId; MonitorPID=$PID; StartedAtUtc=$argusStarted; VMUUID=$argusVmUuid
    WindowsSessionId=$argusWindowsSession; SampleIntervalSeconds=2; MaxMinutes=$MaxMinutes; MaxSamples=$MaxSamples; InitialPhase=$InitialPhase
    OwnVMMeasurementScope='verified_main_VM_process_only'; AttributionSource='fixed own UUID log + PID/creation/session/executable checks'
    OwnOutputByteLimit=5MB; CSVByteLimit=3MB; PhaseByteLimit=1MB; Paths=$argusPaths
    AllowedPhases=$argusPhaseNames; PhaseBoundaryPrecision='Observed by polling, not exact action timestamps'
}
# Atomic CreateNew makes duplicate starters with the same ID fail before overwriting evidence.
$argusGuard = [IO.File]::Open($argusPaths.Session, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try {
    $argusGuardBytes = $argusEncoding.GetBytes(($argusSession | ConvertTo-Json -Depth 5))
    if ($argusGuardBytes.Length -gt 16KB) { throw 'Session record size limit reached.' }
    $argusGuard.Write($argusGuardBytes, 0, $argusGuardBytes.Length)
} finally { $argusGuard.Dispose() }
$null = $argusOwnedPaths.Add($argusPaths.Session)
$argusCsvStream = $null
try {
    foreach ($argusOutput in @($argusPaths.Samples, $argusPaths.Phases, $argusPaths.Summary, $argusPaths.PhaseInput)) {
        $argusNewFile = [IO.File]::Open($argusOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $argusNewFile.Dispose()
        $null = $argusOwnedPaths.Add($argusOutput)
    }
    [IO.File]::WriteAllText($argusPaths.PhaseInput, $InitialPhase, $argusEncoding)
    Write-ArgusJson -Path $argusPaths.Phases -Value @() -ByteLimit 1MB
    Write-ArgusJson -Path $argusPaths.Summary -Value @{Status='running';SessionId=$SessionId;Phases=$argusPhaseMetrics} -ByteLimit 64KB
    $argusCsvStream = [IO.File]::Open($argusPaths.Samples, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $argusStopReason = 'running'
    while ($argusSampleCount -lt $MaxSamples -and $argusClock.Elapsed.TotalMinutes -lt $MaxMinutes) {
        $argusIterationStart = $argusClock.Elapsed.TotalSeconds
        $argusStopRequested = Test-Path -LiteralPath $argusPaths.StopInput
        $argusPhase = $null; $argusPhaseError = $null
        try {
            if ((Get-Item -LiteralPath $argusPaths.PhaseInput).Length -gt 128) { throw 'Phase input is too large.' }
            $argusPhase = [IO.File]::ReadAllText($argusPaths.PhaseInput, $argusEncoding).Trim()
            if ($argusPhase -cnotin $argusPhaseNames) { throw 'Unknown phase.' }
        } catch { $argusPhase = $null; $argusPhaseError = Get-ArgusErrorTag $_ }
        if ($argusPhase -cne $argusActivePhase) {
            $argusBoundaryUtc = [DateTime]::UtcNow.ToString('o')
            if ($null -ne $argusActivePhase) { Add-ArgusPhaseEvent -Kind 'phase_end_observed' -Phase $argusActivePhase -Utc $argusBoundaryUtc }
            $argusActivePhase = $argusPhase
            if ($null -ne $argusActivePhase) { Add-ArgusPhaseEvent -Kind 'phase_start_observed' -Phase $argusActivePhase -Utc $argusBoundaryUtc }
        }
        # A stop request still gets one final bounded sample, including a newly set 'after' phase.
        $argusSample = Read-ArgusSample -Phase $argusPhase -PhaseError $argusPhaseError
        $argusCsvLines = @($argusSample | ConvertTo-Csv -NoTypeInformation)
        if ($argusSampleCount -eq 0) { $argusCsvText = ($argusCsvLines -join "`r`n") + "`r`n" } else { $argusCsvText = $argusCsvLines[1] + "`r`n" }
        $argusCsvBytes = $argusEncoding.GetBytes($argusCsvText)
        if ($argusCsvStream.Length + $argusCsvBytes.Length -gt 3MB) { $argusStopReason = 'csv_size_limit'; break }
        $argusCsvStream.Write($argusCsvBytes, 0, $argusCsvBytes.Length)
        $argusCsvStream.Flush()
        $argusSampleCount++
        Update-ArgusMetrics -Metrics $argusMetrics -Sample $argusSample
        if ($null -ne $argusPhase) { Update-ArgusMetrics -Metrics $argusPhaseMetrics[$argusPhase] -Sample $argusSample }
        if ($argusStopRequested) { $argusStopReason = 'stop_file'; break }
        $argusSleepMs = [Math]::Min(2000, [Math]::Max(0, (2 - ($argusClock.Elapsed.TotalSeconds - $argusIterationStart)) * 1000))
        if ($argusSleepMs -gt 0) { Start-Sleep -Milliseconds ([int]$argusSleepMs) }
    }
    if ($argusStopReason -eq 'running') {
        $argusStopReason = if ($argusSampleCount -ge $MaxSamples) { 'sample_limit' } else { 'duration_limit' }
    }
} catch {
    $argusStopReason = 'observation_error'
    $argusFatalError = Get-ArgusErrorTag $_
} finally {
    if ($null -ne $argusCsvStream) { $argusCsvStream.Dispose() }
    $argusCompleted = [DateTime]::UtcNow.ToString('o')
    if ($null -ne $argusActivePhase -and $argusOwnedPaths.Contains($argusPaths.Phases)) { Add-ArgusPhaseEvent -Kind 'phase_end_monitor_stop' -Phase $argusActivePhase -Utc $argusCompleted }
    $argusSummary = [ordered]@{
        SessionId=$SessionId; Status=$argusStopReason; StartedAtUtc=$argusStarted; CompletedAtUtc=$argusCompleted
        ElapsedSeconds=$argusClock.Elapsed.TotalSeconds; Samples=$argusSampleCount; FatalError=$argusFatalError
        SampleIntervalSeconds=2; MaxMinutes=$MaxMinutes; MaxSamples=$MaxSamples; VMUUID=$argusVmUuid
        OwnVMMeasurementScope='verified_main_VM_process_only'; AttributionSource='fixed own UUID log + PID/creation/session/executable checks'
        AllSamples=$argusMetrics; Phases=$argusPhaseMetrics; Paths=$argusPaths
        Limits=@(
            'Sampled extrema only; absolute peaks between samples are unknown.',
            'Two-second target cadence; CIM/process query time may extend an interval. No new sample after the duration limit; an in-flight query/final evidence write may finish later.',
            'Each CIM request has a five-second operation timeout. Queries are sequential, not an atomic snapshot.',
            'Phase boundaries are first observed polling times. Unobserved phases remain explicitly marked Observed=false.',
            'Host RAM includes the whole system. OwnVM fields/peaks cover only the UUID-log-verified main VirtualBoxVM/VBoxHeadless process, not every VM-related process or model memory.',
            'Unverified hardened stub processes are excluded. This correction cannot recover missing VM-process samples from an earlier session; retain and report that gap.',
            'VBoxSVC is reported separately for this Windows session, may be shared, and is excluded from own VM peaks.',
            'Working sets may include shared pages; PrivateBytes is committed private memory, not private resident RAM.',
            'Query errors produce null values plus error tags. Confirmed absence of own VM processes is a valid zero.',
            'Owned CSV <=3 MiB, phase JSON <=1 MiB, summary <=64 KiB, session JSON <=16 KiB; combined owned outputs remain below 5 MiB.'
        )
    }
    if ($argusOwnedPaths.Contains($argusPaths.Summary)) { Write-ArgusJson -Path $argusPaths.Summary -Value $argusSummary -ByteLimit 64KB }
}
if ($argusFatalError) { exit 20 }
exit 0
