#requires -Version 7.2
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-ArgusCapturedProcess {
    param([string]$FilePath, [string[]]$Arguments, [string]$InputText = '', [int]$TimeoutSeconds = 120)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = 'E:\ARGUS'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['VBOX_USER_HOME'] = 'E:\ARGUS\runtime\virtualbox-user'
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        if (-not $child.Start()) { throw 'Child process did not start.' }
        $outTask = $child.StandardOutput.ReadToEndAsync()
        $errTask = $child.StandardError.ReadToEndAsync()
        if ($InputText.Length) { $child.StandardInput.WriteLine($InputText) }
        $child.StandardInput.Close()
        if (-not $child.WaitForExit($TimeoutSeconds * 1000)) {
            $child.Kill($true)
            $child.WaitForExit()
            throw 'Owned preparation subprocess exceeded its time limit.'
        }
        return [pscustomobject]@{
            ExitCode = $child.ExitCode
            StandardOutput = $outTask.GetAwaiter().GetResult()
            StandardError = $errTask.GetAwaiter().GetResult()
        }
    } finally { $child.Dispose() }
}

function Assert-ArgusMachineInfo {
    param([string]$MachineReadable)
    $values = @{}
    foreach ($line in ($MachineReadable -split '\r?\n')) {
        if ($line -match '^([A-Za-z0-9_-]+)=(?:"(.*)"|([^"\r\n]*))$') {
            if ($values.ContainsKey($Matches[1])) { throw 'Duplicate VM metadata key.' }
            $values[$Matches[1]] = if ($line.Contains('="')) { $Matches[2] } else { $Matches[3] }
        }
    }
    $required = @{
        name = 'ARGUS-Offline'; UUID = '5ace2701-f69f-43de-a36c-0d2b2d530a1e'
        VMState = 'poweroff'; cpus = '2'; memory = '3072'
        clipboard = 'disabled'; clipboard_file_transfers = 'off'; draganddrop = 'disabled'
        usb = 'off'; ehci = 'off'; xhci = 'off'; accelerate3d = 'off'; vrde = 'off'
        'nested-hw-virt' = 'off'; recording_enabled = 'off'
    }
    foreach ($index in 1..8) { $required["nic$index"] = 'none' }
    foreach ($index in 1..4) { $required["uart$index"] = 'off' }
    foreach ($key in $required.Keys) {
        if (-not $values.ContainsKey($key) -or $values[$key] -cne $required[$key]) {
            throw "VM contract does not match at $key."
        }
    }
    if ($MachineReadable -match '(?im)^(?:SharedFolderName|SharedFolderPath|SharedFolderNameMachineMapping|SharedFolderPathMachineMapping)') {
        throw 'VM has an unexpected shared folder.'
    }
}

function Expand-ArgusGuestTemplate {
    param([string]$Template, [string]$PasswordHash)
    if ($PasswordHash -notmatch '^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$') { throw 'Unexpected SHA-512 crypt format.' }
    $placeholder = '__ARGUS_SETUP_PASSWORD_SHA512__'
    if ([regex]::Matches($Template, [regex]::Escape($placeholder)).Count -ne 1 -or $Template.Contains('@@')) {
        throw 'Public guest template has an unexpected credential placeholder.'
    }
    return $Template.Replace($placeholder, $PasswordHash)
}

function Assert-ArgusPrivateAcl {
    param([string]$Path, [Security.Principal.SecurityIdentifier]$UserSid, [bool]$Directory)
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer -ne $Directory) {
        throw 'Private path is not an ordinary file or directory.'
    }
    $acl = Get-Acl -LiteralPath $Path
    $allowed = @($UserSid.Value, 'S-1-5-18')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'Private path has a different owner.' }
    if ($Directory -and -not $acl.AreAccessRulesProtected) { throw 'Existing private directory inherits unreviewed access rules.' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin $allowed) {
            throw 'Existing private path grants access to another identity.'
        }
    }
}

function Ensure-ArgusPrivateDirectory {
    param([string]$Path, [Security.Principal.SecurityIdentifier]$UserSid)
    if (-not (Test-Path -LiteralPath $Path)) {
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetOwner($UserSid)
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        foreach ($sid in @($UserSid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
            $security.AddAccessRule($rule)
        }
        [IO.FileSystemAclExtensions]::CreateDirectory($security, $Path) | Out-Null
    }
    Assert-ArgusPrivateAcl -Path $Path -UserSid $UserSid -Directory $true
}

function Write-ArgusNewUtf8File {
    param([string]$Path, [string]$Content)
    $file = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
        $file.Write($bytes, 0, $bytes.Length)
    } finally { $file.Dispose() }
}

function New-ArgusRandomPassword {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return -join (1..40 | ForEach-Object { $alphabet[[Security.Cryptography.RandomNumberGenerator]::GetInt32($alphabet.Length)] })
}

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ($repo -ine 'E:\ARGUS' -or -not $IsWindows) { throw 'This fixed helper requires the approved Windows ARGUS repository.' }
Set-Location -LiteralPath $repo
$vbox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
$iso = 'E:\ARGUS\runtime\downloads\ubuntu\ubuntu-24.04.5-live-server-amd64.iso'
$expectedHash = '97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8'
$credentialPath = 'E:\ARGUS-Private\credentials\argus-vm.xml'
$bootstrap = 'E:\ARGUS-Private\credentials\bootstrap'
$privateTemplate = Join-Path $bootstrap 'ubuntu-user-data.yaml'
$auxPrefix = Join-Path $bootstrap 'argus-unattended-'
$resultPath = 'E:\ARGUS\runtime\logs\package-b-guest-preparation.json'
$publicTemplatePath = Join-Path $repo 'templates\ubuntu-autoinstall-user-data.yaml.in'
$postScriptPath = Join-Path $repo 'templates\argus-vbox-postinstall.sh'
if (Test-Path -LiteralPath $resultPath) { throw 'A guest preparation attempt is already recorded; refuse an automatic repeat.' }
$stage = 'preflight'
$result = [ordered]@{
    StartedAtUtc = [DateTime]::UtcNow.ToString('o'); Status = 'preflight'; Stage = $stage
    VMUUID = '5ace2701-f69f-43de-a36c-0d2b2d530a1e'; VMStarted = $false
    CredentialPath = $credentialPath; BootstrapDirectory = $bootstrap
    CredentialReused = $false; SubprocessExitCodes = [ordered]@{}; ArtifactSHA256 = [ordered]@{}
}
$markerOwned = $false
$password = $null; $dummy = $null; $passwordHash = $null; $expandedTemplate = $null
try {
    foreach ($path in @($vbox, $openssl, $iso, $publicTemplatePath, $postScriptPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'A pinned prerequisite file is missing.' }
    }
    $sourceEvidence = Get-Content -LiteralPath 'E:\ARGUS\runtime\logs\package-b-ubuntu-source-verification.json' -Raw | ConvertFrom-Json
    if (-not $sourceEvidence.ValidSignature -or $sourceEvidence.GpgExitCode -ne 0 -or
        $sourceEvidence.SigningKeyFingerprint -cne '843938DF228D22F7B3742BC0D94AA3F0EFE21092' -or
        $sourceEvidence.ExpectedSHA256 -cne $expectedHash) { throw 'Pinned successful Ubuntu signature evidence does not match.' }
    $signatureLog = Get-Content -LiteralPath 'E:\ARGUS\runtime\logs\package-b-ubuntu-signature.log' -Raw
    if ($signatureLog -notmatch '(?m)^\[GNUPG:\] VALIDSIG 843938DF228D22F7B3742BC0D94AA3F0EFE21092 ') {
        throw 'The saved successful signature record is missing.'
    }
    $sums = Get-Content -LiteralPath 'E:\ARGUS\runtime\downloads\ubuntu\SHA256SUMS' -Raw
    if ($sums -notmatch ('(?m)^' + $expectedHash + '\s+\*?ubuntu-24\.04\.5-live-server-amd64\.iso\r?$')) {
        throw 'Verified checksum entry no longer matches.'
    }
    if ((Get-Item -LiteralPath $iso).Length -ne 4080486400 -or (Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash) {
        throw 'Current installation ISO does not match the approved bytes.'
    }
    $version = Invoke-ArgusCapturedProcess -FilePath $vbox -Arguments @('--version')
    $result.SubprocessExitCodes.Version = $version.ExitCode
    if ($version.ExitCode -ne 0 -or $version.StandardOutput.Trim() -cne '7.2.20r175154') { throw 'Pinned VirtualBox version differs.' }
    $vmInfo = Invoke-ArgusCapturedProcess -FilePath $vbox -Arguments @('showvminfo', $result.VMUUID, '--machinereadable')
    $result.SubprocessExitCodes.VMPreflight = $vmInfo.ExitCode
    if ($vmInfo.ExitCode -ne 0) { throw 'Could not read stopped VM metadata.' }
    Assert-ArgusMachineInfo -MachineReadable $vmInfo.StandardOutput
    $vmXml = [xml](Get-Content -LiteralPath 'E:\ARGUS\runtime\vms\ARGUS-Offline\ARGUS-Offline.vbox' -Raw)
    $machine = $vmXml.SelectSingleNode("//*[local-name()='Machine']")
    if ($null -eq $machine -or $machine.GetAttribute('OSType') -cne 'Ubuntu24_LTS_64' -or
        $vmXml.SelectNodes("//*[local-name()='SharedFolder' or local-name()='HostDrive']").Count -ne 0) {
        throw 'VM XML does not match the approved guest and filesystem boundaries.'
    }
    $result.Status = 'preparing'; $result.Stage = 'claim_attempt'
    Write-ArgusNewUtf8File -Path $resultPath -Content ($result | ConvertTo-Json -Depth 6)
    $markerOwned = $true
    $stage = 'private_storage'
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($path in @('E:\ARGUS-Private', 'E:\ARGUS-Private\credentials', $bootstrap)) {
        Ensure-ArgusPrivateDirectory -Path $path -UserSid $sid
    }
    if (@(Get-ChildItem -LiteralPath $bootstrap -Force).Count -ne 0) { throw 'Private bootstrap directory already contains files; refuse overwrite.' }
    $stage = 'credential'
    if (Test-Path -LiteralPath $credentialPath) {
        Assert-ArgusPrivateAcl -Path $credentialPath -UserSid $sid -Directory $false
        $credential = Import-Clixml -LiteralPath $credentialPath
        if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'argus-setup') {
            throw 'Existing credential has the wrong identity; no reset performed.'
        }
        $password = $credential.GetNetworkCredential().Password
        if ($password -cnotmatch '^[A-Za-z0-9]{32,}$') { throw 'Existing setup credential does not meet the fixed random-password contract.' }
        $result.CredentialReused = $true
    } else {
        $password = New-ArgusRandomPassword
        $credential = [Management.Automation.PSCredential]::new('argus-setup', (ConvertTo-SecureString -String $password -AsPlainText -Force))
        $credential | Export-Clixml -LiteralPath $credentialPath -Encoding utf8 -NoClobber
        Assert-ArgusPrivateAcl -Path $credentialPath -UserSid $sid -Directory $false
    }
    $stage = 'hash'
    $hashed = Invoke-ArgusCapturedProcess -FilePath $openssl -Arguments @('passwd', '-6', '-stdin') -InputText $password
    $result.SubprocessExitCodes.PasswordHash = $hashed.ExitCode
    if ($hashed.ExitCode -ne 0) { throw 'Password hashing subprocess failed; raw output suppressed.' }
    $passwordHash = $hashed.StandardOutput.Trim()
    $expandedTemplate = Expand-ArgusGuestTemplate -Template (Get-Content -LiteralPath $publicTemplatePath -Raw) -PasswordHash $passwordHash
    Write-ArgusNewUtf8File -Path $privateTemplate -Content $expandedTemplate
    Assert-ArgusPrivateAcl -Path $privateTemplate -UserSid $sid -Directory $false
    $stage = 'unattended_prepare'
    $dummy = New-ArgusRandomPassword
    $prepare = Invoke-ArgusCapturedProcess -FilePath $vbox -Arguments @(
        'unattended', 'install', $result.VMUUID, "--iso=$iso", '--user=argus-setup', '--user-password-file=stdin',
        '--full-user-name=ARGUS local setup', '--hostname=argus-offline.local', '--locale=en_US', '--country=US', '--time-zone=UTC',
        '--no-install-additions', '--no-install-txs', '--start-vm=none', "--script-template=$privateTemplate",
        "--post-install-template=$postScriptPath", "--auxiliary-base-path=$auxPrefix"
    ) -InputText $dummy
    $result.SubprocessExitCodes.UnattendedPrepare = $prepare.ExitCode
    # VBoxManage prints passwords: neither captured stream is emitted or written to a log.
    if ($prepare.ExitCode -ne 0) { throw 'Unattended media preparation failed; raw output suppressed.' }
    $stage = 'post_preparation_contract'
    $after = Invoke-ArgusCapturedProcess -FilePath $vbox -Arguments @('showvminfo', $result.VMUUID, '--machinereadable')
    $result.SubprocessExitCodes.VMPostflight = $after.ExitCode
    if ($after.ExitCode -ne 0) { throw 'Could not read VM metadata after preparation.' }
    Assert-ArgusMachineInfo -MachineReadable $after.StandardOutput
    foreach ($artifact in @(Get-ChildItem -LiteralPath $bootstrap -File -Force)) {
        Assert-ArgusPrivateAcl -Path $artifact.FullName -UserSid $sid -Directory $false
        $result.ArtifactSHA256[$artifact.FullName] = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    foreach ($artifact in @($credentialPath, $publicTemplatePath, $postScriptPath, $iso)) {
        $result.ArtifactSHA256[$artifact] = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $result.Status = 'prepared_not_booted'
    $result.Stage = 'complete'
    $result['CompletedAtUtc'] = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    Write-Output "Guest media prepared; VM remains off. Safe result: $resultPath"
} catch {
    if ($markerOwned) {
        $result.Status = 'stopped_after_preparation_error'; $result.Stage = $stage
        $result['CompletedAtUtc'] = [DateTime]::UtcNow.ToString('o')
        [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    }
    throw "ARGUS guest preparation stopped at stage '$stage'. No automatic retry or VM start; raw subprocess output suppressed."
} finally {
    $password = $null; $dummy = $null; $passwordHash = $null; $expandedTemplate = $null
    $hashed = $null; $prepare = $null; $credential = $null
}
