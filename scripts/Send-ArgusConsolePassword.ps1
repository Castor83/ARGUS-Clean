# One observed Linux password prompt only. Never confirms a guest login/password change.
# Source: VirtualBox v7.2.20 VBoxManageControlVM.cpp, g_aASCIIChars/keyboardPutFile.
#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('active','pending',IgnoreCase=$false)][string]$CredentialSource,
    [switch]$PasswordPromptConfirmed,
    [switch]$USKeyboardConfirmed,
    [guid]$ActionId=[guid]::NewGuid()
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-ArgusConsolePasswordContract {
    return [pscustomobject]@{
        UUID='5ace2701-f69f-43de-a36c-0d2b2d530a1e'; Account='argus-setup'
        ActivePath='E:\ARGUS-Private\credentials\argus-vm.xml'
        PendingPath='E:\ARGUS-Private\credentials\argus-vm-own-pending.xml'
        Bootstrap='E:\ARGUS-Private\credentials\bootstrap'
        PrivateDirectories=@('E:\ARGUS-Private','E:\ARGUS-Private\credentials','E:\ARGUS-Private\credentials\bootstrap')
        VBoxExe='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
        VBoxHome='E:\ARGUS\runtime\virtualbox-user'; LogDirectory='E:\ARGUS\runtime\logs'; TimeoutSeconds=30
    }
}
function Assert-ArgusConsolePrivateAcl {
    param([string]$Path,[Security.Principal.SecurityIdentifier]$UserSid,[bool]$Directory)
    $item=Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer -ne $Directory) { throw 'Unsafe private path.' }
    $acl=Get-Acl -LiteralPath $Path
    $allowed=@($UserSid.Value,'S-1-5-18')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'Unexpected private owner.' }
    if ($Directory -and -not $acl.AreAccessRulesProtected) { throw 'Unreviewed private inheritance.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin $allowed) { throw 'Unexpected private access.' }
    }
}
function Test-ArgusConsolePasswordBytes {
    param([AllowNull()][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 12 -or $Bytes.Length -gt 128) { return $false }
    foreach ($value in $Bytes) {
        # VBox 7.2.20 maps ASCII backtick (0x60) to the apostrophe key: fail before typing.
        if ($value -lt 0x20 -or $value -gt 0x7e -or $value -eq 0x60) { return $false }
    }
    return $true
}
function Import-ArgusConsoleCredential {
    param([ValidateSet('active','pending',IgnoreCase=$false)][string]$CredentialSource,[Security.Principal.SecurityIdentifier]$UserSid)
    $contract=Get-ArgusConsolePasswordContract
    foreach ($directory in $contract.PrivateDirectories) { Assert-ArgusConsolePrivateAcl -Path $directory -UserSid $UserSid -Directory $true }
    $path=if ($CredentialSource -ceq 'active') { $contract.ActivePath } else { $contract.PendingPath }
    Assert-ArgusConsolePrivateAcl -Path $path -UserSid $UserSid -Directory $false
    $credential=Import-Clixml -LiteralPath $path
    if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne $contract.Account) { throw 'Unexpected credential account/type.' }
    return $credential
}
function New-ArgusConsolePasswordFile {
    param([Management.Automation.PSCredential]$Credential,[Security.Principal.SecurityIdentifier]$UserSid)
    $contract=Get-ArgusConsolePasswordContract
    if ($null -eq $Credential -or $Credential.UserName -cne $contract.Account) { throw 'Unexpected credential account.' }
    foreach ($directory in $contract.PrivateDirectories) { Assert-ArgusConsolePrivateAcl -Path $directory -UserSid $UserSid -Directory $true }
    $pointer=[IntPtr]::Zero; $secretBytes=$null; $lineBytes=$null; $owned=$null
    try {
        # Avoid constructing a managed plaintext password string; validate UTF-16 units before ASCII conversion.
        $length=$Credential.Password.Length
        if ($length -lt 12 -or $length -gt 128) { throw 'Password is outside the supported console policy.' }
        $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
        $secretBytes=[byte[]]::new($length)
        for ($index=0;$index -lt $length;$index++) {
            $value=[Runtime.InteropServices.Marshal]::ReadInt16($pointer,$index*2)
            if ($value -lt 0x20 -or $value -gt 0x7e -or $value -eq 0x60) { throw 'Password cannot be safely mapped by this VBox console command.' }
            $secretBytes[$index]=[byte]$value
        }
        if (-not (Test-ArgusConsolePasswordBytes $secretBytes)) { throw 'Unsupported console password.' }
        $path=Join-Path $contract.Bootstrap ('console-password-'+[guid]::NewGuid().ToString('N')+'.txt')
        $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
        $owned=[pscustomobject]@{Path=[IO.Path]::GetFullPath($path);Stream=$stream;CreatedUtc=([IO.File]::GetCreationTimeUtc($path))}
        # The checked private directory protects the first write. Protect only this newly owned file's inherited ACL.
        Assert-ArgusConsolePrivateAcl -Path $path -UserSid $UserSid -Directory $false
        $acl=Get-Acl -LiteralPath $path; $acl.SetAccessRuleProtection($true,$true); Set-Acl -LiteralPath $path -AclObject $acl
        Assert-ArgusConsolePrivateAcl -Path $path -UserSid $UserSid -Directory $false
        $lineBytes=[byte[]]::new($length+1); [Array]::Copy($secretBytes,$lineBytes,$length); $lineBytes[$length]=10
        $stream.Write($lineBytes,0,$lineBytes.Length); $stream.Flush($true); $stream.Dispose()
        # VBox itself opens with DENY_WRITE, so retain a read-only handle after the completed write.
        # This permits its reader while excluding replacement/writing/deletion during the send.
        $owned.Stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if ([IO.File]::GetCreationTimeUtc($path) -ne $owned.CreatedUtc) { throw 'Temporary file identity changed.' }
        return $owned
    } catch {
        if ($null -ne $owned) { Remove-ArgusConsolePasswordFile -OwnedFile $owned -UserSid $UserSid }
        throw 'Safe console password preparation failed.'
    } finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        if ($null -ne $secretBytes) { [Array]::Clear($secretBytes,0,$secretBytes.Length) }
        if ($null -ne $lineBytes) { [Array]::Clear($lineBytes,0,$lineBytes.Length) }
    }
}
function Remove-ArgusConsolePasswordFile {
    param($OwnedFile,[Security.Principal.SecurityIdentifier]$UserSid)
    $contract=Get-ArgusConsolePasswordContract
    $path=[IO.Path]::GetFullPath($OwnedFile.Path)
    if ([IO.Path]::GetDirectoryName($path) -ine [IO.Path]::GetFullPath($contract.Bootstrap) -or
        [IO.Path]::GetFileName($path) -cnotmatch '\Aconsole-password-[0-9a-f]{32}\.txt\z') { throw 'Cleanup is outside the owned temporary path.' }
    try {
        Assert-ArgusConsolePrivateAcl -Path $path -UserSid $UserSid -Directory $false
        if ((Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $UserSid.Value -or
            [IO.File]::GetCreationTimeUtc($path) -ne $OwnedFile.CreatedUtc) { throw 'Temporary ownership/identity changed.' }
    } finally { if ($null -ne $OwnedFile.Stream) { $OwnedFile.Stream.Dispose() } }
    # No recursive or directory deletion, and no wildcard interpretation.
    [IO.File]::Delete($path)
}
function New-ArgusConsoleProcessStart {
    param([string]$PasswordPath)
    $contract=Get-ArgusConsolePasswordContract
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($PasswordPath)) -ine [IO.Path]::GetFullPath($contract.Bootstrap) -or
        [IO.Path]::GetFileName($PasswordPath) -cnotmatch '\Aconsole-password-[0-9a-f]{32}\.txt\z') { throw 'Unexpected password input path.' }
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$contract.VBoxExe; $start.WorkingDirectory='E:\ARGUS'
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $start.Environment['VBOX_USER_HOME']=$contract.VBoxHome
    foreach ($argument in @('controlvm',$contract.UUID,'keyboardputfile',$PasswordPath)) { $start.ArgumentList.Add($argument) }
    return $start
}
function Invoke-ArgusConsolePasswordProcess {
    param([string]$PasswordPath)
    $contract=Get-ArgusConsolePasswordContract
    $child=[Diagnostics.Process]::new(); $child.StartInfo=New-ArgusConsoleProcessStart -PasswordPath $PasswordPath
    $outTask=$null; $errTask=$null; $outputText=$null; $errorText=$null; $started=$false
    try {
        if (-not $child.Start()) { throw 'Caller did not start.' }
        $started=$true
        $child.StandardInput.Close()
        $outTask=$child.StandardOutput.ReadToEndAsync(); $errTask=$child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit($contract.TimeoutSeconds*1000)) {
            # Only this Process instance, never the VM, its frontend, or a process tree.
            $child.Kill(); $null=$child.WaitForExit(5000)
            return [pscustomobject]@{ExitCode=$null;Uncertain=$true}
        }
        if (-not $outTask.Wait(1000) -or -not $errTask.Wait(1000)) { return [pscustomobject]@{ExitCode=$child.ExitCode;Uncertain=$true} }
        $outputText=$outTask.GetAwaiter().GetResult(); $errorText=$errTask.GetAwaiter().GetResult()
        # VBox can report file read failures on stderr but still exit 0. Never emit either stream.
        return [pscustomobject]@{ExitCode=$child.ExitCode;Uncertain=($child.ExitCode -ne 0 -or $outputText.Length -gt 0 -or $errorText.Length -gt 0)}
    } finally {
        # Also bound unexpected capture/wait failures after Start; the owned caller is the only kill target.
        if ($started) { try { if (-not $child.HasExited) { $child.Kill(); $null=$child.WaitForExit(5000) } } catch {} }
        $outputText=$null; $errorText=$null; $outTask=$null; $errTask=$null; $child.Dispose()
    }
}
function New-ArgusConsolePasswordReceipt {
    param([guid]$ActionId,[ValidateSet('active','pending',IgnoreCase=$false)][string]$CredentialSource)
    $contract=Get-ArgusConsolePasswordContract
    $path=Join-Path $contract.LogDirectory ('package-b-console-password-'+$ActionId.ToString('N')+'.json')
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    $state=[ordered]@{
        ActionId=$ActionId.ToString();VMUUID=$contract.UUID;CredentialSource=$CredentialSource
        StartedAtUtc=[DateTime]::UtcNow.ToString('o');FinishedAtUtc=$null
        Status='safe_failed_before_send';GuestResult='not_observed';ExitCode=$null;TemporaryFileRemoved=$null
    }
    $receipt=[pscustomobject]@{Path=$path;Stream=$stream;State=$state}
    try { Write-ArgusConsolePasswordReceipt -Receipt $receipt } catch { $stream.Dispose(); throw 'Safe receipt write failed.' }
    return $receipt
}
function Write-ArgusConsolePasswordReceipt {
    param($Receipt)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Receipt.State | ConvertTo-Json))
    $Receipt.Stream.Position=0; $Receipt.Stream.SetLength(0)
    $Receipt.Stream.Write($bytes,0,$bytes.Length); $Receipt.Stream.Flush($true)
}

$argusReceipt=$null; $argusCredential=$null; $argusOwnedFile=$null; $argusExit=20
try {
    if (-not $IsWindows -or [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')) -ine 'E:\ARGUS') { throw 'Fixed Windows repository required.' }
    $argusReceipt=New-ArgusConsolePasswordReceipt -ActionId $ActionId -CredentialSource $CredentialSource
    if (-not $PasswordPromptConfirmed) { throw 'A newly observed Linux password prompt is required.' }
    if (-not $USKeyboardConfirmed) { throw 'US guest keyboard mapping must be confirmed.' }
    $argusSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $argusCredential=Import-ArgusConsoleCredential -CredentialSource $CredentialSource -UserSid $argusSid
    $argusOwnedFile=New-ArgusConsolePasswordFile -Credential $argusCredential -UserSid $argusSid
    # Persist uncertainty before starting: interruption or partial typing never authorizes a retry.
    $argusReceipt.State.Status='unknown_partial_send'; Write-ArgusConsolePasswordReceipt -Receipt $argusReceipt
    $argusResult=Invoke-ArgusConsolePasswordProcess -PasswordPath $argusOwnedFile.Path
    $argusReceipt.State.ExitCode=$argusResult.ExitCode
    if (-not $argusResult.Uncertain) { $argusReceipt.State.Status='send_attempted_guest_unconfirmed'; $argusExit=0 }
} catch {
    # Suppress exception objects/details and every derived secret value. No automatic retry.
    $argusExit=20
} finally {
    if ($null -ne $argusOwnedFile) {
        try {
            Remove-ArgusConsolePasswordFile -OwnedFile $argusOwnedFile -UserSid $argusSid
            if ($null -ne $argusReceipt) { $argusReceipt.State.TemporaryFileRemoved=$true }
        } catch {
            $argusExit=20
            if ($null -ne $argusReceipt) { $argusReceipt.State.TemporaryFileRemoved=$false }
        }
    }
    if ($null -ne $argusCredential) { $argusCredential.Password.Dispose(); $argusCredential=$null }
    if ($null -ne $argusReceipt) {
        $argusReceipt.State.FinishedAtUtc=[DateTime]::UtcNow.ToString('o')
        try { Write-ArgusConsolePasswordReceipt -Receipt $argusReceipt } catch { $argusExit=20 }
        $argusReceipt.Stream.Dispose()
    }
}
exit $argusExit
