# Synthetic regression only: no private paths, real credentials, or VBox process is accessed.
#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$argusRepo=Split-Path $PSScriptRoot -Parent
$argusHelper=Join-Path $argusRepo 'scripts\Send-ArgusConsolePassword.ps1'
if (-not (Test-Path -LiteralPath $argusHelper)) { throw 'CONSOLE PASSWORD REGRESSION: required bounded sender is missing.' }
$argusTokens=$null; $argusErrors=$null
$argusAst=[Management.Automation.Language.Parser]::ParseFile($argusHelper,[ref]$argusTokens,[ref]$argusErrors)
if (@($argusErrors).Count) { throw 'Sender has parser errors.' }
foreach ($argusFunction in $argusAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    . ([scriptblock]::Create($argusFunction.Extent.Text))
}
$argusPassed=0
function Assert-ArgusSender([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw ('CONSOLE PASSWORD REGRESSION: '+$Message) }; $script:argusPassed++
}
function Assert-ArgusSenderThrows([scriptblock]$Action,[string]$Message) {
    $rejected=$false; try { & $Action | Out-Null } catch { $rejected=$true }
    Assert-ArgusSender $rejected $Message
}
function Read-ArgusSyntheticSharedText([string]$Path) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $reader=[IO.StreamReader]::new($stream)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}
$argusContract=Get-ArgusConsolePasswordContract
Assert-ArgusSender ($argusContract.UUID -ceq '5ace2701-f69f-43de-a36c-0d2b2d530a1e') 'Only the own VM UUID is allowed.'
Assert-ArgusSender ($argusContract.ActivePath -ceq 'E:\ARGUS-Private\credentials\argus-vm.xml' -and $argusContract.PendingPath -ceq 'E:\ARGUS-Private\credentials\argus-vm-own-pending.xml') 'Credential sources must be fixed.'
Assert-ArgusSender ($argusContract.Bootstrap -ceq 'E:\ARGUS-Private\credentials\bootstrap' -and $argusContract.VBoxHome -ceq 'E:\ARGUS\runtime\virtualbox-user') 'Temporary storage and VBox profile must stay in their approved locations.'
Assert-ArgusSender ($argusContract.TimeoutSeconds -eq 30) 'The owned caller process must have a fixed bound.'
foreach ($argusLength in @(12,128)) { Assert-ArgusSender (Test-ArgusConsolePasswordBytes ([Text.Encoding]::ASCII.GetBytes(('A'*$argusLength)))) 'Valid ASCII length must be accepted.' }
foreach ($argusText in @(('A'*11),('A'*129),(('A'*11)+[char]10),(('A'*11)+[char]13),(('A'*11)+[char]0),(('A'*11)+[char]96))) {
    Assert-ArgusSender (-not (Test-ArgusConsolePasswordBytes ([Text.Encoding]::UTF8.GetBytes($argusText)))) 'Control characters, bad length and the VBox backtick mapping defect must stop before sending.'
}
Assert-ArgusSender (-not (Test-ArgusConsolePasswordBytes ([byte[]](65,65,65,65,65,65,65,65,65,65,65,128)))) 'Non-ASCII bytes must be rejected.'
$argusSyntheticRoot=Join-Path $argusRepo ('runtime\tests\console-password-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($argusSyntheticRoot)
$argusOriginalContract=$argusContract
$script:argusSyntheticContract=[pscustomobject]@{
    Bootstrap=$argusSyntheticRoot; LogDirectory=$argusSyntheticRoot; UUID=$argusContract.UUID
    ActivePath=(Join-Path $argusSyntheticRoot 'active.xml'); PendingPath=(Join-Path $argusSyntheticRoot 'pending.xml')
    VBoxHome=$argusContract.VBoxHome; VBoxExe=$argusContract.VBoxExe; TimeoutSeconds=30; Account='argus-setup'
    PrivateDirectories=@($argusSyntheticRoot)
}
function Get-ArgusConsolePasswordContract { return $script:argusSyntheticContract }
$argusSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$argusAcl=[Security.AccessControl.DirectorySecurity]::new()
$argusAcl.SetOwner($argusSid); $argusAcl.SetAccessRuleProtection($true,$false)
foreach ($argusIdentity in @($argusSid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $argusAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($argusIdentity,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $argusSyntheticRoot -AclObject $argusAcl
$argusSecure=ConvertTo-SecureString 'SyntheticOnly12!' -AsPlainText -Force
$argusTemp=$null; $argusReceipt=$null; $argusImported=$null
try {
    $argusCredential=[Management.Automation.PSCredential]::new('argus-setup',$argusSecure)
    Export-Clixml -InputObject $argusCredential -LiteralPath $argusSyntheticContract.ActivePath -NoClobber
    Export-Clixml -InputObject $argusCredential -LiteralPath $argusSyntheticContract.PendingPath -NoClobber
    foreach ($argusCaseVariant in @('Active','ACTIVE','Pending','PENDING')) {
        Assert-ArgusSenderThrows { Import-ArgusConsoleCredential -CredentialSource $argusCaseVariant -UserSid $argusSid } 'Case variants must be rejected before choosing a different credential source.'
        Assert-ArgusSenderThrows { New-ArgusConsolePasswordReceipt -ActionId ([guid]::NewGuid()) -CredentialSource $argusCaseVariant } 'Receipt validation must reject the same case variants consistently.'
    }
    $argusSourceBefore=[IO.File]::ReadAllBytes($argusSyntheticContract.ActivePath)
    $argusImported=Import-ArgusConsoleCredential -CredentialSource active -UserSid $argusSid
    Assert-ArgusSender ($argusImported.UserName -ceq 'argus-setup') 'ACL-checked synthetic DPAPI import must preserve the fixed account.'
    Assert-ArgusSenderThrows { Import-ArgusConsoleCredential -CredentialSource other -UserSid $argusSid } 'Unknown source must be rejected.'
    $argusTemp=New-ArgusConsolePasswordFile -Credential $argusImported -UserSid $argusSid
    $argusBytes=[IO.File]::ReadAllBytes($argusTemp.Path)
    Assert-ArgusSender ([Text.Encoding]::ASCII.GetString($argusBytes) -ceq "SyntheticOnly12!`n") 'The owned file must contain exactly synthetic ASCII plus one LF, without BOM/CR.'
    Assert-ArgusSenderThrows { [IO.File]::WriteAllText($argusTemp.Path,'replacement') } 'The open owned handle must prevent replacement during sending.'
    $argusStart=New-ArgusConsoleProcessStart -PasswordPath $argusTemp.Path
    Assert-ArgusSender (($argusStart.ArgumentList -join '|') -ceq ('controlvm|'+$argusOriginalContract.UUID+'|keyboardputfile|'+$argusTemp.Path)) 'Arguments may contain only the UUID, command and path.'
    Assert-ArgusSender ($argusStart.Environment['VBOX_USER_HOME'] -ceq $argusOriginalContract.VBoxHome -and $argusStart.RedirectStandardOutput -and $argusStart.RedirectStandardError -and -not $argusStart.UseShellExecute) 'Profile must be child-local and output must be captured.'
    $argusTempPath=$argusTemp.Path
    Remove-ArgusConsolePasswordFile -OwnedFile $argusTemp -UserSid $argusSid
    $argusTemp=$null
    Assert-ArgusSender (-not [IO.File]::Exists($argusTempPath)) 'Only the owned temporary file must be removed.'
    Assert-ArgusSender ([Convert]::ToBase64String([IO.File]::ReadAllBytes($argusSyntheticContract.ActivePath)) -ceq [Convert]::ToBase64String($argusSourceBefore)) 'Source encrypted credential bytes must remain unchanged.'
    $argusForeign=Join-Path $argusSyntheticRoot 'foreign.txt'; [IO.File]::WriteAllText($argusForeign,'preserve')
    Assert-ArgusSenderThrows { Remove-ArgusConsolePasswordFile -OwnedFile ([pscustomobject]@{Path=$argusForeign;Stream=$null;CreatedUtc=[datetime]::UtcNow}) -UserSid $argusSid } 'Cleanup must reject non-owned names.'
    Assert-ArgusSender ([IO.File]::ReadAllText($argusForeign) -ceq 'preserve') 'Foreign file must survive cleanup.'
    $argusUnsafeSecure=ConvertTo-SecureString ('SyntheticOnly'+[char]96) -AsPlainText -Force
    try {
        Assert-ArgusSenderThrows { New-ArgusConsolePasswordFile -Credential ([Management.Automation.PSCredential]::new('argus-setup',$argusUnsafeSecure)) -UserSid $argusSid } 'A real synthetic SecureString containing backtick must be rejected before file creation.'
        Assert-ArgusSender (@(Get-ChildItem -LiteralPath $argusSyntheticRoot -Filter 'console-password-*.txt').Count -eq 0) 'Unsupported input must leave no plaintext file.'
    } finally { $argusUnsafeSecure.Dispose() }
    # A synthetic bad ACL must stop before import, while the real source remains untouched.
    $argusGoodAcl=Get-Acl -LiteralPath $argusSyntheticContract.ActivePath
    $argusBadAcl=Get-Acl -LiteralPath $argusSyntheticContract.ActivePath
    $argusBadAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Read','Allow'))
    Set-Acl -LiteralPath $argusSyntheticContract.ActivePath -AclObject $argusBadAcl
    Assert-ArgusSenderThrows { Import-ArgusConsoleCredential -CredentialSource active -UserSid $argusSid } 'A foreign allow ACE must prevent credential import.'
    Set-Acl -LiteralPath $argusSyntheticContract.ActivePath -AclObject $argusGoodAcl
    $argusAction=[guid]::NewGuid(); $argusReceipt=New-ArgusConsolePasswordReceipt -ActionId $argusAction -CredentialSource active
    $argusReceiptBytes=Read-ArgusSyntheticSharedText $argusReceipt.Path
    Assert-ArgusSenderThrows { New-ArgusConsolePasswordReceipt -ActionId $argusAction -CredentialSource active } 'CreateNew receipt must prevent repeating the same action ID.'
    Assert-ArgusSender ((Read-ArgusSyntheticSharedText $argusReceipt.Path) -ceq $argusReceiptBytes) 'Existing receipt must be preserved.'
    Assert-ArgusSender (($argusReceipt.State.Keys | Sort-Object) -join ',' -ceq 'ActionId,CredentialSource,ExitCode,FinishedAtUtc,GuestResult,StartedAtUtc,Status,TemporaryFileRemoved,VMUUID') 'Receipt may contain only fixed safe metadata.'
    Assert-ArgusSender (-not $argusReceiptBytes.Contains('SyntheticOnly12!')) 'Receipt must not contain password content.'
    Assert-ArgusSender ($argusReceipt.State.GuestResult -ceq 'not_observed' -and $argusReceipt.State.Status -ceq 'safe_failed_before_send') 'Receipt must never claim a guest login or password change.'
    $argusReceipt.Stream.Dispose()
    $argusText=[IO.File]::ReadAllText($argusHelper)
    Assert-ArgusSender ($argusText.Contains('[switch]$PasswordPromptConfirmed') -and $argusText.Contains('if (-not $PasswordPromptConfirmed)')) 'Every actual invocation must explicitly confirm an observed password prompt.'
    Assert-ArgusSender (-not ($argusText -match '(?i)guestcontrol|keyboardputstring|startvm|controlvm.+(?:poweroff|reset)')) 'The helper must contain no broader guest or VM action.'
    # Exercise the actual bounded child implementation using only a fresh synthetic PowerShell caller.
    $script:argusSyntheticChildCode="[Console]::Out.Write('SyntheticOutputOnly');[Console]::Error.Write('SyntheticErrorOnly');exit 0"
    function New-ArgusConsoleProcessStart {
        param([string]$PasswordPath)
        $start=[Diagnostics.ProcessStartInfo]::new(); $start.FileName=(Get-Process -Id $PID).Path
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        foreach ($argument in @('-NoProfile','-Command',$script:argusSyntheticChildCode)) { $start.ArgumentList.Add($argument) }
        return $start
    }
    $argusCapture=@(Invoke-ArgusConsolePasswordProcess -PasswordPath 'unused-synthetic-path')
    Assert-ArgusSender ($argusCapture.Count -eq 1 -and $argusCapture[0].Uncertain -and $argusCapture[0].ExitCode -eq 0) 'Even zero exit plus captured output/errors must be uncertain, never emitted.'
    Assert-ArgusSender (($argusCapture | ConvertTo-Json -Compress) -notmatch 'SyntheticOutputOnly|SyntheticErrorOnly') 'The result must discard child output contents.'
    $script:argusSyntheticChildCode='Start-Sleep -Seconds 20'; $argusSyntheticContract.TimeoutSeconds=1
    $argusWatch=[Diagnostics.Stopwatch]::StartNew()
    $argusTimeout=Invoke-ArgusConsolePasswordProcess -PasswordPath 'unused-synthetic-path'
    $argusWatch.Stop()
    Assert-ArgusSender ($argusTimeout.Uncertain -and $null -eq $argusTimeout.ExitCode -and $argusWatch.Elapsed.TotalSeconds -lt 7) 'Timeout must end only the owned synthetic caller within the fixed bound and retain uncertainty.'
} finally {
    if ($null -ne $argusReceipt) { $argusReceipt.Stream.Dispose() }
    if ($null -ne $argusTemp) { Remove-ArgusConsolePasswordFile -OwnedFile $argusTemp -UserSid $argusSid }
    $argusSecure.Dispose(); if ($null -ne $argusImported) { $argusImported.Password.Dispose() }
    $argusResolved=[IO.Path]::GetFullPath($argusSyntheticRoot)
    $argusExpected=[IO.Path]::GetFullPath((Join-Path $argusRepo 'runtime\tests'))+[IO.Path]::DirectorySeparatorChar
    if (-not $argusResolved.StartsWith($argusExpected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Synthetic cleanup escaped its fresh test directory.' }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $argusResolved -Recurse -Force
}
Write-Output ('PASS: {0} synthetic console-password assertions; no private input or VBox process accessed.' -f $argusPassed)
