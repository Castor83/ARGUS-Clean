# Synthetic policy/storage regression. No GUI or actual private credential file is used.
#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$argusRepo = Split-Path $PSScriptRoot -Parent
$argusHelper = Join-Path $argusRepo 'scripts\Request-ArgusOwnCredential.ps1'
if (-not (Test-Path -LiteralPath $argusHelper)) { throw 'OWN CREDENTIAL REGRESSION: required password validation and pending-only storage helper is missing.' }
$argusTokens=$null; $argusErrors=$null
$argusTree=[Management.Automation.Language.Parser]::ParseFile($argusHelper,[ref]$argusTokens,[ref]$argusErrors)
if (@($argusErrors).Count) { throw 'Credential helper syntax is invalid.' }
foreach ($argusFunction in $argusTree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    . ([scriptblock]::Create($argusFunction.Extent.Text))
}
$argusPassed=0
function Assert-ArgusOwnCredential {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw ('OWN CREDENTIAL REGRESSION: '+$Message) }
    $script:argusPassed++
}
function Assert-ArgusOwnCredentialThrows {
    param([scriptblock]$Action,[string]$Message)
    $argusRejected=$false
    try { & $Action | Out-Null } catch { $argusRejected=$true }
    Assert-ArgusOwnCredential $argusRejected $Message
}
$argusContract=Get-ArgusOwnCredentialContract
Assert-ArgusOwnCredential ($argusContract.PendingPath -ceq 'E:\ARGUS-Private\credentials\argus-vm-own-pending.xml') 'Pending destination must be fixed and separate from the active credential.'
Assert-ArgusOwnCredential ($argusContract.StatusPath -ceq 'E:\ARGUS\runtime\logs\package-b-own-credential-dialog.json' -and $argusContract.Account -ceq 'argus-setup') 'Status destination/account must match the approved contract.'
foreach ($argusValid in @(('A'*12),('Z'*128),'  own PW 12!','ascii!"#$%&''()*+,-./:;<=>?@[\]^_`{|}~')) {
    Assert-ArgusOwnCredential (Test-ArgusOwnCredentialInput $argusValid $argusValid) 'Printable ASCII boundaries/spaces/punctuation must be preserved and accepted.'
}
foreach ($argusInvalid in @('',('A'*11),('A'*129),"ASCII12`nXYZ", "ASCII12`rXYZ", "ASCII12`tXYZ", (('A'*12)+"`n"), ('ASCII12'+[char]127+'XYZ'),('ASCII12'+[char]228+'XYZ'))) {
    Assert-ArgusOwnCredential (-not (Test-ArgusOwnCredentialInput $argusInvalid $argusInvalid)) 'Wrong length, control characters and non-ASCII input must be rejected.'
}
Assert-ArgusOwnCredential (-not (Test-ArgusOwnCredentialInput 'CaseSensitive12!' 'casesensitive12!')) 'Confirmation comparison must be case sensitive.'
Assert-ArgusOwnCredential (-not (Test-ArgusOwnCredentialInput ' Matching12! ' 'Matching12!')) 'Passwords must not be trimmed or normalized.'

# The actual save function is exercised against a fresh synthetic folder inside the repository.
# Only the contract provider and ACL boundary are substituted; Export-Clixml stays real.
$argusSyntheticRoot=Join-Path $argusRepo ('runtime\tests\own-credential-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($argusSyntheticRoot)
$argusSyntheticContract=[pscustomobject]@{
    PrivateDirectories=@($argusSyntheticRoot); PendingPath=(Join-Path $argusSyntheticRoot 'pending.xml')
    StatusPath=(Join-Path $argusSyntheticRoot 'status.json'); Account='argus-setup'; TimeoutMinutes=10
}
function Get-ArgusOwnCredentialContract { return $script:argusSyntheticContract }
$argusDenyAcl=$false
function Assert-ArgusPrivateAcl {
    param($Path,$UserSid,$Directory)
    if ($script:argusDenyAcl) { throw 'Synthetic rejected ACL.' }
}
$argusSyntheticSecure=ConvertTo-SecureString 'SyntheticOnly12!' -AsPlainText -Force
$argusSyntheticCredential=[Management.Automation.PSCredential]::new('argus-setup',$argusSyntheticSecure)
try {
    $argusDenyAcl=$true
    Assert-ArgusOwnCredentialThrows { Save-ArgusOwnPendingCredential -Credential $argusSyntheticCredential } 'An unacceptable directory ACL must stop before any credential write.'
    Assert-ArgusOwnCredential (-not [IO.File]::Exists($argusSyntheticContract.PendingPath)) 'Rejected ACL must leave no pending file.'
    $argusDenyAcl=$false
    Save-ArgusOwnPendingCredential -Credential $argusSyntheticCredential
    $argusPendingText=[IO.File]::ReadAllText($argusSyntheticContract.PendingPath)
    Assert-ArgusOwnCredential ($argusPendingText.Contains('<SS N="Password">') -and -not $argusPendingText.Contains('SyntheticOnly12!')) 'The actual Windows export must contain an encrypted SecureString, never plaintext.'
    $argusImported=Import-Clixml -LiteralPath $argusSyntheticContract.PendingPath
    Assert-ArgusOwnCredential ($argusImported -is [Management.Automation.PSCredential] -and $argusImported.UserName -ceq 'argus-setup') 'Pending output must remain a PSCredential for the fixed account.'
    $argusBefore=[IO.File]::ReadAllText($argusSyntheticContract.PendingPath)
    Assert-ArgusOwnCredentialThrows { Save-ArgusOwnPendingCredential -Credential $argusSyntheticCredential } 'An existing pending credential must not be replaced.'
    Assert-ArgusOwnCredential ([IO.File]::ReadAllText($argusSyntheticContract.PendingPath) -ceq $argusBefore) 'Existing pending bytes must remain unchanged.'
    # Simulate the existence-check/write race: actual NoClobber must still preserve the file.
    function Test-Path {
        param($LiteralPath,$PathType)
        if ($LiteralPath -ceq $script:argusSyntheticContract.PendingPath) { return $false }
        return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
    }
    Assert-ArgusOwnCredentialThrows { Save-ArgusOwnPendingCredential -Credential $argusSyntheticCredential } 'NoClobber must also reject a file appearing after the initial guard.'
    Assert-ArgusOwnCredential ([IO.File]::ReadAllText($argusSyntheticContract.PendingPath) -ceq $argusBefore) 'NoClobber must preserve existing bytes during a raced write.'
    Remove-Item Function:\Test-Path
    $argusSafeRecord=New-ArgusOwnDialogStatus -Status 'pending_saved' -StartedAtUtc ([DateTime]::UtcNow.ToString('o'))
    Assert-ArgusOwnCredential (($argusSafeRecord.Keys | Sort-Object) -join ',' -ceq 'Path,StartedAtUtc,Status,UpdatedAtUtc') 'Status must contain only approved metadata, no UI data.'
    Assert-ArgusOwnCredentialThrows { New-ArgusOwnDialogStatus -Status 'not_an_approved_status' -StartedAtUtc 'safe' } 'Status must reject arbitrary input values.'
} finally {
    $argusSyntheticSecure.Dispose(); $argusSyntheticCredential=$null; $argusImported=$null
    # Only this checked, fresh synthetic test directory is removed.
    $argusResolved=[IO.Path]::GetFullPath($argusSyntheticRoot)
    $argusExpectedParent=[IO.Path]::GetFullPath((Join-Path $argusRepo 'runtime\tests'))+[IO.Path]::DirectorySeparatorChar
    if (-not $argusResolved.StartsWith($argusExpectedParent,[StringComparison]::OrdinalIgnoreCase)) { throw 'Synthetic cleanup escaped the test directory.' }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $argusResolved -Recurse -Force
}
Write-Output ('PASS: {0} synthetic credential assertions; no GUI or actual private credential file accessed.' -f $argusPassed)
