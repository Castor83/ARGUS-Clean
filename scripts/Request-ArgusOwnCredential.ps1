# Interactive pending credential only. No active credential is read or changed.
# Root launches this script with PowerShell 7 -STA after review.
#requires -Version 7.2
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ArgusOwnCredentialContract {
    return [pscustomobject]@{
        Account='argus-setup'; TimeoutMinutes=10
        PrivateDirectories=@('E:\ARGUS-Private','E:\ARGUS-Private\credentials')
        PendingPath='E:\ARGUS-Private\credentials\argus-vm-own-pending.xml'
        StatusPath='E:\ARGUS\runtime\logs\package-b-own-credential-dialog.json'
    }
}
function Test-ArgusOwnCredentialInput {
    param([AllowNull()][string]$Password,[AllowNull()][string]$Confirmation)
    return [bool]($Password -cmatch '\A[\x20-\x7E]{12,128}\z' -and
        [string]::Equals($Password,$Confirmation,[StringComparison]::Ordinal))
}
function Assert-ArgusPrivateAcl {
    param([string]$Path,[Security.Principal.SecurityIdentifier]$UserSid,[bool]$Directory)
    $argusItem=Get-Item -LiteralPath $Path -Force
    if (($argusItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $argusItem.PSIsContainer -ne $Directory) { throw 'Private path is not an ordinary file or directory.' }
    $argusAcl=Get-Acl -LiteralPath $Path
    $argusAllowed=@($UserSid.Value,'S-1-5-18')
    if ($argusAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $argusAllowed) { throw 'Private path has a different owner.' }
    if ($Directory -and -not $argusAcl.AreAccessRulesProtected) { throw 'Private directory inherits unreviewed access rules.' }
    foreach ($argusRule in $argusAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($argusRule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $argusRule.IdentityReference.Value -notin $argusAllowed) { throw 'Private path grants access to another identity.' }
    }
}
function Save-ArgusOwnPendingCredential {
    param([Management.Automation.PSCredential]$Credential)
    $argusContract=Get-ArgusOwnCredentialContract
    if ($null -eq $Credential -or $Credential.UserName -cne $argusContract.Account) { throw 'Unexpected pending credential account.' }
    $argusSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($argusDirectory in $argusContract.PrivateDirectories) { Assert-ArgusPrivateAcl -Path $argusDirectory -UserSid $argusSid -Directory $true }
    if (Test-Path -LiteralPath $argusContract.PendingPath) {
        Assert-ArgusPrivateAcl -Path $argusContract.PendingPath -UserSid $argusSid -Directory $false
        throw 'Pending credential already exists; preserve it.'
    }
    # Windows Export-Clixml encrypts the PSCredential SecureString using current-user DPAPI.
    # The checked private directory protects the file from its first write; no ACL is changed.
    Export-Clixml -InputObject $Credential -LiteralPath $argusContract.PendingPath -Encoding utf8 -NoClobber -ErrorAction Stop
    Assert-ArgusPrivateAcl -Path $argusContract.PendingPath -UserSid $argusSid -Directory $false
}
function New-ArgusOwnDialogStatus {
    param(
        [ValidateSet('shown','pending_saved','cancelled','expired','safe_failed')][string]$Status,
        [string]$StartedAtUtc
    )
    $argusContract=Get-ArgusOwnCredentialContract
    return [ordered]@{Status=$Status;StartedAtUtc=$StartedAtUtc;UpdatedAtUtc=[DateTime]::UtcNow.ToString('o');Path=$argusContract.PendingPath}
}
function Write-ArgusOwnDialogStatus {
    param($State,[switch]$Claim)
    $argusContract=Get-ArgusOwnCredentialContract
    $argusSafeJson=New-ArgusOwnDialogStatus -Status $State.Status -StartedAtUtc $State.StartedAtUtc | ConvertTo-Json
    $argusBytes=[Text.UTF8Encoding]::new($false).GetBytes($argusSafeJson)
    if ($Claim) {
        $argusStream=[IO.File]::Open($argusContract.StatusPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $argusStream.Write($argusBytes,0,$argusBytes.Length) } finally { $argusStream.Dispose() }
        $State.OwnsStatus=$true
    } else {
        if (-not $State.OwnsStatus) { throw 'No ownership of the safe dialog status file.' }
        [IO.File]::WriteAllText($argusContract.StatusPath,$argusSafeJson,[Text.UTF8Encoding]::new($false))
    }
}

$argusContract=Get-ArgusOwnCredentialContract
$argusState=[pscustomobject]@{Status='safe_failed';StartedAtUtc=[DateTime]::UtcNow.ToString('o');OwnsStatus=$false;DeadlineUtc=$null}
$argusDialog=$null; $argusTimer=$null; $argusPasswordBox=$null; $argusConfirmBox=$null
try {
    $argusRepo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    if (-not $IsWindows -or $argusRepo -ine 'E:\ARGUS' -or [Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) { throw 'Approved Windows repository and PowerShell STA are required.' }
    Set-Location -LiteralPath $argusRepo
    # Fail closed until the real Form.Shown event records 'shown'. Atomic claim prevents duplicate dialogs.
    Write-ArgusOwnDialogStatus -State $argusState -Claim
    $argusSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($argusDirectory in $argusContract.PrivateDirectories) { Assert-ArgusPrivateAcl -Path $argusDirectory -UserSid $argusSid -Directory $true }
    if (Test-Path -LiteralPath $argusContract.PendingPath) {
        Assert-ArgusPrivateAcl -Path $argusContract.PendingPath -UserSid $argusSid -Directory $false
        throw 'An existing pending credential must be preserved.'
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $argusDialog=[Windows.Forms.Form]::new()
    $argusDialog.Text='ARGUS: eigenes VM-Kennwort'
    $argusDialog.ClientSize=[Drawing.Size]::new(560,320)
    $argusDialog.FormBorderStyle=[Windows.Forms.FormBorderStyle]::FixedDialog
    $argusDialog.StartPosition=[Windows.Forms.FormStartPosition]::CenterScreen
    $argusDialog.MaximizeBox=$false; $argusDialog.MinimizeBox=$false; $argusDialog.TopMost=$true
    $argusInstruction=[Windows.Forms.Label]::new()
    $argusInstruction.SetBounds(16,12,528,76)
    $argusInstruction.Text="Konto: argus-setup (fest)`r`n12 bis 128 druckbare ASCII-Zeichen, einschließlich Leerzeichen.`r`nUS-Gasttastatur; keine Umlaute oder Zeilenumbrüche.`r`nNur verschlüsselt vormerken. Das VM-Kennwort bleibt unverändert."
    $argusFirstLabel=[Windows.Forms.Label]::new(); $argusFirstLabel.SetBounds(16,96,528,20); $argusFirstLabel.Text='Eigenes Kennwort'
    $argusPasswordBox=[Windows.Forms.TextBox]::new(); $argusPasswordBox.SetBounds(16,118,528,26)
    $argusPasswordBox.UseSystemPasswordChar=$true; $argusPasswordBox.MaxLength=129; $argusPasswordBox.TabIndex=0
    $argusSecondLabel=[Windows.Forms.Label]::new(); $argusSecondLabel.SetBounds(16,154,528,20); $argusSecondLabel.Text='Kennwort wiederholen'
    $argusConfirmBox=[Windows.Forms.TextBox]::new(); $argusConfirmBox.SetBounds(16,176,528,26)
    $argusConfirmBox.UseSystemPasswordChar=$true; $argusConfirmBox.MaxLength=129; $argusConfirmBox.TabIndex=1
    $argusNotice=[Windows.Forms.Label]::new(); $argusNotice.SetBounds(16,214,528,42)
    $argusNotice.Text='Dieser Dialog schließt nach 10 Minuten automatisch.'
    $argusSave=[Windows.Forms.Button]::new(); $argusSave.SetBounds(308,274,112,30); $argusSave.Text='Speichern'; $argusSave.TabIndex=2
    $argusCancel=[Windows.Forms.Button]::new(); $argusCancel.SetBounds(432,274,112,30); $argusCancel.Text='Abbrechen'; $argusCancel.TabIndex=3
    $argusCancel.DialogResult=[Windows.Forms.DialogResult]::Cancel
    $argusDialog.AcceptButton=$argusSave; $argusDialog.CancelButton=$argusCancel
    $argusDialog.Controls.AddRange([Windows.Forms.Control[]]@($argusInstruction,$argusFirstLabel,$argusPasswordBox,$argusSecondLabel,$argusConfirmBox,$argusNotice,$argusSave,$argusCancel))
    $argusTimer=[Windows.Forms.Timer]::new(); $argusTimer.Interval=500
    $argusDialog.Add_Shown({
        try {
            $argusState.Status='shown'; $argusState.DeadlineUtc=[DateTime]::UtcNow.AddMinutes($argusContract.TimeoutMinutes)
            Write-ArgusOwnDialogStatus -State $argusState
            $argusTimer.Start(); $null=$argusPasswordBox.Focus()
        } catch {
            $argusState.Status='safe_failed'
            try { Write-ArgusOwnDialogStatus -State $argusState } catch {}
            $argusDialog.Close()
        }
    })
    $argusSave.Add_Click({
        $argusSecure=$null; $argusPendingCredential=$null
        try {
            if ($null -eq $argusState.DeadlineUtc -or [DateTime]::UtcNow -ge $argusState.DeadlineUtc) {
                $argusState.Status='expired'; Write-ArgusOwnDialogStatus -State $argusState; $argusDialog.Close(); return
            }
            if (-not (Test-ArgusOwnCredentialInput $argusPasswordBox.Text $argusConfirmBox.Text)) {
                $argusNotice.Text='Bitte 12 bis 128 druckbare ASCII-Zeichen zweimal identisch eingeben.'
                return
            }
            $argusSecure=ConvertTo-SecureString -String $argusPasswordBox.Text -AsPlainText -Force
            $argusSecure.MakeReadOnly()
            $argusPendingCredential=[Management.Automation.PSCredential]::new($argusContract.Account,$argusSecure)
            Save-ArgusOwnPendingCredential -Credential $argusPendingCredential
            $argusState.Status='pending_saved'; Write-ArgusOwnDialogStatus -State $argusState
            $argusDialog.Close()
        } catch {
            $argusState.Status='safe_failed'
            try { Write-ArgusOwnDialogStatus -State $argusState } catch {}
            $argusDialog.Close()
        } finally {
            if ($null -ne $argusSecure) { $argusSecure.Dispose() }
            $argusPendingCredential=$null; $argusSecure=$null
        }
    })
    $argusTimer.Add_Tick({
        if ($null -ne $argusState.DeadlineUtc -and [DateTime]::UtcNow -ge $argusState.DeadlineUtc) {
            try { $argusState.Status='expired'; Write-ArgusOwnDialogStatus -State $argusState }
            catch { $argusState.Status='safe_failed'; try { Write-ArgusOwnDialogStatus -State $argusState } catch {} }
            finally { $argusDialog.Close() }
        }
    })
    $argusDialog.Add_FormClosing({
        $argusTimer.Stop()
        try {
            if ($argusState.Status -eq 'shown') { $argusState.Status='cancelled'; Write-ArgusOwnDialogStatus -State $argusState }
        } catch { $argusState.Status='safe_failed'; try { Write-ArgusOwnDialogStatus -State $argusState } catch {} }
        finally { $argusPasswordBox.Clear(); $argusConfirmBox.Clear() }
    })
    $null=$argusDialog.ShowDialog()
} catch {
    $argusState.Status='safe_failed'
    if ($argusState.OwnsStatus) { try { Write-ArgusOwnDialogStatus -State $argusState } catch {} }
    # Never emit exception details, UI input, credential objects, or derived values.
} finally {
    foreach ($argusBox in @($argusPasswordBox,$argusConfirmBox)) { if ($null -ne $argusBox) { try { $argusBox.Clear() } catch {} } }
    if ($null -ne $argusTimer) { $argusTimer.Stop(); $argusTimer.Dispose() }
    if ($null -ne $argusDialog) { $argusDialog.Dispose() }
    $argusPasswordBox=$null; $argusConfirmBox=$null
}
if ($argusState.Status -eq 'safe_failed') { exit 20 }
exit 0
