$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$helper = 'E:\ARGUS\scripts\Prepare-ArgusGuest.ps1'
if (-not (Test-Path -LiteralPath $helper)) { throw 'RED: guest preparation helper and VM guard do not exist yet.' }
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Preparation helper has parser errors.' }
foreach ($name in @('Assert-ArgusMachineInfo', 'Expand-ArgusGuestTemplate', 'Invoke-ArgusCapturedProcess', 'Assert-ArgusPrivateAcl', 'Ensure-ArgusPrivateDirectory', 'Write-ArgusNewUtf8File')) {
    $fn = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }.GetNewClosure(), $true)
    if ($null -eq $fn) { throw "Required guard function missing: $name" }
    Invoke-Expression $fn.Extent.Text
}
$validInfo = @'
name="ARGUS-Offline"
UUID="5ace2701-f69f-43de-a36c-0d2b2d530a1e"
VMState="poweroff"
cpus=2
memory=3072
clipboard="disabled"
clipboard_file_transfers="off"
draganddrop="disabled"
usb="off"
ehci="off"
xhci="off"
accelerate3d="off"
vrde="off"
nested-hw-virt="off"
recording_enabled="off"
nic1="none"
nic2="none"
nic3="none"
nic4="none"
nic5="none"
nic6="none"
nic7="none"
nic8="none"
uart1="off"
uart2="off"
uart3="off"
uart4="off"
'@
Assert-ArgusMachineInfo -MachineReadable $validInfo
foreach ($changed in @($validInfo.Replace('nic1="none"','nic1="nat"'), $validInfo.Replace('VMState="poweroff"','VMState="running"'), $validInfo.Replace('uart1="off"','uart1="0x03f8,4"'), $validInfo.Replace('cpus=2','cpus=4'), $validInfo.Replace('UUID="5ace2701-f69f-43de-a36c-0d2b2d530a1e"','UUID="other"'))) {
    $rejected = $false
    try { Assert-ArgusMachineInfo -MachineReadable $changed } catch { $rejected = $true }
    if (-not $rejected) { throw 'VM boundary guard accepted an unauthorized mutation.' }
}
$fakeHash = '$6$TestSalt$' + ('A' * 86)
$expanded = Expand-ArgusGuestTemplate -Template "password: '__ARGUS_SETUP_PASSWORD_SHA512__'" -PasswordHash $fakeHash
if ($expanded -ne "password: '$fakeHash'") { throw 'Hash insertion failed.' }
foreach ($bad in @('plaintext', '$6$quote''injection$' + ('A' * 86))) {
    $rejected = $false
    try { Expand-ArgusGuestTemplate -Template '__ARGUS_SETUP_PASSWORD_SHA512__' -PasswordHash $bad | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Credential template accepted an invalid hash.' }
}
$captured = Invoke-ArgusCapturedProcess -FilePath 'C:\Program Files\Git\usr\bin\openssl.exe' -Arguments @('passwd','-6','-salt','TestSalt','-stdin') -InputText 'synthetic-test-value'
if ($captured.ExitCode -ne 0 -or $captured.StandardOutput.Trim() -notmatch '^\$6\$TestSalt\$[./0-9A-Za-z]{86}$') { throw 'Captured child-process hash behavior failed.' }
$template = Get-Content -LiteralPath 'E:\ARGUS\templates\ubuntu-autoinstall-user-data.yaml.in' -Raw
foreach ($required in @('shutdown: poweroff','fallback: offline-install','update: false','install-server: false','argus-setup','/usr/sbin/nologin','__ARGUS_SETUP_PASSWORD_SHA512__')) {
    if (-not $template.Contains($required)) { throw "Guest contract item absent: $required" }
}
$postScript = Get-Content -LiteralPath 'E:\ARGUS\templates\argus-vbox-postinstall.sh' -Raw
if (-not $postScript.Contains('ARGUS_BASELINE_BEGIN') -or -not $postScript.Contains('After=cloud-final.service getty@tty1.service')) { throw 'Fixed VGA report or ordering absent.' }
$testDirectory = Join-Path 'E:\ARGUS\runtime' ('preparation-acl-test-' + [Guid]::NewGuid().ToString('N'))
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
Ensure-ArgusPrivateDirectory -Path $testDirectory -UserSid $sid
Ensure-ArgusPrivateDirectory -Path $testDirectory -UserSid $sid
$testFile = Join-Path $testDirectory 'synthetic-no-secret.txt'
Write-ArgusNewUtf8File -Path $testFile -Content 'synthetic-test-only'
Assert-ArgusPrivateAcl -Path $testFile -UserSid $sid -Directory $false
$duplicateRefused = $false
try { Write-ArgusNewUtf8File -Path $testFile -Content 'overwritten' } catch { $duplicateRefused = $true }
if (-not $duplicateRefused -or (Get-Content -LiteralPath $testFile -Raw) -cne 'synthetic-test-only') { throw 'Existing file was not preserved.' }
Write-Output 'PASS: valid VM accepted; five boundary mutations refused; invalid hashes refused; isolated child stdin/output worked; atomic ACL directory/file created; duplicate write refused; guest contract present.'
