# Synthetic shell fixtures only. Never accesses a guest, systemd, or private data.
#requires -Version 7.2
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$argusRepo=Split-Path $PSScriptRoot -Parent
$argusHelper=Join-Path $argusRepo 'templates\argus-guest-startup-repair.sh'
if(-not(Test-Path -LiteralPath $argusHelper)){throw 'RED: focused guest startup repair helper does not exist.'}
$argusFixture=Join-Path $argusRepo ('runtime\tests\startup-repair-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($argusFixture)
$argusTest=@'
#!/bin/bash
set -eu
source <(sed '/^# ARGUS_MAIN_ENTRY$/,$d' "$1")
test_root="$2"
passed=0
assert() { if ! "$@"; then printf 'FAIL: %s\n' "$*" >&2; exit 1; fi; passed=$((passed+1)); }
# Linux root ownership, symlink metadata, and systemd are mocked on Windows.
# Real sandbox unit bytes pass through the production hash and target validators.
argus_require_root() { :; }
argus_require_owned() { :; }
argus_require_tools() { :; }
mkdir() {
    local args=()
    while [ "$#" -gt 0 ]; do
        if [ "$1" = -m ]; then shift 2; else args+=("$1"); shift; fi
    done
    command mkdir "${args[@]}"
}
chmod() { :; }
cp() { if [ "$1" = -p ]; then shift; fi; command cp "$@"; }
argus_read_enable_target() { cat "$1"; }
argus_link_state() {
    if [ -f "$1" ]; then
        argus_validate_enable_target "$(cat "$1")" || return 70
        printf 'approved\n'
    else
        printf 'absent\n'
    fi
}
argus_systemctl() {
    printf '%s\n' "$*" >> "$test_root/systemctl-calls.txt"
    case "$1" in
        show) printf 'inactive\n';;
        daemon-reload) :;;
        enable) mkdir -p "$(dirname "$argus_new_link")"; printf '../argus-baseline.service\n' > "$argus_new_link";;
        *) return 90;;
    esac
}
fresh() {
    local case_dir="$test_root/$1"
    mkdir -p "$case_dir/etc/multi-user.target.wants" "$case_dir/etc/cloud-init.target.wants" "$case_dir/varlib"
    argus_unit="$case_dir/etc/argus-baseline.service"
    argus_stage="$argus_unit.argus-ordering-new"
    argus_old_link="$case_dir/etc/multi-user.target.wants/argus-baseline.service"
    argus_new_link="$case_dir/etc/cloud-init.target.wants/argus-baseline.service"
    argus_backup_parent="$case_dir/varlib/argus"
    argus_backup="$argus_backup_parent/startup-repair-ordering-01"
    argus_emit_correct_unit | sed '/^# cloud-final is after multi-user.target;/d;s/WantedBy=cloud-init.target/WantedBy=multi-user.target/' > "$argus_unit"
    printf '../argus-baseline.service\n' > "$argus_old_link"
}
fresh diagnose
before=$(sha256sum "$argus_unit")
assert test "$(argus_classify_unit "$argus_unit")" = old
argus_main --diagnose > "$test_root/diagnose-output.txt"
assert test "$before" = "$(sha256sum "$argus_unit")"
assert test -f "$argus_old_link"
assert test ! -e "$argus_backup_parent"
assert grep -q '^ARGUS_NETWORK_POLICY=UNCHANGED$' "$test_root/diagnose-output.txt"
fresh apply
argus_main --apply > "$test_root/apply-output.txt"
assert test "$(argus_classify_unit "$argus_unit")" = corrected
assert test ! -e "$argus_old_link"
assert test -f "$argus_new_link"
assert test "$(cat "$argus_new_link")" = ../argus-baseline.service
assert test "$(argus_classify_unit "$argus_backup/argus-baseline.service.before")" = old
assert test -f "$argus_backup/activation-before.txt"
assert grep -q '^OLD_LINK_TARGET=../argus-baseline.service$' "$argus_backup/activation-before.txt"
assert grep -q '^ARGUS_ORDERING_STATUS=CORRECTED_PENDING_BOOT$' "$test_root/apply-output.txt"
before=$(sha256sum "$argus_unit")
argus_main --apply > "$test_root/repeat-output.txt"
assert test "$before" = "$(sha256sum "$argus_unit")"
assert grep -q '^ARGUS_ORDERING_STATUS=ALREADY_CORRECT$' "$test_root/repeat-output.txt"
fresh changed_unit
printf '\nExecStart=/bin/false\n' >> "$argus_unit"
if argus_main --apply > "$test_root/rejected-unit.txt" 2>&1; then exit 1; fi
assert test ! -e "$argus_backup_parent"
assert test -f "$argus_old_link"
fresh foreign_link
rm -- "$argus_old_link"
printf '/unexpected-public-test-target\n' > "$argus_old_link"
if argus_main --apply > "$test_root/rejected-link.txt" 2>&1; then exit 1; fi
assert test ! -e "$argus_backup_parent"
assert test "$(cat "$argus_old_link")" = /unexpected-public-test-target
fresh existing_backup
mkdir -p "$argus_backup"
printf preserved > "$argus_backup/sentinel"
if argus_main --apply > "$test_root/rejected-backup.txt" 2>&1; then exit 1; fi
assert test "$(cat "$argus_backup/sentinel")" = preserved
assert test "$(argus_classify_unit "$argus_unit")" = old
if argus_main --unapproved-mode > "$test_root/rejected-mode.txt" 2>&1; then exit 1; fi
assert test "$(argus_classify_unit "$argus_unit")" = old
assert test "$(grep -c '^daemon-reload$' "$test_root/systemctl-calls.txt")" = 1
assert test "$(grep -c '^enable argus-baseline.service$' "$test_root/systemctl-calls.txt")" = 1
printf 'PASS: %s synthetic startup repair assertions; no guest or real systemd accessed.\n' "$passed"
'@
$argusDriver=Join-Path $argusFixture 'driver.sh'
[IO.File]::WriteAllText($argusDriver,$argusTest.Replace("`r`n","`n"),[Text.UTF8Encoding]::new($false))
& 'C:\Program Files\Git\bin\bash.exe' $argusDriver.Replace('\','/') $argusHelper.Replace('\','/') $argusFixture.Replace('\','/')
if($LASTEXITCODE-ne0){throw 'Synthetic guest startup repair regression failed.'}
