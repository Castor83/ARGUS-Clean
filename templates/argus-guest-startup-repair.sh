#!/bin/sh
# Fixed guest-only ordering repair. No network policy, credentials, or host changes.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
argus_unit=/etc/systemd/system/argus-baseline.service
argus_stage=/etc/systemd/system/argus-baseline.service.argus-ordering-new
argus_old_link=/etc/systemd/system/multi-user.target.wants/argus-baseline.service
argus_new_link=/etc/systemd/system/cloud-init.target.wants/argus-baseline.service
argus_backup_parent=/var/lib/argus
argus_backup=/var/lib/argus/startup-repair-ordering-01

argus_fail() {
    printf 'ARGUS_ORDERING_STATUS=REFUSED\nARGUS_REASON=%s\n' "$1" >&2
    return 70
}
argus_require_root() {
    [ "$(id -u)" = 0 ] || { argus_fail ROOT_REQUIRED; return 70; }
}
argus_require_tools() {
    for argus_tool in sha256sum awk stat readlink dirname cat mkdir cp chmod mv rm timeout systemctl; do
        command -v "$argus_tool" >/dev/null 2>&1 || { argus_fail REQUIRED_TOOL_MISSING; return 70; }
    done
}
argus_require_owned() {
    [ ! -L "$1" ] || { argus_fail UNEXPECTED_SYMLINK; return 70; }
    case "$3" in
        file) [ -f "$1" ] || { argus_fail UNIT_NOT_REGULAR; return 70; };;
        directory) [ -d "$1" ] || { argus_fail BACKUP_PARENT_NOT_DIRECTORY; return 70; };;
        *) argus_fail INVALID_INTERNAL_TYPE; return 70;;
    esac
    [ "$(stat -c '%u:%g:%a' -- "$1")" = "0:0:$2" ] || { argus_fail UNEXPECTED_OWNERSHIP_OR_MODE; return 70; }
}
argus_classify_unit() {
    [ -f "$1" ] && [ ! -L "$1" ] || { argus_fail UNIT_NOT_REGULAR; return 70; }
    argus_hash=$(sha256sum -- "$1" | awk '{print $1}')
    case "$argus_hash" in
        886cdb8056cf988f33d8a903015257b256a8db1154c6db3ec9e5be363fafcd6e) printf 'old\n';;
        addf7a1737080b01587ac9342e90914edef71c21c9786204cca1d34133b6384c) printf 'corrected\n';;
        *) argus_fail UNIT_BYTES_NOT_APPROVED; return 70;;
    esac
}
argus_validate_enable_target() {
    case "$1" in
        "$argus_unit"|../argus-baseline.service) ;;
        *) argus_fail UNEXPECTED_ENABLE_LINK_TARGET; return 70;;
    esac
}
argus_read_enable_target() { readlink -- "$1"; }
argus_link_state() {
    if [ -L "$1" ]; then
        argus_validate_enable_target "$(argus_read_enable_target "$1")" || return 70
        [ "$(stat -c '%u:%g' -- "$1")" = '0:0' ] || { argus_fail UNEXPECTED_LINK_OWNER; return 70; }
        printf 'approved\n'
    elif [ -e "$1" ]; then
        argus_fail ENABLE_LINK_IS_NOT_SYMLINK; return 70
    else
        printf 'absent\n'
    fi
}
argus_check_context() {
    argus_require_owned "$(dirname "$argus_unit")" 755 directory || return 70
    for argus_link in "$argus_old_link" "$argus_new_link"; do
        argus_link_parent=$(dirname "$argus_link")
        if [ -e "$argus_link_parent" ] || [ -L "$argus_link_parent" ]; then
            argus_require_owned "$argus_link_parent" 755 directory || return 70
        fi
    done
    argus_require_owned "$argus_unit" 644 file || return 70
    argus_unit_class=$(argus_classify_unit "$argus_unit") || return 70
    argus_old_state=$(argus_link_state "$argus_old_link") || return 70
    argus_new_state=$(argus_link_state "$argus_new_link") || return 70
}
argus_systemctl() { timeout 15s systemctl "$@"; }
argus_print_diagnosis() {
    printf 'ARGUS_ORDERING_DIAG_BEGIN\nUNIT_CONTRACT=%s\nOLD_ENABLE_LINK=%s\nNEW_ENABLE_LINK=%s\n' "$argus_unit_class" "$argus_old_state" "$argus_new_state"
    for argus_diagnostic_unit in argus-baseline.service systemd-networkd-wait-online.service; do
        argus_state=$(argus_systemctl show --property=ActiveState --value "$argus_diagnostic_unit" 2>/dev/null) || argus_state=query_failed
        case "$argus_state" in active|inactive|failed|activating|deactivating|reloading|maintenance) ;; *) argus_state=query_failed;; esac
        printf '%s_ACTIVE=%s\n' "$argus_diagnostic_unit" "$argus_state"
    done
    printf 'ARGUS_NETWORK_POLICY=UNCHANGED\nARGUS_ORDERING_DIAG_END\n'
}
argus_emit_correct_unit() {
    cat <<'ARGUS_CORRECT_UNIT'
[Unit]
Description=ARGUS fixed local baseline report
After=cloud-final.service getty@tty1.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/argus-baseline-report
RemainAfterExit=yes
TimeoutStartSec=30

[Install]
# cloud-final is after multi-user.target; do not order this report before that target.
WantedBy=cloud-init.target
ARGUS_CORRECT_UNIT
}
argus_main() {
    [ "$#" -le 1 ] || { argus_fail UNAPPROVED_ARGUMENTS; return 70; }
    argus_mode=${1:---diagnose}
    case "$argus_mode" in --diagnose|--apply) ;; *) argus_fail UNAPPROVED_MODE; return 70;; esac
    argus_require_root || return 70
    argus_require_tools || return 70
    argus_check_context || return 70
    if [ "$argus_mode" = --diagnose ]; then argus_print_diagnosis; return 0; fi
    if [ "$argus_unit_class:$argus_old_state:$argus_new_state" = corrected:absent:approved ]; then
        printf 'ARGUS_ORDERING_STATUS=ALREADY_CORRECT\nARGUS_NETWORK_POLICY=UNCHANGED\n'
        return 0
    fi
    [ ! -e "$argus_stage" ] && [ ! -L "$argus_stage" ] || { argus_fail STAGING_FILE_EXISTS; return 70; }
    [ ! -e "$argus_backup" ] && [ ! -L "$argus_backup" ] || { argus_fail BACKUP_EXISTS_NO_AUTOMATIC_REPEAT; return 70; }
    if [ ! -e "$argus_backup_parent" ] && [ ! -L "$argus_backup_parent" ]; then
        argus_require_owned "$(dirname "$argus_backup_parent")" 755 directory || return 70
        mkdir -m 0700 -- "$argus_backup_parent" || { argus_fail BACKUP_PARENT_CREATE_FAILED; return 70; }
    fi
    argus_require_owned "$argus_backup_parent" 700 directory || return 70
    mkdir -m 0700 -- "$argus_backup" || { argus_fail BACKUP_CREATE_FAILED; return 70; }
    argus_require_owned "$argus_backup" 700 directory || return 70
    cp -p -- "$argus_unit" "$argus_backup/argus-baseline.service.before" || { argus_fail UNIT_BACKUP_FAILED; return 70; }
    argus_old_target=absent; argus_new_target=absent
    if [ "$argus_old_state" = approved ]; then argus_old_target=$(argus_read_enable_target "$argus_old_link") || return 70; fi
    if [ "$argus_new_state" = approved ]; then argus_new_target=$(argus_read_enable_target "$argus_new_link") || return 70; fi
    (umask 077; set -C; printf 'UNIT_CONTRACT=%s\nOLD_ENABLE_LINK=%s\nOLD_LINK_TARGET=%s\nNEW_ENABLE_LINK=%s\nNEW_LINK_TARGET=%s\n' "$argus_unit_class" "$argus_old_state" "$argus_old_target" "$argus_new_state" "$argus_new_target" > "$argus_backup/activation-before.txt") || { argus_fail ENABLE_FINDING_BACKUP_FAILED; return 70; }
    if [ "$argus_unit_class" = old ]; then
        (umask 077; set -C; argus_emit_correct_unit > "$argus_stage") || { argus_fail STAGING_WRITE_FAILED; return 70; }
        [ "$(argus_classify_unit "$argus_stage")" = corrected ] || { argus_fail STAGING_CONTRACT_FAILED; return 70; }
        chmod 0644 -- "$argus_stage" || { argus_fail STAGING_MODE_FAILED; return 70; }
        argus_check_context || return 70
        mv -T -- "$argus_stage" "$argus_unit" || { argus_fail UNIT_REPLACE_FAILED; return 70; }
    fi
    argus_old_state=$(argus_link_state "$argus_old_link") || return 70
    if [ "$argus_old_state" = approved ]; then rm -- "$argus_old_link" || { argus_fail OLD_ENABLE_LINK_REMOVE_FAILED; return 70; }; fi
    argus_systemctl daemon-reload >/dev/null 2>&1 || { argus_fail DAEMON_RELOAD_FAILED; return 70; }
    argus_systemctl enable argus-baseline.service >/dev/null 2>&1 || { argus_fail ENABLE_FAILED; return 70; }
    argus_check_context || return 70
    [ "$argus_unit_class:$argus_old_state:$argus_new_state" = corrected:absent:approved ] || { argus_fail FINAL_CONTRACT_FAILED; return 70; }
    printf 'ARGUS_ORDERING_STATUS=CORRECTED_PENDING_BOOT\nARGUS_NETWORK_POLICY=UNCHANGED\nARGUS_BASELINE_ACCEPTANCE=NOT_RUN\n'
}
# ARGUS_MAIN_ENTRY
argus_main "$@"
