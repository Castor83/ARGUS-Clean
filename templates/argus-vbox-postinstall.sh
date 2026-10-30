#!/bin/sh
# Fixed setup code: install a local read-only baseline report, no guest-control channel.
set -eu
export LC_ALL=C
[ "${1:-}" = '--direct' ] || exit 40
[ "$(id -u)" = '0' ] || exit 41
install -d -m 0755 /usr/local/libexec
cat > /usr/local/libexec/argus-baseline-report <<'ARGUS_REPORT'
#!/bin/sh
set -u
export LC_ALL=C
argus_ok=1
argus_report=/var/log/argus-baseline.txt
{
    printf 'ARGUS_BASELINE_BEGIN\n'
    printf 'UTC=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
    printf 'ROOT_SOURCE=%s\n' "$(findmnt -n -o SOURCE /)"
    . /etc/os-release
    printf 'OS=%s VERSION=%s\n' "$ID" "$VERSION_ID"
    [ "$ID:$VERSION_ID" = 'ubuntu:24.04' ] || argus_ok=0
    argus_python=$(python3 --version 2>&1) || argus_python=MISSING
    printf 'PYTHON=%s\n' "$argus_python"
    case "$argus_python" in 'Python 3.12.'*) ;; *) argus_ok=0 ;; esac
    printf 'MEM_TOTAL_KIB=%s\n' "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    argus_id=$(id argus 2>/dev/null) || argus_id=MISSING
    printf 'WORKER_ID=%s\n' "$argus_id"
    argus_groups=$(id -nG argus 2>/dev/null) || argus_groups=MISSING
    printf 'WORKER_GROUPS=%s\n' "$argus_groups"
    [ "$argus_groups" = 'argus' ] || argus_ok=0
    argus_shell=$(getent passwd argus | cut -d: -f7)
    printf 'WORKER_SHELL=%s\n' "$argus_shell"
    [ "$argus_shell" = '/usr/sbin/nologin' ] || argus_ok=0
    if command -v runuser >/dev/null && command -v sudo >/dev/null; then
        if runuser -u argus -- sudo -n true >/dev/null 2>&1; then
            printf 'WORKER_SUDO=FAIL_ALLOWED\n'; argus_ok=0
        else
            printf 'WORKER_SUDO=DENIED\n'
        fi
    else
        printf 'WORKER_SUDO=FAIL_TEST_TOOL_MISSING\n'; argus_ok=0
    fi
    argus_root_status=$(passwd -S root 2>/dev/null | awk '{print $2}')
    printf 'ROOT_PASSWORD_STATUS=%s\n' "$argus_root_status"
    [ "$argus_root_status" = 'L' ] || argus_ok=0
    argus_interfaces=$(ls /sys/class/net | paste -sd, -)
    printf 'NETWORK_INTERFACES=%s\n' "$argus_interfaces"
    [ "$argus_interfaces" = 'lo' ] || argus_ok=0
    if argus_failed_list=$(systemctl --failed --no-legend --plain --no-pager 2>/dev/null); then
        argus_failed=$(printf '%s\n' "$argus_failed_list" | awk 'NF {n++} END {print n+0}')
    else
        argus_failed=QUERY_FAILED
    fi
    printf 'FAILED_UNITS=%s\n' "$argus_failed"
    [ "$argus_failed" = '0' ] || argus_ok=0
    argus_ga=absent
    for argus_unit in vboxadd.service vboxadd-service.service virtualbox-guest-utils.service; do
        argus_state=$(systemctl show "$argus_unit" -p LoadState --value 2>/dev/null || true)
        [ "$argus_state" = 'not-found' ] || argus_ga=present_or_unknown
    done
    command -v VBoxService >/dev/null 2>&1 && argus_ga=present_or_unknown
    printf 'GUEST_ADDITIONS_SERVICES=%s\n' "$argus_ga"
    [ "$argus_ga" = 'absent' ] || argus_ok=0
    if [ "$argus_ok" = '1' ]; then printf 'BASELINE=PASS\n'; else printf 'BASELINE=FAIL\n'; fi
    printf 'ARGUS_BASELINE_END\n'
} > "$argus_report" 2>&1
# VGA only. No network, serial, shared folder, guest property or guest-control output.
printf '\033[2J\033[H' > /dev/tty1
cat "$argus_report" > /dev/tty1
[ "$argus_ok" = '1' ]
ARGUS_REPORT
chmod 0755 /usr/local/libexec/argus-baseline-report
cat > /etc/systemd/system/argus-baseline.service <<'ARGUS_UNIT'
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
ARGUS_UNIT
chmod 0644 /etc/systemd/system/argus-baseline.service
# Enable for normal boots only. Do not start a cloud-final-dependent unit here.
systemctl enable argus-baseline.service
