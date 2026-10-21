# Appended to guest-probe.sh for the 0.0.3.1 console/audit diagnosis only.
collect diag_bootc_version bootc --version
collect diag_kernel_printk cat /proc/sys/kernel/printk
collect diag_audit_status auditctl -s
collect diag_console_units systemctl show sl-console@tty1.service sl-console@ttyS0.service --property=Id,ActiveState,SubState,TTYPath,StandardInput,StandardOutput,StandardError
collect diag_console_processes ps --no-headers -o pid,user,tty,label,args -C sl-console
collect diag_journald_config systemd-analyze cat-config systemd/journald.conf
collect diag_auditd_config sh -c 'grep -Ev "^[[:space:]]*(#|$)" /etc/audit/auditd.conf'

# Model repeated appliance status refreshes without changing persistent state.
for i in 1 2 3 4 5; do
    collect "diag_session_status_$i" busctl --system call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
    sleep 1
done
sleep 2
collect diag_kernel_audit journalctl --boot --no-pager --output=short-monotonic --dmesg --grep='audit:|avc:|SELINUX_ERR'
collect diag_audit_events journalctl --boot --no-pager --output=short-monotonic _TRANSPORT=audit
