# Phase 4D BOOT_2 branch. The same credential-delivered probe runs on every
# boot of the one QEMU process; a recorded BOOT_1 boot_id selects this branch.
# Records use a post_ prefix so they never overwrite BOOT_1 evidence.
if [[ -e /var/lib/slprobe-4d/boot1_id ]]; then
    collect post_boot_id cat /proc/sys/kernel/random/boot_id
    collect post_previous_boot_id cat /var/lib/slprobe-4d/boot1_id
    collect post_system_state timeout 300 systemctl is-system-running --wait
    collect post_failed_units systemctl --failed --no-legend --plain
    collect post_selinux getenforce
    collect post_platform_status /usr/bin/corectl status --json
    collect post_session_status busctl --system --auto-start=no --json=short call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
    # Platform/Session1 agreement: status reads are not atomic, so boot-time
    # facts (for example IPv6 autoconfiguration) may still be settling. Each
    # attempt reads Platform, Session1, then Platform again and records all
    # three payloads. Stop at the first attempt where all three are identical;
    # retry every 5 seconds for at most 120 seconds. The guest comparison only
    # controls the loop; the host evaluator re-checks the recorded payloads.
    post_read() {
        local output
        output=$("$@" 3>&- 2>&1; printf '\nSLPROBE_EXIT=%s' "$?")
        post_rc=${output##*$'\n'SLPROBE_EXIT=}
        post_out=${output%$'\n'SLPROBE_EXIT=*}
    }
    post_emit() {
        printf '%s\t%s\t' "$1" "$2" >&3
        printf '%s' "$3" | base64 --wrap=0 >&3
        printf '\n' >&3
    }
    post_attempt=0
    post_converged=
    post_started=$SECONDS
    while :; do
        post_attempt=$((post_attempt + 1))
        post_read /usr/bin/corectl status --json
        a_rc=$post_rc a_out=$post_out
        post_read busctl --system --auto-start=no --json=short call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
        s_rc=$post_rc s_out=$post_out
        post_read /usr/bin/corectl status --json
        b_rc=$post_rc b_out=$post_out
        post_emit "post_agree_${post_attempt}_platform_a" "$a_rc" "$a_out"
        post_emit "post_agree_${post_attempt}_session" "$s_rc" "$s_out"
        post_emit "post_agree_${post_attempt}_platform_b" "$b_rc" "$b_out"
        if [[ $a_rc == 0 && $s_rc == 0 && $b_rc == 0 ]] && python3 -c '
import json, sys
a, s, b = (json.loads(value) for value in sys.argv[1:4])
envelope = s.get("type") == "s" and len(s.get("data", [])) == 1
sys.exit(0 if envelope and a == json.loads(s["data"][0]) == b else 1)' "$a_out" "$s_out" "$b_out" 3>&- 2>/dev/null; then
            post_converged=$post_attempt
            break
        fi
        (( SECONDS - post_started + 5 > 120 )) && break
        sleep 5
    done
    collect post_agree_attempts echo "$post_attempt"
    if [[ -n $post_converged ]]; then
        collect post_agree_converged echo "$post_converged"
    fi
    printf 'post_complete\t0\tZG9uZQ==\n' >&3
    echo 'CoreOS boot probe: post-reboot evidence collection complete'
    exit 0
fi
