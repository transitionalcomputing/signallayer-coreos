# Phase 5E extension. This credential is never installed in the image. It
# exercises the shipped fixed APIs in one disposable boot and emits only
# boolean/public evidence; generated credentials never leave the guest.
collect phase5e_release grep -E '^(VERSION|PLATFORM_API_VERSION)=' /usr/lib/signallayer/release
collect phase5e_units systemctl show sl-authd.service sl-platformd.service sl-sessiond.service sl-console@tty1.service sl-console@ttyS0.service --property=Id,ActiveState,SubState,User,ExecStart,CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges,TTYPath,StandardInput,Restart
collect phase5e_console_processes ps --no-headers -o pid,user:20,tty,label,args -C sl-console
collect phase5e_console_masks sh -c 'for u in getty@.service serial-getty@.service console-getty.service; do printf "%s=" "$u"; systemctl is-enabled "$u"; done'
collect phase5e_bus_platform cat /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf
collect phase5e_bus_auth cat /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf
collect phase5e_bus_session cat /usr/share/dbus-1/system.d/org.signallayer.Session1.conf
collect phase5e_console_unit cat /usr/lib/systemd/system/sl-console@.service
collect phase5e_remoted_unit cat /usr/lib/systemd/system/sl-remoted.service
collect phase5e_modules semodule --list-modules=full
collect phase5e_loaded_policy sh -c 'gzip -c /sys/fs/selinux/policy | base64 --wrap=0'
collect phase5e_loaded_policy_hash sha256sum /sys/fs/selinux/policy

cat >/run/phase5e-runtime.py <<'PY'
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time

PLATFORM = ("org.signallayer.Platform1", "/org/signallayer/Platform1", "org.signallayer.Platform1")
SESSION = ("org.signallayer.Session1", "/org/signallayer/Session1", "org.signallayer.Session1")
AUTH = ("org.signallayer.Auth1", "/org/signallayer/Auth1", "org.signallayer.Auth1")
STATE = Path("/var/lib/sl-remote-management")
LISTENING = Path("/run/sl-remoted/listening")
results = {}

def command(argv, check=True, timeout=45):
    done = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)
    if check and done.returncode:
        raise RuntimeError(f"command failed ({done.returncode}): {argv[0]}: {done.stderr.strip()}")
    return done

def systemctl(*args, check=True):
    return command(["systemctl", *args], check=check, timeout=60)

def call(peer, member, signature=None, values=(), user=None, check=True):
    destination, path, interface = peer
    argv = ["busctl", "--system", "--auto-start=no", "--json=short", "call",
            destination, path, interface, member]
    if signature is not None:
        argv.extend([signature, *values])
    if user:
        argv = ["runuser", "-u", user, "--", *argv]
    done = command(argv, check=check)
    if done.returncode:
        return done
    return json.loads(done.stdout) if done.stdout.strip() else {"type": "", "data": []}

def data(peer, member, signature=None, values=(), user=None):
    return call(peer, member, signature, values, user)["data"]

def wait_for(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False

def session_status():
    return json.loads(data(SESSION, "GetPlatformStatus")[0])

def enrollment():
    value = data(PLATFORM, "GetRemoteManagementEnrollment", user="sl-console")
    return {"url": value[0], "fingerprint": value[1], "code": value[2], "expires": value[3]}

def endpoint():
    value = enrollment()["url"]
    if not value.startswith("https://") or not value.endswith("/"):
        raise RuntimeError("invalid enrollment URL")
    return value[8:-1]

def request(method, path, body=None, cookie=None, origin=True, host=None):
    target = endpoint()
    address = target.rsplit(":", 1)[0].strip("[]")
    headers = {"Host": host or target}
    if origin:
        headers["Origin"] = "https://" + target
    payload = None
    if body is not None:
        payload = json.dumps(body, separators=(",", ":"))
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    connection = http.client.HTTPSConnection(address, 8443, timeout=10,
        context=ssl._create_unverified_context())
    connection.request(method, path, body=payload, headers=headers)
    response = connection.getresponse()
    content = response.read()
    found = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return response.status, found, content

def pair_and_confirm(password):
    info = enrollment()
    status, _, body = request("POST", "/api/v1/pair",
                              {"pairing_code": info["code"], "password": password})
    if status != 200:
        raise RuntimeError(f"pair returned {status}")
    recovery = json.loads(body)["recovery_key"]
    status, _, _ = request("POST", "/api/v1/confirm", {"recovery_key": recovery})
    if status != 204:
        raise RuntimeError(f"confirm returned {status}")
    return recovery

def login(password):
    return request("POST", "/api/v1/login", {"password": password})

def console_call(peer, member, signature=None, values=(), check=True):
    return call(peer, member, signature, values, user="sl-console", check=check)

try:
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    initial = session_status()
    results["initial_disabled_unenrolled"] = initial["remote_management"] == {
        "enabled": False, "listening": False, "enrolled": False}

    # The console must survive a failed wanted boot-reset worker and backend
    # loss; the fixture lives only in /run and is removed before workflows.
    dropin = Path("/run/systemd/system/sl-rm-boot-reset.service.d/95-phase5e-fail.conf")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/false\n")
    systemctl("daemon-reload")
    systemctl("stop", "sl-console@tty1.service", "sl-console@ttyS0.service", check=False)
    systemctl("reset-failed", "sl-rm-boot-reset.service", check=False)
    systemctl("start", "sl-console@tty1.service", "sl-console@ttyS0.service", check=False)
    results["console_survives_failed_boot_reset"] = all(
        systemctl("is-active", unit, check=False).stdout.strip() == "active"
        for unit in ("sl-console@tty1.service", "sl-console@ttyS0.service"))
    dropin.unlink()
    systemctl("daemon-reload")
    systemctl("reset-failed", "sl-rm-boot-reset.service", check=False)

    systemctl("stop", "sl-platformd.service")
    results["console_survives_platform_loss"] = all(
        systemctl("is-active", unit, check=False).stdout.strip() == "active"
        for unit in ("sl-console@tty1.service", "sl-console@ttyS0.service"))
    systemctl("start", "sl-platformd.service")
    systemctl("stop", "sl-authd.service")
    results["console_survives_auth_loss"] = all(
        systemctl("is-active", unit, check=False).stdout.strip() == "active"
        for unit in ("sl-console@tty1.service", "sl-console@ttyS0.service"))
    systemctl("start", "sl-authd.service")
    systemctl("restart", "sl-sessiond.service", "sl-platformd.service")

    old_pid = int(systemctl("show", "--value", "--property=MainPID",
                            "sl-console@tty1.service").stdout)
    os.kill(old_pid, 9)
    results["console_restarts_after_crash"] = wait_for(lambda: (
        int(systemctl("show", "--value", "--property=MainPID",
                      "sl-console@tty1.service").stdout or 0) not in (0, old_pid)))

    # Exact broker caller boundary for the console identity.
    denied = []
    for member in ("StartUpdate", "StartRollback", "StartReboot"):
        denied.append(console_call(PLATFORM, member, check=False).returncode != 0)
    denied.append(console_call(AUTH, "ResetEnrollment", check=False).returncode != 0)
    denied.append(console_call(AUTH, "ConsumePairing", "ss", ("00000000", "invalid"),
                               check=False).returncode != 0)
    systemd_denied = command(["runuser", "-u", "sl-console", "--", "busctl", "--system",
        "--auto-start=no", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartUnit", "ss", "sl-update.service", "replace"],
        check=False)
    denied.append(systemd_denied.returncode != 0)
    results["console_mutation_boundaries_denied"] = all(denied)

    # Unenrolled local-console identity may enable and expose pairing.
    console_call(PLATFORM, "EnableRemoteManagement")
    results["enable_without_enrollment"] = wait_for(LISTENING.exists) and bool(enrollment()["code"])
    first = enrollment()
    address = first["url"][8:-1].rsplit(":", 1)[0].strip("[]")

    status, headers, body = request("GET", "/")
    results["bundled_https_console"] = status == 200 and b"SignalLayer" in body and all(
        key in headers for key in ("content-security-policy", "cache-control",
                                   "x-content-type-options", "x-frame-options"))
    results["host_boundary"] = request("GET", "/", host="wrong.invalid:8443")[0] == 421
    results["origin_boundary"] = request("POST", "/api/v1/login",
        {"password": "irrelevant"}, origin=False)[0] == 403
    results["unauthenticated_status_denied"] = request("GET", "/api/v1/status")[0] == 401
    results["remote_mutation_routes_absent"] = all(
        request("POST", path, {}, origin=True)[0] == 404
        for path in ("/api/v1/update", "/api/v1/rollback", "/api/v1/reboot",
                     "/api/v1/enable", "/api/v1/disable", "/api/v1/reenroll"))

    password1 = secrets.token_urlsafe(24)
    recovery1 = pair_and_confirm(password1)
    results["pairing_enrolls_operator"] = session_status()["remote_management"]["enrolled"]
    results["bad_password_denied"] = login("definitely-wrong-password")[0] == 401
    status, headers, _ = login(password1)
    cookie = headers.get("set-cookie", "")
    cookie_value = cookie.split(";", 1)[0]
    results["secure_session_cookie"] = status == 204 and all(token in cookie for token in (
        "__Host-sl_session=", "Secure", "HttpOnly", "SameSite=Strict", "Path=/"))
    status, _, remote_body = request("GET", "/api/v1/status", cookie=cookie_value)
    direct = session_status()
    results["remote_session_status_agrees"] = status == 200 and json.loads(remote_body) == direct
    results["remote_status_read_only"] = direct["schema_version"] == "0.4" and set(
        direct["remote_management"]) == {"enabled", "listening", "enrolled"}
    results["logout_invalidates_session"] = (
        request("POST", "/api/v1/logout", cookie=cookie_value)[0] == 204 and
        request("GET", "/api/v1/status", cookie=cookie_value)[0] == 401)

    # Disabled reenrollment rotates identity without creating pairing; the
    # next explicit enable creates a fresh pairing.
    console_call(PLATFORM, "DisableRemoteManagement")
    results["disable_withdraws_listener"] = wait_for(lambda: not LISTENING.exists())
    console_call(PLATFORM, "ReenrollRemoteManagement")
    disabled_reenroll = enrollment()
    results["disabled_reenroll_rotates_without_pairing"] = (
        disabled_reenroll["fingerprint"] != first["fingerprint"] and
        disabled_reenroll["code"] == "" and not session_status()["remote_management"]["enabled"])
    console_call(PLATFORM, "EnableRemoteManagement")
    results["reenable_creates_pairing"] = wait_for(LISTENING.exists) and bool(enrollment()["code"])
    password2 = secrets.token_urlsafe(24)
    recovery2 = pair_and_confirm(password2)

    # Console-only recovery changes the credential and does not create a web
    # mutation path.
    password3 = secrets.token_urlsafe(24)
    console_call(AUTH, "RecoverPassword", "ss", (recovery2, password3))
    results["console_recovery_changes_password"] = (
        login(password2)[0] == 401 and login(password3)[0] == 204)

    # ResetIncomplete is a distinct failure and Reenroll is its repair path.
    pending = STATE / "reset-pending"
    pending.touch(exist_ok=True)
    failed_enable = console_call(PLATFORM, "EnableRemoteManagement", check=False)
    results["reset_incomplete_blocks_enable"] = (
        failed_enable.returncode != 0 and "reset" in failed_enable.stderr.lower())
    before_repair = enrollment()["fingerprint"]
    console_call(PLATFORM, "ReenrollRemoteManagement")
    results["reenroll_repairs_reset_incomplete"] = (
        not pending.exists() and enrollment()["fingerprint"] != before_repair)

    # Run the shipped boot-reset worker once by clearing only its boot-argument
    # condition in a disposable /run drop-in. RemainAfterExit must make a
    # second start a no-op in the same boot.
    systemctl("stop", "sl-remoted.service", check=False)
    boot_dropin = Path("/run/systemd/system/sl-rm-boot-reset.service.d/95-phase5e-run.conf")
    boot_dropin.parent.mkdir(parents=True, exist_ok=True)
    boot_dropin.write_text("[Unit]\nConditionKernelCommandLine=\n")
    systemctl("daemon-reload")
    systemctl("reset-failed", "sl-rm-boot-reset.service", check=False)
    systemctl("start", "sl-rm-boot-reset.service")
    first_start = systemctl("show", "--value", "--property=ExecMainStartTimestampMonotonic",
                            "sl-rm-boot-reset.service").stdout.strip()
    systemctl("start", "sl-rm-boot-reset.service")
    second_start = systemctl("show", "--value", "--property=ExecMainStartTimestampMonotonic",
                             "sl-rm-boot-reset.service").stdout.strip()
    results["boot_reset_runs_once_per_boot"] = (
        first_start and first_start == second_start and
        systemctl("is-active", "sl-rm-boot-reset.service", check=False).stdout.strip() == "active" and
        not data(AUTH, "GetEnrollmentState")[0])
    boot_dropin.unlink()
    systemctl("daemon-reload")
    systemctl("reset-failed", "sl-rm-boot-reset.service", check=False)
    console_call(PLATFORM, "ReenrollRemoteManagement")
    results["boot_reset_recovery_reenrolls"] = bool(enrollment()["code"])

    # A source outside the primary prefix is dropped before TLS.
    command(["ip", "address", "add", "192.0.2.5/32", "dev", "lo"])
    offlink_refused = False
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(3)
    try:
        raw.bind(("192.0.2.5", 0))
        raw.connect((address, 8443))
        ssl._create_unverified_context().wrap_socket(raw, server_hostname=address)
    except Exception:
        offlink_refused = True
    finally:
        raw.close()
        command(["ip", "address", "del", "192.0.2.5/32", "dev", "lo"], check=False)
    results["offlink_source_refused"] = offlink_refused

    # Kernel invalidation withdraws listeners before a fresh Session1 view is
    # published. A temporary dummy link is only a netlink notification source.
    command(["ip", "link", "add", "slprobe5e0", "type", "dummy"])
    withdrew = wait_for(lambda: not LISTENING.exists(), 2)
    command(["ip", "link", "del", "slprobe5e0"], check=False)
    rebound = wait_for(LISTENING.exists, 30)
    results["network_invalidation_fail_closed"] = withdrew and rebound

    # With Session1 unavailable, a fresh remoted process cannot publish a
    # listener; restoring Session1 restores it without widening the bind.
    systemctl("stop", "sl-remoted.service", check=False)
    systemctl("stop", "sl-sessiond.service")
    systemctl("start", "sl-remoted.service", check=False)
    time.sleep(1)
    results["session_loss_has_no_listener"] = not LISTENING.exists()
    systemctl("start", "sl-sessiond.service")
    systemctl("restart", "sl-remoted.service")
    results["session_restore_rebinds"] = wait_for(LISTENING.exists, 30)

    final = session_status()
    results["cross_service_final_state"] = final["remote_management"] == {
        "enabled": True, "listening": True, "enrolled": False}
    results["boot_id_unchanged"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip() == boot_id
    results["selinux_enforcing"] = command(["getenforce"]).stdout.strip() == "Enforcing"
    results["no_failed_units"] = not systemctl("--failed", "--no-legend", "--plain",
                                               check=False).stdout.strip()
    print(json.dumps({"checks": results}, sort_keys=True))
except Exception as error:
    print(json.dumps({"checks": results, "error": str(error)}, sort_keys=True))
    raise
PY

collect phase5e_runtime /usr/bin/python3 /run/phase5e-runtime.py
rm -f /run/phase5e-runtime.py
collect phase5e_final_units systemctl --failed --no-legend --plain
collect phase5e_final_state systemctl is-system-running
collect phase5e_final_selinux getenforce
collect phase5e_final_boot_id cat /proc/sys/kernel/random/boot_id
collect phase5e_final_mounts findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
collect phase5e_final_root_write write_probe "/.slprobe-phase5e-$marker"
collect phase5e_final_usr_write write_probe "/usr/.slprobe-phase5e-$marker"
collect phase5e_audit journalctl --boot --no-pager --output=cat _TRANSPORT=audit
collect phase5e_console_journal journalctl --boot --no-pager --unit=sl-console@tty1.service --unit=sl-console@ttyS0.service
