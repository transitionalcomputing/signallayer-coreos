#!/usr/bin/env python3
"""Fixed, test-only requests via shipped Python/libsystemd; no binary fixture."""
import ctypes as c
import json
import os
import sys

BUS = "org.signallayer.Platform1"
PATH = "/org/signallayer/Platform1"


class BusError(c.Structure):
    _fields_ = [("name", c.c_char_p), ("message", c.c_char_p), ("need_free", c.c_int)]


lib = c.CDLL("libsystemd.so.0")
pointer = c.c_void_p
lib.sd_bus_open_system.argtypes = [c.POINTER(pointer)]
lib.sd_bus_open_system.restype = c.c_int
lib.sd_bus_get_unique_name.argtypes = [pointer, c.POINTER(c.c_char_p)]
lib.sd_bus_get_unique_name.restype = c.c_int
lib.sd_bus_set_method_call_timeout.argtypes = [pointer, c.c_uint64]
lib.sd_bus_set_method_call_timeout.restype = c.c_int
lib.sd_bus_call_method.argtypes = [pointer, c.c_char_p, c.c_char_p, c.c_char_p,
                                 c.c_char_p, c.POINTER(BusError), c.POINTER(pointer), c.c_char_p]
lib.sd_bus_call_method.restype = c.c_int
lib.sd_bus_message_read.argtypes = [pointer, c.c_char_p]
lib.sd_bus_message_read.restype = c.c_int
lib.sd_bus_message_get_signature.argtypes = [pointer, c.c_int]
lib.sd_bus_message_get_signature.restype = c.c_char_p
lib.sd_bus_message_unref.argtypes = [pointer]
lib.sd_bus_message_unref.restype = pointer
lib.sd_bus_error_free.argtypes = [c.POINTER(BusError)]
lib.sd_bus_error_free.restype = None
lib.sd_bus_flush_close_unref.argtypes = [pointer]
lib.sd_bus_flush_close_unref.restype = pointer


def checked(result):
    if result < 0:
        raise RuntimeError(os.strerror(-result))


def run(scenario):
    if scenario not in {"own", "unsupported", "wrong-path", "wrong-interface", "invalid-signature", "status", "identity-only", "start-reboot"}:
        raise ValueError("unknown test scenario")
    bus = pointer()
    checked(lib.sd_bus_open_system(c.byref(bus)))
    try:
        checked(lib.sd_bus_set_method_call_timeout(bus, 10_000_000))
        sender = c.c_char_p()
        checked(lib.sd_bus_get_unique_name(bus, c.byref(sender)))
        error, reply = BusError(), pointer()
        checked(lib.sd_bus_call_method(bus, b"org.freedesktop.DBus", b"/org/freedesktop/DBus",
                                      b"org.freedesktop.DBus", b"GetConnectionUnixUser",
                                      c.byref(error), c.byref(reply), b"s", sender))
        uid = c.c_uint32()
        checked(lib.sd_bus_message_read(reply, b"u", c.byref(uid)))
        lib.sd_bus_message_unref(reply)
        lib.sd_bus_error_free(c.byref(error))
        if uid.value != os.getuid():
            raise RuntimeError("broker UID differs from process UID")
        # Phase 4D denial fixture only: never request a reboot as root.
        if scenario == "start-reboot" and uid.value == 0:
            raise RuntimeError("start-reboot is a non-root denial fixture")
        if scenario == "identity-only":
            print(json.dumps({"sender": sender.value.decode(), "uid": uid.value}), flush=True)
            return 0
        request = {"scenario": scenario, "sender": sender.value.decode(), "uid": uid.value,
                   "destination": BUS, "path": PATH, "interface": BUS,
                   "member": "GetStatus", "signature": "", "body": []}
        arguments = []
        if scenario == "own":
            request.update(destination="org.freedesktop.DBus", path="/org/freedesktop/DBus",
                           interface="org.freedesktop.DBus", member="RequestName", signature="su", body=[BUS, 4])
            arguments = [c.c_char_p(BUS.encode()), c.c_uint32(4)]
        elif scenario == "unsupported":
            request["member"] = "UnsupportedPhase3BMethod"
        elif scenario == "wrong-path":
            request["path"] = "/org/signallayer/WrongObject"
        elif scenario == "wrong-interface":
            request["interface"] = "org.signallayer.WrongInterface"
        elif scenario == "start-reboot":
            request["member"] = "StartReboot"
        elif scenario == "invalid-signature":
            request.update(signature="s", body=["unexpected"])
            arguments = [c.c_char_p(b"unexpected")]
        error, reply = BusError(), pointer()
        result = lib.sd_bus_call_method(bus, *(request[key].encode() for key in (
            "destination", "path", "interface", "member")), c.byref(error), c.byref(reply),
            request["signature"].encode(), *arguments)
        if result >= 0:
            response = {"request": request, "result": "success",
                        "reply_signature": lib.sd_bus_message_get_signature(reply, 1).decode()}
        elif error.name:
            response = {"request": request, "result": "method_error", "error_name": error.name.decode(),
                        "message": error.message.decode(errors="replace") if error.message else None}
        else:
            response = {"request": request, "result": "transport_error", "message": os.strerror(-result)}
        print(json.dumps(response), flush=True)
        lib.sd_bus_message_unref(reply)
        lib.sd_bus_error_free(c.byref(error))
        return 0 if result >= 0 else 1
    finally:
        lib.sd_bus_flush_close_unref(bus)


if __name__ == "__main__":
    try:
        sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else ""))
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"fixture_error": str(error)}), file=sys.stderr)
        sys.exit(1)
