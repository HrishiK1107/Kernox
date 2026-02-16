#!/usr/bin/env python3
"""
Kernox Red Team Simulation — Privilege Escalation

Demonstrates privilege escalation detection by calling setuid(0).
Must be run as a non-root user for the escalation to be detected.

SAFE: Runs with setuid which requires appropriate permissions.
      If run as non-root, the call will fail (permission denied)
      but the eBPF hook fires BEFORE the kernel checks permissions,
      so the agent will still capture the attempt.

Usage:
    python3 simulations/sim_privesc.py
"""

import os
import ctypes


def main():
    current_uid = os.getuid()
    print(f"[SIM] Privilege escalation simulation")
    print(f"[SIM] Current UID: {current_uid}")
    print(f"[SIM] Will attempt setuid(0)")
    print(f"[SIM] Expected alert: alert_privilege_escalation")
    print()

    if current_uid == 0:
        print("[SIM] WARNING: Already running as root (UID 0)")
        print("[SIM] The agent won't flag this as escalation (uid == target_id)")
        print("[SIM] Run as a normal user for proper detection")
        print()

    # Attempt setuid(0) — the eBPF tracepoint fires on sys_enter_setuid
    # regardless of whether the kernel allows it
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    print(f"  [+] Calling setuid(0)...")
    result = libc.setuid(0)

    if result == 0:
        print(f"  [+] setuid(0) succeeded! New UID: {os.getuid()}")
    else:
        errno = ctypes.get_errno()
        print(f"  [+] setuid(0) failed (errno={errno}) — expected for non-root")
        print(f"  [+] But the eBPF hook captured the attempt!")

    # Also try setgid(0) for additional coverage
    print(f"  [+] Calling setgid(0)...")
    result = libc.setgid(0)

    if result == 0:
        print(f"  [+] setgid(0) succeeded! New GID: {os.getgid()}")
    else:
        errno = ctypes.get_errno()
        print(f"  [+] setgid(0) failed (errno={errno}) — expected for non-root")

    print()
    print(f"[SIM] Done. Check agent output for 'alert_privilege_escalation' event")


if __name__ == "__main__":
    main()
