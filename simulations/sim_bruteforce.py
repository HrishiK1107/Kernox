#!/usr/bin/env python3
"""
Kernox Red Team Simulation — SSH Brute Force

Simulates SSH brute force by making rapid failed SSH login attempts.
This should trigger the agent's `alert_brute_force` detection from
auth.log monitoring.

SAFE: Connects to localhost SSH with intentionally wrong credentials.
      Requires SSH server running locally (sshd).

Usage:
    python3 simulations/sim_bruteforce.py
"""

import subprocess
import time
import sys

TARGET_HOST = "127.0.0.1"
TARGET_USER = "kernox_fake_user"  # non-existent user
ATTEMPT_COUNT = 8  # above the 5-attempt threshold
DELAY = 0.5        # 500ms between attempts — within 60s window


def main():
    print(f"[SIM] SSH brute force simulation")
    print(f"[SIM] Target: {TARGET_USER}@{TARGET_HOST}")
    print(f"[SIM] Will make {ATTEMPT_COUNT} failed login attempts")
    print(f"[SIM] Expected alert: alert_brute_force")
    print()

    # Check if sshd is running
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "ssh"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() != "active":
            print("[SIM] WARNING: SSH service doesn't appear to be running")
            print("[SIM] Start it with: sudo systemctl start ssh")
            print("[SIM] Continuing anyway...")
            print()
    except Exception:
        pass

    for i in range(ATTEMPT_COUNT):
        try:
            # Use sshpass or ssh with forced failure
            # -o StrictHostKeyChecking=no: skip host key prompt
            # -o BatchMode=yes: fail immediately without password prompt
            # -o ConnectTimeout=2: don't hang
            result = subprocess.run(
                [
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=2",
                    f"{TARGET_USER}@{TARGET_HOST}",
                    "echo test",
                ],
                capture_output=True, text=True, timeout=5,
            )
            print(f"  [+] Attempt {i+1}/{ATTEMPT_COUNT} — failed login (expected)")
        except subprocess.TimeoutExpired:
            print(f"  [+] Attempt {i+1}/{ATTEMPT_COUNT} — timeout (ssh not responding)")
        except FileNotFoundError:
            print("[SIM] ERROR: 'ssh' command not found. Install openssh-client.")
            sys.exit(1)

        time.sleep(DELAY)

    print()
    total_time = ATTEMPT_COUNT * DELAY
    print(f"[SIM] Done. {ATTEMPT_COUNT} failed attempts in {total_time:.1f}s")
    print(f"[SIM] Check agent output for 'alert_brute_force' event")
    print(f"[SIM] Also check: sudo tail -5 /var/log/auth.log")


if __name__ == "__main__":
    main()
