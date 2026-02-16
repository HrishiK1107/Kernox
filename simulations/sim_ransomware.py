#!/usr/bin/env python3
"""
Kernox Red Team Simulation — Ransomware Burst

Simulates ransomware-like behavior by rapidly creating, writing,
and renaming files in a temp directory. This should trigger the
agent's `alert_ransomware_burst` detection.

SAFE: Only operates on temp files, non-destructive.

Usage:
    python3 simulations/sim_ransomware.py
"""

import os
import sys
import time
import tempfile

TARGET_DIR = tempfile.mkdtemp(prefix="kernox_sim_ransom_")
FILE_COUNT = 30  # above the 20-file burst threshold
DELAY = 0.05     # 50ms between writes — well within 5s window


def main():
    print(f"[SIM] Ransomware burst simulation")
    print(f"[SIM] Target directory: {TARGET_DIR}")
    print(f"[SIM] Will create {FILE_COUNT} files rapidly")
    print(f"[SIM] Expected alert: alert_ransomware_burst")
    print()

    for i in range(FILE_COUNT):
        filepath = os.path.join(TARGET_DIR, f"victim_file_{i:04d}.txt")

        # Create and write
        with open(filepath, "w") as f:
            f.write(f"ENCRYPTED_DATA_{i:04d}" * 100)

        # Rename (simulates .encrypted extension)
        encrypted = filepath + ".encrypted"
        os.rename(filepath, encrypted)

        print(f"  [+] {encrypted}")
        time.sleep(DELAY)

    print()
    print(f"[SIM] Done. {FILE_COUNT} files written + renamed in {FILE_COUNT * DELAY:.1f}s")
    print(f"[SIM] Check agent output for 'alert_ransomware_burst' event")

    # Cleanup
    for f in os.listdir(TARGET_DIR):
        os.remove(os.path.join(TARGET_DIR, f))
    os.rmdir(TARGET_DIR)
    print(f"[SIM] Cleaned up temp directory")


if __name__ == "__main__":
    main()
