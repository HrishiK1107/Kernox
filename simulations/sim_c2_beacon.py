#!/usr/bin/env python3
"""
Kernox Red Team Simulation — C2 Beaconing

Simulates command-and-control beaconing by making repeated TCP
connections to the same IP:port. This should trigger the agent's
`alert_c2_beaconing` detection.

SAFE: Connects to a non-routable IP, connections will fail fast.

Usage:
    python3 simulations/sim_c2_beacon.py
"""

import socket
import time

# Non-routable IP — connections will fail immediately (safe)
C2_HOST = "192.0.2.1"  # TEST-NET-1 (RFC 5737), guaranteed non-routable
C2_PORT = 4444
BEACON_COUNT = 15  # above the 10-connection threshold
DELAY = 0.3        # 300ms between beacons — within 60s window


def main():
    print(f"[SIM] C2 beaconing simulation")
    print(f"[SIM] Target: {C2_HOST}:{C2_PORT}")
    print(f"[SIM] Will attempt {BEACON_COUNT} connections")
    print(f"[SIM] Expected alert: alert_c2_beaconing")
    print()

    for i in range(BEACON_COUNT):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((C2_HOST, C2_PORT))
            sock.close()
            print(f"  [+] Beacon {i+1}/{BEACON_COUNT} connected (unexpected!)")
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"  [+] Beacon {i+1}/{BEACON_COUNT} (connect attempted)")
        finally:
            try:
                sock.close()
            except Exception:
                pass

        time.sleep(DELAY)

    print()
    total_time = BEACON_COUNT * DELAY
    print(f"[SIM] Done. {BEACON_COUNT} connections in {total_time:.1f}s")
    print(f"[SIM] Check agent output for 'alert_c2_beaconing' event")


if __name__ == "__main__":
    main()
