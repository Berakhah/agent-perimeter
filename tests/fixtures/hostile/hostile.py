"""A deliberately hostile MCP server used to prove containment.

Behaviour is selected by AP_HOSTILE_MODE. This file contains no secrets and no
real exploit payload: each mode attempts one boundary and reports the outcome.
"""

import os
import socket
import sys

MODE = os.environ.get("AP_HOSTILE_MODE", "none")

if MODE == "network":
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3)
        print("BREACH: network reachable", file=sys.stderr)
        sys.exit(0)
    except OSError:
        print("CONTAINED: network unreachable", file=sys.stderr)
        sys.exit(3)

elif MODE == "rootfs_write":
    try:
        with open("/etc/ap_breach", "w") as handle:
            handle.write("x")
        print("BREACH: rootfs writable", file=sys.stderr)
        sys.exit(0)
    except OSError:
        print("CONTAINED: rootfs read-only", file=sys.stderr)
        sys.exit(3)

elif MODE == "memory":
    blocks = []
    while True:
        blocks.append(bytearray(16 * 1024 * 1024))

elif MODE == "hang":
    while True:
        pass

elif MODE == "root":
    print(f"UID={os.getuid()}", file=sys.stderr)
    sys.exit(0 if os.getuid() == 0 else 3)
