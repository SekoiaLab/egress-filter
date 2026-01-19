#!/usr/bin/env python3
"""Test the IPv6 blocker BPF program."""

import errno
import socket
import sys
from pathlib import Path

import tinybpf

# Initialize with system libbpf
for libbpf_path in ["/usr/lib/x86_64-linux-gnu/libbpf.so.1", "/usr/lib/libbpf.so.1"]:
    if Path(libbpf_path).exists():
        tinybpf.init(libbpf_path)
        break

BPF_PATH = Path(__file__).parent / "src" / "bpf" / "ipv6_blocker.bpf.o"


def get_self_cgroup() -> str:
    """Get the cgroup path for the current process."""
    cgroup_info = Path("/proc/self/cgroup").read_text().strip()
    cgroup_rel = cgroup_info.split(":")[-1]
    return f"/sys/fs/cgroup{cgroup_rel}"


def test_ipv6_blocker():
    """Test that IPv6 blocker blocks native IPv6 but allows v4-mapped."""
    cgroup_path = get_self_cgroup()

    with tinybpf.load(str(BPF_PATH)) as obj:
        links = []
        links.append(obj.program("block_connect6").attach_cgroup(cgroup_path))
        links.append(obj.program("block_sendmsg6").attach_cgroup(cgroup_path))

        config_map = obj.maps["config"].typed(key=int, value=int)

        # Enable blocking
        config_map[0] = 1

        # Native IPv6 TCP should be blocked
        print("Native IPv6 TCP (should block)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("2001:4860:4860::8888", 443))
            s.close()
            print("FAIL - connected")
            return False
        except OSError as e:
            if e.errno in (errno.EPERM, errno.EACCES):
                print("OK")
            elif e.errno == errno.ENETUNREACH:
                print("SKIP (no IPv6)")
            else:
                print(f"FAIL: {e}")
                return False

        # Native IPv6 UDP should be blocked
        print("Native IPv6 UDP (should block)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.sendto(b"\x00", ("2001:4860:4860::8888", 53))
            s.close()
            print("FAIL - sent")
            return False
        except OSError as e:
            if e.errno in (errno.EPERM, errno.EACCES):
                print("OK")
            elif e.errno == errno.ENETUNREACH:
                print("SKIP (no IPv6)")
            else:
                print(f"FAIL: {e}")
                return False

        # v4-mapped TCP should be allowed
        print("v4-mapped TCP (should allow)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("::ffff:8.8.8.8", 443))
            s.close()
            print("OK")
        except OSError as e:
            if e.errno in (errno.EPERM, errno.EACCES):
                print(f"FAIL - blocked: {e}")
                return False
            print(f"SKIP (network): {e}")

        # v4-mapped UDP should be allowed
        print("v4-mapped UDP (should allow)...", end=" ")
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.sendto(b"\x00", ("::ffff:8.8.8.8", 53))
            s.close()
            print("OK")
        except OSError as e:
            if e.errno in (errno.EPERM, errno.EACCES):
                print(f"FAIL - blocked: {e}")
                return False
            print(f"SKIP (network): {e}")

        for link in links:
            link.destroy()

    print("All tests passed!")
    return True


if __name__ == "__main__":
    sys.exit(0 if test_ipv6_blocker() else 1)
