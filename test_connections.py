#!/usr/bin/env python3
"""Generate test connections to exercise all BPF code paths."""

import socket
import subprocess
import sys


def test_tcp_ipv4():
    """TCP IPv4 via handle_sockops AF_INET path."""
    print("TCP IPv4...", end=" ", flush=True)
    try:
        result = subprocess.run(
            ["curl", "-4", "-s", "--max-time", "5", "http://example.com"],
            capture_output=True,
            timeout=10,
        )
        print("OK" if result.returncode == 0 else "FAIL")
        return result.returncode == 0
    except Exception as e:
        print(f"FAIL: {e}")
        return False


def test_tcp_ipv6():
    """TCP IPv6 via handle_sockops AF_INET6 native path."""
    print("TCP IPv6...", end=" ", flush=True)
    try:
        result = subprocess.run(
            ["curl", "-6", "-s", "--max-time", "5", "http://example.com"],
            capture_output=True,
            timeout=10,
        )
        print("OK" if result.returncode == 0 else "SKIP (no IPv6)")
        return True  # Don't fail if no IPv6
    except Exception:
        print("SKIP")
        return True


def test_tcp_v4mapped():
    """TCP via handle_sockops AF_INET6 v4-mapped path."""
    print("TCP v4-mapped...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("::ffff:8.8.8.8", 443))
        s.close()
        print("OK")
        return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False


def test_udp_ipv4():
    """UDP IPv4 via handle_sendmsg4."""
    print("UDP IPv4...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"\x00", ("8.8.8.8", 53))
        s.close()
        print("OK")
        return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False


def test_udp_ipv6():
    """UDP IPv6 via handle_sendmsg6 native path."""
    print("UDP IPv6...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.sendto(b"\x00", ("2001:4860:4860::8888", 53))
        s.close()
        print("OK")
        return True
    except socket.gaierror:
        print("SKIP (no IPv6)")
        return True
    except OSError:
        print("SKIP (no IPv6)")
        return True


def test_udp_v4mapped():
    """UDP via handle_sendmsg6 v4-mapped path."""
    print("UDP v4-mapped...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.sendto(b"\x00", ("::ffff:8.8.8.8", 53))
        s.close()
        print("OK")
        return True
    except Exception as e:
        print(f"FAIL: {e}")
        return False


def main():
    results = [
        test_tcp_ipv4(),
        test_tcp_ipv6(),
        test_tcp_v4mapped(),
        test_udp_ipv4(),
        test_udp_ipv6(),
        test_udp_v4mapped(),
    ]

    if all(results):
        print("All connection tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
