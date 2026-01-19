#!/usr/bin/env python3
"""
Test script that generates various network connections to be captured by mitmproxy.

Generates:
- HTTP requests
- HTTPS requests
- DNS queries
- Raw TCP connections (non-HTTP)
- Raw UDP connections (non-DNS)
"""

import socket
import ssl
import sys
import time


def test_http_request():
    """Make a plain HTTP request."""
    print("TEST: HTTP GET http://example.com/")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        # Use example.com which still supports HTTP
        sock.connect(("example.com", 80))
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        sock.sendall(request)
        response = sock.recv(1024)
        sock.close()
        print(f"  -> Got {len(response)} bytes response")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return False


def test_https_request():
    """Make an HTTPS request."""
    print("TEST: HTTPS GET https://httpbin.org/get")
    try:
        context = ssl.create_default_context()
        # For testing with mitmproxy, we may need to disable verification
        # or trust mitmproxy's CA
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("httpbin.org", 443))
        ssock = context.wrap_socket(sock, server_hostname="httpbin.org")
        request = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
        ssock.sendall(request)
        response = ssock.recv(4096)
        ssock.close()
        print(f"  -> Got {len(response)} bytes response")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return False


def test_dns_query():
    """Make a DNS query (A record)."""
    print("TEST: DNS A query for example.com")
    try:
        # Build a simple DNS query for example.com A record
        # Transaction ID
        txn_id = b"\x12\x34"
        # Flags: standard query
        flags = b"\x01\x00"
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        # Query: example.com, Type A, Class IN
        query = b"\x07example\x03com\x00\x00\x01\x00\x01"

        dns_request = txn_id + flags + counts + query

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        # Use Google's public DNS (mitmproxy will intercept)
        sock.sendto(dns_request, ("8.8.8.8", 53))
        response, addr = sock.recvfrom(512)
        sock.close()
        print(f"  -> Got {len(response)} bytes DNS response")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return False


def test_dns_query_aaaa():
    """Make a DNS query (AAAA record)."""
    print("TEST: DNS AAAA query for google.com")
    try:
        # Build a simple DNS query for google.com AAAA record
        txn_id = b"\x56\x78"
        flags = b"\x01\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        # Query: google.com, Type AAAA (28), Class IN
        query = b"\x06google\x03com\x00\x00\x1c\x00\x01"

        dns_request = txn_id + flags + counts + query

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(dns_request, ("8.8.8.8", 53))
        response, addr = sock.recvfrom(512)
        sock.close()
        print(f"  -> Got {len(response)} bytes DNS response")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return False


def test_raw_tcp():
    """Make a raw TCP connection (non-HTTP) to a known port."""
    print("TEST: Raw TCP connection to time.nist.gov:13 (daytime)")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        # NIST daytime service
        sock.connect(("time.nist.gov", 13))
        data = sock.recv(100)
        sock.close()
        print(f"  -> Got: {data.decode('ascii', errors='ignore').strip()}")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        # Try alternate: connect to a well-known TCP port
        return test_raw_tcp_alternate()


def test_raw_tcp_alternate():
    """Alternate raw TCP test - connect to SSH port."""
    print("TEST: Raw TCP connection to github.com:22 (SSH)")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("github.com", 22))
        # Read SSH banner
        data = sock.recv(100)
        sock.close()
        print(f"  -> Got SSH banner: {data.decode('ascii', errors='ignore').strip()}")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return False


def test_raw_udp():
    """Make a raw UDP connection (non-DNS)."""
    print("TEST: Raw UDP to time.nist.gov:123 (NTP)")
    try:
        # Build a simple NTP request
        # NTP v3, client mode
        ntp_request = b"\x1b" + b"\x00" * 47

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(ntp_request, ("time.nist.gov", 123))
        response, addr = sock.recvfrom(100)
        sock.close()
        print(f"  -> Got {len(response)} bytes NTP response")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return False


def test_http_post():
    """Make an HTTP POST request."""
    print("TEST: HTTP POST https://httpbin.org/post")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("httpbin.org", 443))
        ssock = context.wrap_socket(sock, server_hostname="httpbin.org")

        body = b'{"test": "data"}'
        request = (
            b"POST /post HTTP/1.1\r\n"
            b"Host: httpbin.org\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n"
        ) + body

        ssock.sendall(request)
        response = ssock.recv(4096)
        ssock.close()
        print(f"  -> Got {len(response)} bytes response")
        return True
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return False


def main():
    """Run all connection tests."""
    print("=" * 60)
    print("Connection Test Suite for mitmproxy")
    print("=" * 60)
    print()

    results = []

    # HTTP/HTTPS tests
    results.append(("HTTP GET", test_http_request()))
    time.sleep(0.5)

    results.append(("HTTPS GET", test_https_request()))
    time.sleep(0.5)

    results.append(("HTTPS POST", test_http_post()))
    time.sleep(0.5)

    # DNS tests
    results.append(("DNS A", test_dns_query()))
    time.sleep(0.5)

    results.append(("DNS AAAA", test_dns_query_aaaa()))
    time.sleep(0.5)

    # Raw TCP (non-HTTP)
    results.append(("Raw TCP", test_raw_tcp()))
    time.sleep(0.5)

    # Raw UDP (non-DNS)
    results.append(("Raw UDP (NTP)", test_raw_udp()))

    print()
    print("=" * 60)
    print("Results:")
    print("=" * 60)
    passed = 0
    failed = 0
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print()
    print(f"Total: {passed} passed, {failed} failed")

    # Return success if at least some tests passed
    # (some may fail due to network restrictions)
    return passed > 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
