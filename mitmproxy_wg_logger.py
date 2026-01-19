#!/usr/bin/env python3
"""
mitmproxy WireGuard mode connection logger.

Logs various connection types:
- HTTPS/HTTP: method and full URL
- DNS: question type, name, and answer data
- Non-HTTP TCP: dest IP + dest port
- Non-DNS UDP: dest IP + dest port
"""

import logging
import sys

from mitmproxy import http, dns
from mitmproxy.tcp import TCPFlow
from mitmproxy.udp import UDPFlow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


class ConnectionLogger:
    """Addon that logs all connection types with relevant details."""

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Log HTTP CONNECT requests (for HTTPS tunneling)."""
        logger.info(f"HTTP_CONNECT: {flow.request.host}:{flow.request.port}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Log HTTP/HTTPS requests with method and full URL."""
        scheme = "https" if flow.request.scheme == "https" else "http"
        url = flow.request.pretty_url
        method = flow.request.method
        logger.info(f"HTTP_REQUEST: {method} {url}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Log HTTP/HTTPS responses."""
        status = flow.response.status_code if flow.response else "?"
        logger.info(f"HTTP_RESPONSE: {status} {flow.request.pretty_url}")

    def dns_request(self, flow: dns.DNSFlow) -> None:
        """Log DNS requests with question type and name."""
        if flow.request:
            for question in flow.request.questions:
                qtype = question.type.name
                qname = question.name
                logger.info(f"DNS_REQUEST: {qtype} {qname}")

    def dns_response(self, flow: dns.DNSFlow) -> None:
        """Log DNS responses with answer data."""
        if flow.response and flow.request and flow.request.questions:
            question = flow.request.questions[0]
            qtype = question.type.name
            qname = question.name

            answers = []
            for answer in flow.response.answers:
                # Format answer based on type
                if hasattr(answer, "data"):
                    answers.append(str(answer.data))
                else:
                    answers.append(repr(answer))

            answers_str = ", ".join(answers) if answers else "no answers"
            logger.info(f"DNS_RESPONSE: {qtype} {qname} -> {answers_str}")

    def tcp_start(self, flow: TCPFlow) -> None:
        """Log non-HTTP TCP connections."""
        addr = flow.server_conn.address
        if addr:
            logger.info(f"TCP_CONNECT: {addr[0]}:{addr[1]}")

    def tcp_message(self, flow: TCPFlow) -> None:
        """Log TCP message direction and size."""
        if flow.messages:
            msg = flow.messages[-1]
            direction = "client->server" if msg.from_client else "server->client"
            logger.info(f"TCP_DATA: {flow.server_conn.address[0]}:{flow.server_conn.address[1]} {direction} {len(msg.content)} bytes")

    def tcp_end(self, flow: TCPFlow) -> None:
        """Log TCP connection end."""
        addr = flow.server_conn.address
        if addr:
            logger.info(f"TCP_END: {addr[0]}:{addr[1]}")

    def udp_start(self, flow: UDPFlow) -> None:
        """Log non-DNS UDP connections."""
        addr = flow.server_conn.address
        if addr:
            logger.info(f"UDP_START: {addr[0]}:{addr[1]}")

    def udp_message(self, flow: UDPFlow) -> None:
        """Log UDP message direction and size."""
        if flow.messages:
            msg = flow.messages[-1]
            direction = "client->server" if msg.from_client else "server->client"
            addr = flow.server_conn.address
            if addr:
                logger.info(f"UDP_DATA: {addr[0]}:{addr[1]} {direction} {len(msg.content)} bytes")

    def udp_end(self, flow: UDPFlow) -> None:
        """Log UDP connection end."""
        addr = flow.server_conn.address
        if addr:
            logger.info(f"UDP_END: {addr[0]}:{addr[1]}")


addons = [ConnectionLogger()]


if __name__ == "__main__":
    # When run directly, start mitmproxy in WireGuard mode with this addon
    import subprocess
    import os

    script_path = os.path.abspath(__file__)
    cmd = [
        "mitmdump",
        "--mode", "wireguard",
        "--set", "block_global=false",
        "-s", script_path,
    ]
    subprocess.run(cmd)
