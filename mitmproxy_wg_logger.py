#!/usr/bin/env python3
"""
mitmproxy WireGuard mode connection logger.

Logs one line per connection:
- HTTP/HTTPS: method URL -> status
- DNS: type name -> answers
- Non-HTTP TCP: dest:port
- Non-DNS UDP: dest:port
"""

import logging
import sys

from mitmproxy import http, dns
from mitmproxy.tcp import TCPFlow
from mitmproxy.udp import UDPFlow

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# DNS record type names
DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 257: "CAA",
}


class ConnectionLogger:
    """Addon that logs one line per connection."""

    def __init__(self):
        self.logged_flows = set()

    def response(self, flow: http.HTTPFlow) -> None:
        """Log HTTP/HTTPS when response is received (once per request)."""
        if flow.id in self.logged_flows:
            return
        self.logged_flows.add(flow.id)

        method = flow.request.method
        url = flow.request.pretty_url
        status = flow.response.status_code if flow.response else "?"
        logger.info(f"HTTP: {method} {url} -> {status}")

    def error(self, flow) -> None:
        """Log HTTP errors (failed connections)."""
        if not hasattr(flow, 'request') or flow.request is None:
            return
        if flow.id in self.logged_flows:
            return
        self.logged_flows.add(flow.id)

        method = flow.request.method
        url = flow.request.pretty_url
        err = str(flow.error) if flow.error else "error"
        logger.info(f"HTTP: {method} {url} -> {err}")

    def dns_response(self, flow: dns.DNSFlow) -> None:
        """Log DNS when response is received (once per query)."""
        if flow.id in self.logged_flows:
            return
        self.logged_flows.add(flow.id)

        if not flow.request or not flow.request.questions:
            return

        q = flow.request.questions[0]
        qtype = DNS_TYPES.get(q.type, f"TYPE{q.type}")
        qname = q.name

        if flow.response and flow.response.answers:
            answers = []
            for a in flow.response.answers:
                if hasattr(a, 'data'):
                    answers.append(str(a.data))
            result = ", ".join(answers) if answers else "no data"
        elif flow.error:
            result = "SERVFAIL"
        else:
            result = "no answer"

        logger.info(f"DNS: {qtype} {qname} -> {result}")

    def dns_error(self, flow: dns.DNSFlow) -> None:
        """Log DNS errors."""
        if flow.id in self.logged_flows:
            return
        self.logged_flows.add(flow.id)

        if not flow.request or not flow.request.questions:
            return

        q = flow.request.questions[0]
        qtype = DNS_TYPES.get(q.type, f"TYPE{q.type}")
        qname = q.name
        logger.info(f"DNS: {qtype} {qname} -> error")

    def tcp_start(self, flow: TCPFlow) -> None:
        """Log non-HTTP TCP connections once at start."""
        if flow.id in self.logged_flows:
            return
        self.logged_flows.add(flow.id)

        addr = flow.server_conn.address
        if addr:
            logger.info(f"TCP: {addr[0]}:{addr[1]}")

    def udp_start(self, flow: UDPFlow) -> None:
        """Log non-DNS UDP connections once at start."""
        if flow.id in self.logged_flows:
            return
        self.logged_flows.add(flow.id)

        addr = flow.server_conn.address
        if addr:
            logger.info(f"UDP: {addr[0]}:{addr[1]}")


addons = [ConnectionLogger()]
