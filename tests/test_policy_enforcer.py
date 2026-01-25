"""Tests for PolicyEnforcer and DNSIPCache.

These tests verify the policy enforcement logic without requiring
mitmproxy, BPF, or network infrastructure.
"""

import time
import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy import (
    PolicyMatcher,
    PolicyEnforcer,
    DNSIPCache,
    ProcessInfo,
    Verdict,
)


# =============================================================================
# DNSIPCache Tests
# =============================================================================


class TestDNSIPCache:
    """Tests for DNS IP correlation cache."""

    def test_add_and_lookup(self):
        """Basic add and lookup."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "github.com", ttl=300)

        assert cache.lookup("140.82.121.4") == "github.com"
        assert cache.lookup("8.8.8.8") is None

    def test_add_many(self):
        """Add multiple IPs for same hostname."""
        cache = DNSIPCache()
        cache.add_many(
            ["140.82.121.4", "140.82.121.5", "140.82.121.6"],
            "github.com",
            ttl=300,
        )

        assert cache.lookup("140.82.121.4") == "github.com"
        assert cache.lookup("140.82.121.5") == "github.com"
        assert cache.lookup("140.82.121.6") == "github.com"

    def test_hostname_normalized_to_lowercase(self):
        """Hostnames are stored lowercase."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "GitHub.COM", ttl=300)

        assert cache.lookup("140.82.121.4") == "github.com"

    def test_expiry(self):
        """Entries expire based on TTL."""
        cache = DNSIPCache(min_ttl=1, max_ttl=1)
        cache.add("140.82.121.4", "github.com", ttl=1)

        # Should exist immediately
        assert cache.lookup("140.82.121.4") == "github.com"

        # Wait for expiry
        time.sleep(1.1)

        # Should be gone
        assert cache.lookup("140.82.121.4") is None

    def test_ttl_clamped_to_max(self):
        """TTL is clamped to max_ttl."""
        cache = DNSIPCache(max_ttl=10)
        cache.add("140.82.121.4", "github.com", ttl=9999)

        # Entry should exist
        assert cache.lookup("140.82.121.4") == "github.com"

    def test_ttl_clamped_to_min(self):
        """TTL is clamped to min_ttl."""
        cache = DNSIPCache(min_ttl=60)
        cache.add("140.82.121.4", "github.com", ttl=1)

        # Should still exist after 1 second (min_ttl is 60)
        time.sleep(1.1)
        assert cache.lookup("140.82.121.4") == "github.com"

    def test_cleanup_expired(self):
        """cleanup_expired removes old entries."""
        cache = DNSIPCache(min_ttl=1, max_ttl=1)
        cache.add("140.82.121.4", "github.com", ttl=1)
        cache.add("8.8.8.8", "dns.google", ttl=1)

        assert len(cache) == 2

        time.sleep(1.1)
        removed = cache.cleanup_expired()

        assert removed == 2
        assert len(cache) == 0

    def test_clear(self):
        """clear removes all entries."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "github.com", ttl=300)
        cache.add("8.8.8.8", "dns.google", ttl=300)

        cache.clear()

        assert len(cache) == 0
        assert cache.lookup("140.82.121.4") is None

    def test_stats(self):
        """stats returns correct counts."""
        cache = DNSIPCache(min_ttl=1, max_ttl=1)
        cache.add("140.82.121.4", "github.com", ttl=300)  # Will be clamped to 1
        cache.add("8.8.8.8", "dns.google", ttl=300)

        stats = cache.stats()
        assert stats["total"] == 2
        assert stats["valid"] == 2
        assert stats["expired"] == 0

        time.sleep(1.1)

        stats = cache.stats()
        assert stats["total"] == 2
        assert stats["valid"] == 0
        assert stats["expired"] == 2

    def test_overwrite_existing(self):
        """Adding same IP overwrites previous entry."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "github.com", ttl=300)
        cache.add("140.82.121.4", "api.github.com", ttl=300)

        assert cache.lookup("140.82.121.4") == "api.github.com"


# =============================================================================
# PolicyEnforcer Tests - HTTPS
# =============================================================================


class TestEnforcerHTTPS:
    """Tests for HTTPS connection enforcement."""

    def test_https_allowed_by_host_rule(self):
        """HTTPS with SNI matching host rule is allowed."""
        matcher = PolicyMatcher("github.com")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
        )

        assert decision.allowed
        assert decision.hostname == "github.com"

    def test_https_allowed_by_wildcard_rule(self):
        """HTTPS with SNI matching wildcard rule is allowed."""
        matcher = PolicyMatcher("*.github.com")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="api.github.com",
        )

        assert decision.allowed
        assert decision.hostname == "api.github.com"

    def test_https_blocked_no_matching_rule(self):
        """HTTPS is blocked when no rule matches."""
        matcher = PolicyMatcher("github.com")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="93.184.216.34",
            dst_port=443,
            sni="example.com",
        )

        assert decision.blocked
        assert "example.com" in decision.reason

    def test_https_no_sni_uses_dns_cache(self):
        """HTTPS without SNI uses DNS cache for hostname."""
        matcher = PolicyMatcher("github.com")
        dns_cache = DNSIPCache()
        dns_cache.add("140.82.121.4", "github.com", ttl=300)
        enforcer = PolicyEnforcer(matcher, dns_cache)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni=None,  # No SNI
        )

        assert decision.allowed
        assert "DNS cache" in decision.reason

    def test_https_no_sni_no_cache_blocked(self):
        """HTTPS without SNI and no DNS cache is blocked."""
        matcher = PolicyMatcher("github.com")  # Host rule only
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni=None,
        )

        assert decision.blocked
        assert "no SNI" in decision.reason

    def test_https_no_sni_allowed_by_ip_rule(self):
        """HTTPS without SNI can match IP rules."""
        matcher = PolicyMatcher("140.82.121.4:443")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni=None,
        )

        assert decision.allowed


# =============================================================================
# PolicyEnforcer Tests - HTTP
# =============================================================================


class TestEnforcerHTTP:
    """Tests for HTTP request enforcement."""

    def test_http_allowed_by_url_rule(self):
        """HTTP request matching URL rule is allowed."""
        matcher = PolicyMatcher("https://api.github.com/*")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_http(
            dst_ip="140.82.121.4",
            dst_port=443,
            url="https://api.github.com/repos/owner/repo",
            method="GET",
        )

        assert decision.allowed

    def test_http_blocked_wrong_method(self):
        """HTTP request with wrong method is blocked."""
        matcher = PolicyMatcher("GET https://api.github.com/*")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_http(
            dst_ip="140.82.121.4",
            dst_port=443,
            url="https://api.github.com/repos/owner/repo",
            method="POST",
        )

        assert decision.blocked
        assert "POST" in decision.reason

    def test_http_blocked_wrong_path(self):
        """HTTP request with wrong path is blocked."""
        matcher = PolicyMatcher("https://api.github.com/repos/*")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_http(
            dst_ip="140.82.121.4",
            dst_port=443,
            url="https://api.github.com/users/octocat",
            method="GET",
        )

        assert decision.blocked


# =============================================================================
# PolicyEnforcer Tests - TCP
# =============================================================================


class TestEnforcerTCP:
    """Tests for raw TCP connection enforcement."""

    def test_tcp_allowed_via_dns_cache(self):
        """TCP connection allowed when DNS cache has hostname."""
        matcher = PolicyMatcher("github.com:22")
        dns_cache = DNSIPCache()
        dns_cache.add("140.82.121.4", "github.com", ttl=300)
        enforcer = PolicyEnforcer(matcher, dns_cache)

        decision = enforcer.check_tcp(
            dst_ip="140.82.121.4",
            dst_port=22,
        )

        assert decision.allowed
        assert "DNS cache" in decision.reason
        assert decision.hostname == "github.com"

    def test_tcp_blocked_without_dns_cache(self):
        """TCP connection blocked without DNS cache (no IP rule)."""
        matcher = PolicyMatcher("github.com:22")  # Host rule only
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_tcp(
            dst_ip="140.82.121.4",
            dst_port=22,
        )

        assert decision.blocked
        assert "no DNS correlation" in decision.reason

    def test_tcp_allowed_by_ip_rule(self):
        """TCP connection allowed by IP rule."""
        matcher = PolicyMatcher("140.82.121.4:22")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_tcp(
            dst_ip="140.82.121.4",
            dst_port=22,
        )

        assert decision.allowed

    def test_tcp_allowed_by_cidr_rule(self):
        """TCP connection allowed by CIDR rule."""
        matcher = PolicyMatcher("140.82.0.0/16:*")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_tcp(
            dst_ip="140.82.121.4",
            dst_port=22,
        )

        assert decision.allowed

    def test_tcp_dns_cache_wrong_port(self):
        """TCP connection blocked when DNS cache hostname doesn't match port."""
        matcher = PolicyMatcher("github.com:443")  # Only port 443
        dns_cache = DNSIPCache()
        dns_cache.add("140.82.121.4", "github.com", ttl=300)
        enforcer = PolicyEnforcer(matcher, dns_cache)

        decision = enforcer.check_tcp(
            dst_ip="140.82.121.4",
            dst_port=22,  # Port 22, not 443
        )

        assert decision.blocked


# =============================================================================
# PolicyEnforcer Tests - DNS
# =============================================================================


class TestEnforcerDNS:
    """Tests for DNS query enforcement."""

    def test_dns_allowed_by_host_rule(self):
        """DNS query for allowed hostname is allowed."""
        matcher = PolicyMatcher("github.com:53/udp")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_dns(
            dst_ip="8.8.8.8",
            dst_port=53,
            query_name="github.com",
        )

        assert decision.allowed
        assert decision.hostname == "github.com"

    def test_dns_allowed_by_wildcard(self):
        """DNS query matching wildcard is allowed."""
        matcher = PolicyMatcher("*.github.com:53/udp")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_dns(
            dst_ip="8.8.8.8",
            dst_port=53,
            query_name="api.github.com",
        )

        assert decision.allowed

    def test_dns_blocked_no_rule(self):
        """DNS query for unknown hostname is blocked."""
        matcher = PolicyMatcher("github.com:53/udp")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_dns(
            dst_ip="8.8.8.8",
            dst_port=53,
            query_name="evil.com",
        )

        assert decision.blocked
        assert "evil.com" in decision.reason


# =============================================================================
# PolicyEnforcer Tests - UDP
# =============================================================================


class TestEnforcerUDP:
    """Tests for UDP packet enforcement."""

    def test_udp_allowed_by_ip_rule(self):
        """UDP packet to allowed IP is allowed."""
        matcher = PolicyMatcher("8.8.8.8:53/udp")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_udp(
            dst_ip="8.8.8.8",
            dst_port=53,
        )

        assert decision.allowed

    def test_udp_blocked_wrong_port(self):
        """UDP packet to wrong port is blocked."""
        matcher = PolicyMatcher("8.8.8.8:53/udp")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_udp(
            dst_ip="8.8.8.8",
            dst_port=123,  # NTP, not DNS
        )

        assert decision.blocked

    def test_udp_blocked_tcp_rule(self):
        """UDP packet doesn't match TCP rule."""
        matcher = PolicyMatcher("8.8.8.8:53")  # TCP by default
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_udp(
            dst_ip="8.8.8.8",
            dst_port=53,
        )

        assert decision.blocked


# =============================================================================
# PolicyEnforcer Tests - Process Attributes
# =============================================================================


class TestEnforcerProcessInfo:
    """Tests for process attribute matching."""

    def test_exe_attribute_match(self):
        """Connection allowed when exe matches."""
        matcher = PolicyMatcher("github.com exe=/usr/bin/curl")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
            proc=ProcessInfo(exe="/usr/bin/curl"),
        )

        assert decision.allowed

    def test_exe_attribute_mismatch(self):
        """Connection blocked when exe doesn't match."""
        matcher = PolicyMatcher("github.com exe=/usr/bin/curl")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
            proc=ProcessInfo(exe="/usr/bin/wget"),
        )

        assert decision.blocked

    def test_exe_wildcard_match(self):
        """Connection allowed when exe matches wildcard."""
        matcher = PolicyMatcher("github.com exe=*/node")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
            proc=ProcessInfo(exe="/home/user/.nvm/versions/node/v18/bin/node"),
        )

        assert decision.allowed

    def test_step_attribute_match(self):
        """Connection allowed when step matches."""
        matcher = PolicyMatcher("github.com step=build.my-step")
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
            proc=ProcessInfo(step="build.my-step"),
        )

        assert decision.allowed


# =============================================================================
# PolicyEnforcer Tests - Audit Mode
# =============================================================================


class TestEnforcerAuditMode:
    """Tests for audit mode (log but don't block)."""

    def test_audit_mode_allows_blocked(self):
        """In audit mode, blocked connections are allowed with note."""
        matcher = PolicyMatcher("github.com")
        enforcer = PolicyEnforcer(matcher, audit_mode=True)

        decision = enforcer.check_https(
            dst_ip="93.184.216.34",
            dst_port=443,
            sni="example.com",  # Not in policy
        )

        assert decision.allowed  # Allowed in audit mode
        assert "[AUDIT]" in decision.reason
        assert "Would block" in decision.reason

    def test_audit_mode_normal_allows_unchanged(self):
        """In audit mode, allowed connections work normally."""
        matcher = PolicyMatcher("github.com")
        enforcer = PolicyEnforcer(matcher, audit_mode=True)

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
        )

        assert decision.allowed
        assert "[AUDIT]" not in decision.reason


# =============================================================================
# PolicyEnforcer Tests - DNS Response Recording
# =============================================================================


class TestEnforcerDNSRecording:
    """Tests for DNS response IP recording."""

    def test_record_dns_response(self):
        """Recording DNS response populates cache."""
        matcher = PolicyMatcher("github.com:22")
        enforcer = PolicyEnforcer(matcher)

        # Initially, TCP would be blocked
        decision = enforcer.check_tcp(dst_ip="140.82.121.4", dst_port=22)
        assert decision.blocked

        # Record DNS response
        enforcer.record_dns_response(
            query_name="github.com",
            ips=["140.82.121.4", "140.82.121.5"],
            ttl=300,
        )

        # Now TCP should be allowed
        decision = enforcer.check_tcp(dst_ip="140.82.121.4", dst_port=22)
        assert decision.allowed

        decision = enforcer.check_tcp(dst_ip="140.82.121.5", dst_port=22)
        assert decision.allowed

    def test_record_dns_response_empty_ips(self):
        """Recording empty IP list is a no-op."""
        matcher = PolicyMatcher("github.com")
        enforcer = PolicyEnforcer(matcher)

        # Should not raise
        enforcer.record_dns_response(query_name="github.com", ips=[], ttl=300)


# =============================================================================
# Complex Scenarios
# =============================================================================


class TestEnforcerComplexScenarios:
    """Tests for complex real-world scenarios."""

    def test_github_ssh_workflow(self):
        """Simulate GitHub SSH workflow: DNS then TCP."""
        policy = """
        github.com:443
        github.com:22
        *.github.com:443
        """
        matcher = PolicyMatcher(policy)
        enforcer = PolicyEnforcer(matcher)

        # 1. DNS query for github.com (would be handled separately)
        decision = enforcer.check_dns("8.8.8.8", 53, "github.com")
        # DNS check uses host rules, would need :53/udp rule
        # For this test, we're focusing on the TCP part

        # 2. Record DNS response
        enforcer.record_dns_response("github.com", ["140.82.121.4"], ttl=300)

        # 3. SSH connection using resolved IP
        decision = enforcer.check_tcp("140.82.121.4", 22)
        assert decision.allowed
        assert decision.hostname == "github.com"

    def test_api_with_path_restrictions(self):
        """API with path-based restrictions."""
        policy = """
        [https://api.github.com]
        GET /repos/*/releases
        POST /repos/*/issues
        """
        matcher = PolicyMatcher(policy)
        enforcer = PolicyEnforcer(matcher)

        # GET releases - allowed
        decision = enforcer.check_http(
            "140.82.121.4", 443,
            "https://api.github.com/repos/owner/releases",
            "GET",
        )
        assert decision.allowed

        # POST issues - allowed
        decision = enforcer.check_http(
            "140.82.121.4", 443,
            "https://api.github.com/repos/owner/issues",
            "POST",
        )
        assert decision.allowed

        # DELETE - blocked
        decision = enforcer.check_http(
            "140.82.121.4", 443,
            "https://api.github.com/repos/owner/issues/1",
            "DELETE",
        )
        assert decision.blocked

        # Wrong path - blocked
        decision = enforcer.check_http(
            "140.82.121.4", 443,
            "https://api.github.com/users/octocat",
            "GET",
        )
        assert decision.blocked

    def test_mixed_protocol_policy(self):
        """Policy with multiple protocols."""
        policy = """
        # HTTPS
        github.com
        *.github.com

        # DNS
        [:53/udp]
        8.8.8.8
        1.1.1.1

        # Internal network
        [:*]
        10.0.0.0/8
        """
        matcher = PolicyMatcher(policy)
        enforcer = PolicyEnforcer(matcher)

        # HTTPS to github
        decision = enforcer.check_https("140.82.121.4", 443, "github.com")
        assert decision.allowed

        # DNS to 8.8.8.8
        decision = enforcer.check_udp("8.8.8.8", 53)
        assert decision.allowed

        # TCP to internal network
        decision = enforcer.check_tcp("10.1.2.3", 8080)
        assert decision.allowed

        # Blocked: external IP not in policy
        decision = enforcer.check_tcp("93.184.216.34", 80)
        assert decision.blocked


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
