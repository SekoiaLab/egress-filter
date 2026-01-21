#!/bin/bash
# Setup transparent proxy with BPF PID tracking
#
# This script:
# 1. Starts unified_proxy.py (mitmproxy + nfqueue)
# 2. Configures iptables to redirect traffic through the proxy
# 3. Installs mitmproxy CA certificate system-wide
#
# Requirements:
# - Must run as root (for BPF and iptables)
# - unified_proxy.py must be in current directory
# - .venv with dependencies must exist

set -e

# Cleanup iptables on failure to avoid breaking runner communication
trap 'sudo "$(dirname "$0")"/iptables.sh cleanup' ERR

# Start unified proxy as root (needed for BPF), exclude root's traffic via iptables
# shellcheck disable=SC2024  # Redirect to /tmp intentionally uses current user perms
sudo env PROXY_LOG_FILE=/tmp/proxy.log \
  "$(pwd)"/.venv/bin/python unified_proxy.py > /tmp/proxy-stdout.log 2>&1 &
PROXY_PID=$!

# Wait for proxy to be listening
counter=0
while ! sudo ss -tln | grep -q ':8080 '; do
    sleep 1
    counter=$((counter+1))
    if ! sudo kill -0 $PROXY_PID 2>/dev/null; then
        echo "Proxy process died! Output:"
        cat /tmp/proxy-stdout.log || true
        exit 1
    fi
    if [ $counter -gt 10 ]; then
        echo "Timeout waiting for proxy"
        exit 1
    fi
done

# Setup iptables (rules defined in iptables.sh)
sudo "$(dirname "$0")"/iptables.sh setup

# Install mitmproxy certificate as system CA
sudo mkdir -p /usr/local/share/ca-certificates/extra
sudo openssl x509 -in /root/.mitmproxy/mitmproxy-ca-cert.pem -inform PEM -out /tmp/mitmproxy-ca-cert.crt 2>/dev/null
sudo cp /tmp/mitmproxy-ca-cert.crt /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.crt
sudo dpkg-reconfigure -p critical ca-certificates >/dev/null 2>&1
sudo update-ca-certificates >/dev/null 2>&1

# Set CA env vars for tools that don't use system store (copy to readable location)
sudo cp /root/.mitmproxy/mitmproxy-ca-cert.pem /tmp/mitmproxy-ca-cert.pem
sudo chmod 644 /tmp/mitmproxy-ca-cert.pem

# Export env vars (for GitHub Actions, write to GITHUB_ENV)
if [ -n "${GITHUB_ENV:-}" ]; then
    echo "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
    echo "REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
else
    export NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem
    export REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem
fi
