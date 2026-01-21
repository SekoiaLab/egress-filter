#!/bin/bash
# Setup transparent proxy with BPF PID tracking (GitHub Actions only)
#
# This script:
# 1. Starts unified_proxy.py (mitmproxy + nfqueue)
# 2. Configures iptables to redirect traffic through the proxy
# 3. Installs mitmproxy CA certificate system-wide
#
# Must run as root.

set -e

[[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }

# Cleanup iptables on failure to avoid breaking runner communication
trap '"$(dirname "$0")"/iptables.sh cleanup' ERR

# Start unified proxy (exclude root's traffic via iptables to prevent loops)
env PROXY_LOG_FILE=/tmp/proxy.log \
  "$(pwd)"/.venv/bin/python unified_proxy.py > /tmp/proxy-stdout.log 2>&1 &
PROXY_PID=$!

# Wait for proxy to be listening
counter=0
while ! ss -tln | grep -q ':8080 '; do
    sleep 1
    counter=$((counter+1))
    if ! kill -0 $PROXY_PID 2>/dev/null; then
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
"$(dirname "$0")"/iptables.sh setup

# Install mitmproxy certificate as system CA
mkdir -p /usr/local/share/ca-certificates/extra
openssl x509 -in /root/.mitmproxy/mitmproxy-ca-cert.pem -inform PEM -out /tmp/mitmproxy-ca-cert.crt 2>/dev/null
cp /tmp/mitmproxy-ca-cert.crt /usr/local/share/ca-certificates/extra/mitmproxy-ca-cert.crt
dpkg-reconfigure -p critical ca-certificates >/dev/null 2>&1
update-ca-certificates >/dev/null 2>&1

# Set CA env vars for tools that don't use system store (copy to readable location)
cp /root/.mitmproxy/mitmproxy-ca-cert.pem /tmp/mitmproxy-ca-cert.pem
chmod 644 /tmp/mitmproxy-ca-cert.pem

# Set CA env vars for subsequent steps
echo "NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
echo "REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca-cert.pem" >> "$GITHUB_ENV"
