#!/bin/bash
# Cleanup iptables rules set by setup-proxy.sh
#
# Delegates to iptables.sh cleanup for single source of truth.
# Safe to run multiple times.

exec "$(dirname "$0")"/iptables.sh cleanup
