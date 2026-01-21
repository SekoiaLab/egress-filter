# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Session Start

At the start of each session, read and display the contents of `TODO.md` to remind the user of pending tasks.

## Project Overview

eBPF-based connection-to-PID tracker integrated with mitmproxy transparent proxy. Attributes every network connection to the process that made it.

## Key Files

- `unified_proxy.py` - mitmproxy addon with BPF-based PID tracking + nfqueue UDP handler
- `src/bpf/port_tracker.bpf.c` - BPF program for connection tracking + IPv6 blocking
- `scripts/setup-proxy.sh` - Setup transparent proxy with iptables
- `scripts/test-connectivity.sh` - Basic connectivity tests
- `scripts/cleanup-iptables.sh` - Cleanup iptables rules
- `.github/workflows/test-transparent-proxy.yml` - CI workflow

## How It Works

1. BPF program attaches to cgroup and tracks TCP connections via `sockops` hook
2. When a connection is made, BPF records `(dst_ip, src_port, dst_port)` → PID in an LRU hash map
3. mitmproxy in transparent mode intercepts traffic via iptables REDIRECT
4. unified_proxy.py looks up the PID from BPF maps for each connection and logs it

## Running the Workflow

The workflow runs on `workflow_dispatch` (manual trigger):

```bash
gh workflow run test-transparent-proxy.yml
```

## Local Development

```bash
# Install dependencies
uv sync

# Compile BPF (requires Docker)
uv run tinybpf docker-compile src/bpf/port_tracker.bpf.c

# Run proxy (requires root for BPF)
sudo .venv/bin/python unified_proxy.py
```

## BPF Map Structure

```python
class ConnKeyV4(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]
```

## Supported Runners

This action only supports **GitHub-hosted Ubuntu runners**. Self-hosted runners are not supported.

Current support:
- `ubuntu-latest` (currently Ubuntu 24.04, x64)

Planned expansion:
1. ARM64 runners (ubuntu-24.04-arm)
2. Previous Ubuntu releases (ubuntu-22.04)

### GitHub Actions Environment Variables

- `ImageOS`: Runner image identifier (e.g., `ubuntu24`, `ubuntu22`). Used for platform detection and cache keys.
- `process.arch`: Node.js architecture (`x64`, `arm64`). Used in cache keys.

Cache key format: `egress-filter-venv-${ImageOS}-${arch}-${lockHash}`

The `.deb` packages in `setup-proxy.sh` are hardcoded to Ubuntu 24.04 amd64. When adding ARM64 or other Ubuntu versions, these URLs need architecture/version-specific variants.

## Dependencies

- tinybpf (from git) - BPF loading and map access
- mitmproxy - transparent proxy

See `pyproject.toml` for full dependency list.
