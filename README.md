# Egress Filter

A GitHub Action that monitors and attributes all network egress to the processes that made them, using eBPF-based connection tracking and a transparent proxy.

## Usage

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: gregclermont/egress-filter@main

      - uses: actions/checkout@v4

      # Your build steps here - all network traffic is monitored
      - run: npm install
      - run: npm test
```

## How It Works

1. **eBPF tracking**: A BPF program attaches to the cgroup and tracks TCP/UDP connections, mapping `(dst_ip, src_port, dst_port)` to PID
2. **Transparent proxy**: mitmproxy intercepts all HTTP/HTTPS/DNS traffic via iptables REDIRECT
3. **PID attribution**: Each request is logged with the process that made it

## Requirements

- **GitHub-hosted Ubuntu runners only** (ubuntu-latest, ubuntu-24.04)
- Self-hosted runners are not supported

## Logs

Network activity is logged to `/tmp/proxy.log`:

```
HTTP src_port=54321 dst=example.com:443 url=https://example.com/api pid=1234 comm=curl
DNS src_port=45678 dst=8.8.8.8:53 name=example.com txid=12345 pid=1234 comm=curl
```

## License

MIT
