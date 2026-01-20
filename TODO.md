# TODO

## Done

- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)

## Next Steps

- [ ] Add comprehensive tests to workflow for all combinations:
  - Protocols: UDP, DNS, TCP, HTTP, HTTPS
  - Destinations: loopback (127.x), external IPs
  - Address types: IPv4, IPv4-mapped (::ffff:x.x.x.x), native IPv6
  - Proxy modes: redirected via iptables, direct request to mitmproxy
  - Goal: find bugs and unhandled cases in PID tracking
- [ ] Do something about non-DNS UDP traffic
