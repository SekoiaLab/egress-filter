// SPDX-License-Identifier: GPL-2.0
//
// ipv6_blocker.bpf.c - Block ALL IPv6 connections (including IPv4-mapped)
//
// Blocks all AF_INET6 socket connections to ensure traffic goes through
// our transparent proxy. IPv4-mapped addresses (::ffff:x.x.x.x) bypass
// iptables REDIRECT, so we block them to force apps to use AF_INET sockets.
//

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// ============================================
// TCP: connect6 - block all
// ============================================

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx) {
    return 0;  // Block all IPv6 (native and v4-mapped)
}

// ============================================
// UDP: sendmsg6 - block all
// ============================================

SEC("cgroup/sendmsg6")
int block_sendmsg6(struct bpf_sock_addr *ctx) {
    return 0;  // Block all IPv6 (native and v4-mapped)
}

char LICENSE[] SEC("license") = "GPL";
