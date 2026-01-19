// SPDX-License-Identifier: GPL-2.0
//
// ipv6_blocker.bpf.c - Block native IPv6 connections
//
// Security-focused convenience: blocks native IPv6 to simplify threat analysis
// (IPv6 has less threat intel coverage). IPv4-mapped addresses are allowed.
//

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Config flags
#define CFG_BLOCK_IPV6 0

// ============================================
// Maps
// ============================================

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 1);
} config SEC(".maps");

// ============================================
// Helpers
// ============================================

static __always_inline bool is_v4_mapped(u32 *ip6) {
    // ::ffff:x.x.x.x
    return ip6[0] == 0 &&
           ip6[1] == 0 &&
           ip6[2] == bpf_htonl(0x0000ffff);
}

static __always_inline bool ipv6_blocked(void) {
    u32 key = CFG_BLOCK_IPV6;
    u8 *val = bpf_map_lookup_elem(&config, &key);
    return val && *val;
}

// ============================================
// TCP: connect6
// ============================================

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx) {
    // v4-mapped: allow
    if (is_v4_mapped(ctx->user_ip6))
        return 1;

    // Native IPv6: block if configured
    if (ipv6_blocked())
        return 0;

    return 1;
}

// ============================================
// UDP: sendmsg6
// ============================================

SEC("cgroup/sendmsg6")
int block_sendmsg6(struct bpf_sock_addr *ctx) {
    // v4-mapped: allow
    if (is_v4_mapped(ctx->user_ip6))
        return 1;

    // Native IPv6: block if configured
    if (ipv6_blocked())
        return 0;

    return 1;
}

char LICENSE[] SEC("license") = "GPL";
