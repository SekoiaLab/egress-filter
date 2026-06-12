// SPDX-License-Identifier: GPL-2.0
//
// conn_tracker.bpf.c - Track connections to PID mapping for egress firewall
//
// Provides 4-tuple→PID correlation for mitmproxy to attribute connections
// to processes. IPv4 only - all IPv6 is blocked to force apps through
// the transparent proxy (IPv6 would bypass iptables REDIRECT).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// ============================================
// Data structures
// ============================================

struct conn_key_v4 {
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;
    u8  pad[3];
} __attribute__((packed));

// ============================================
// Maps
// ============================================

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct conn_key_v4);
    __type(value, u32);
    __uint(max_entries, 65536);
} conn_to_pid_v4 SEC(".maps");

// ============================================
// IPv6 blocking
// ============================================
// Block ALL IPv6 connections (including IPv4-mapped ::ffff:x.x.x.x).
// This forces apps to use AF_INET sockets, which go through our
// transparent proxy via iptables REDIRECT.

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx) {
    return 0;  // Block
}

SEC("cgroup/sendmsg6")
int block_sendmsg6(struct bpf_sock_addr *ctx) {
    return 0;  // Block
}

// ============================================
// Raw socket blocking
// ============================================
// Block raw sockets to prevent iptables bypass. Without this, processes
// with CAP_NET_RAW can craft packets that skip our transparent proxy:
//
// - SOCK_RAW: Can craft IP packets, bypasses iptables in some cases
// - AF_PACKET: Operates at Layer 2, completely bypasses iptables
//
// This hook fires on socket() syscall for all processes in the cgroup.

SEC("cgroup/sock_create")
int block_raw_sockets(struct bpf_sock *sk) {
    if (!sk)
        return 1;  // Allow (shouldn't happen)

    // Block AF_PACKET entirely - Layer 2 access bypasses all IP filtering
    if (sk->family == AF_PACKET)
        return 0;  // Block

    // Block SOCK_RAW for any protocol - prevents IP header manipulation
    if (sk->type == SOCK_RAW)
        return 0;  // Block

    return 1;  // Allow
}

// ============================================
// TCP: kprobe/tcp_connect
// ============================================
// Why kprobe instead of cgroup/connect4?
//
// Investigation confirmed: cgroup hooks DO fire for all processes including
// containers (cgroups are orthogonal to network namespaces), but at connect()
// time the kernel hasn't assigned the ephemeral source port yet (src_port=0).
// Since we need src_port for the 4-tuple key, cgroup/connect4 can't be used.
//
// The kprobe fires later in the connection sequence, after the kernel has
// assigned the ephemeral port.

SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    if (!sk)
        return 0;

    // Only track IPv4 (IPv6 is blocked by cgroup hooks)
    u16 family;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    u16 src_port;
    BPF_CORE_READ_INTO(&src_port, sk, __sk_common.skc_num);
    if (src_port == 0)
        return 0;

    u32 dst_ip;
    u16 dst_port;
    BPF_CORE_READ_INTO(&dst_ip, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);

    if (dst_ip == 0)
        return 0;

    struct conn_key_v4 key = {
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = bpf_ntohs(dst_port),
        .protocol = IPPROTO_TCP,
    };
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);

    return 0;
}

// ============================================
// UDP: kprobe
// ============================================
// We use kprobe instead of cgroup hooks for UDP because:
//
// 1. cgroup/sendmsg4 doesn't work for connected UDP sockets.
//    When send() is called without a destination (connected socket),
//    user_ip4 is 0. We tried falling back to ctx->sk but it doesn't
//    contain the connected destination.
//
// 2. cgroup/connect4 can't help because at connect() time for UDP,
//    the socket isn't bound yet - src_port is 0. The ephemeral port
//    is only assigned when actually sending data.
//
// 3. Dual-hook approach (connect4 stores cookie->dest, sendmsg4 completes)
//    was tested but TCP tracking broke for host processes while Docker
//    containers still worked. Root cause unknown.
//
// The kprobe fires after the socket is bound and has access to both
// msg_name (for sendto) and socket state (for connected sockets).

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!sk)
        return 0;

    // Only track IPv4 (IPv6 is blocked by cgroup/sendmsg6)
    u16 family;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    u16 src_port;
    BPF_CORE_READ_INTO(&src_port, sk, __sk_common.skc_num);
    if (src_port == 0)
        return 0;

    u32 dst_ip = 0;
    u16 dst_port = 0;

    // Get destination from msg_name (unconnected) or socket (connected)
    struct sockaddr_in *sin = NULL;
    if (msg)
        BPF_CORE_READ_INTO(&sin, msg, msg_name);

    if (sin) {
        bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &sin->sin_addr.s_addr);
        bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sin->sin_port);
    } else {
        BPF_CORE_READ_INTO(&dst_ip, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    }

    if (dst_ip == 0)
        return 0;

    struct conn_key_v4 key = {
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = bpf_ntohs(dst_port),
        .protocol = IPPROTO_UDP,
    };
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&conn_to_pid_v4, &key, &pid, BPF_ANY);

    return 0;
}

// ============================================
// NAT source-port reversal: cgroup_skb/egress
// ============================================
// iptables REDIRECT (DNAT to the proxy) collapses every destination onto the
// single proxy socket :8080. Under load, netfilter remaps colliding source
// ports, so the port the proxy sees (peername) differs from the original
// ephemeral port the tcp_connect kprobe recorded as the map key — the proxy's
// lookup then misses and the connection can't be attributed.
//
// This egress hook runs after NAT (in ip_finish_output, past POSTROUTING), so
// the packet carries the post-NAT (possibly mangled) source port, while
// skb->sk still holds the original socket tuple (NAT rewrites the packet, not
// the socket). On the SYN, when the two differ, we look up the PID already
// stored under the original key (by tcp_connect) and add a second entry under
// the post-NAT key, so the proxy's existing lookup hits directly. No userspace
// changes are needed.
//
// We avoid reading conntrack structs: nf_conn isn't in the kernel BTF here
// (conntrack is a module), so CO-RE can't traverse it. Everything we need is
// in struct bpf_sock and the packet headers.

SEC("cgroup_skb/egress")
int rekey_nat_egress(struct __sk_buff *skb) {
    // cgroup_skb must return 1 (allow); 0 would drop the packet.
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 1;
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP)
        return 1;

    u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return 1;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return 1;
    if (!tcp->syn)  // only act once, on connection setup
        return 1;

    // skb->sk is exposed as sock_common; promote to a full socket so the
    // verifier lets us read protocol / addresses / ports.
    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return 1;
    sk = bpf_sk_fullsock(sk);
    if (!sk || sk->protocol != IPPROTO_TCP)
        return 1;

    // Original tuple from the socket (NAT didn't touch it).
    u32 orig_dst_ip = sk->dst_ip4;             // network order
    u16 orig_dst_port = bpf_ntohs(sk->dst_port);  // dst_port is network order
    u16 orig_src_port = sk->src_port;          // already host order
    // Post-NAT source port from the packet.
    u16 nat_src_port = bpf_ntohs(tcp->source);

    if (nat_src_port == orig_src_port || orig_dst_ip == 0)
        return 1;  // not mangled

    struct conn_key_v4 orig_key = {
        .dst_ip = orig_dst_ip,
        .src_port = orig_src_port,
        .dst_port = orig_dst_port,
        .protocol = IPPROTO_TCP,
    };
    u32 *pid = bpf_map_lookup_elem(&conn_to_pid_v4, &orig_key);
    if (!pid)
        return 1;  // not a connection we tracked

    struct conn_key_v4 nat_key = {
        .dst_ip = orig_dst_ip,
        .src_port = nat_src_port,
        .dst_port = orig_dst_port,
        .protocol = IPPROTO_TCP,
    };
    u32 val = *pid;
    bpf_map_update_elem(&conn_to_pid_v4, &nat_key, &val, BPF_ANY);

    return 1;
}

char LICENSE[] SEC("license") = "GPL";
