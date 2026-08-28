// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

// Keep BPF tests close to production code size by default.
// Enable verbose debug output only when explicitly requested via CFLAGS:
//   -D__BPF_TEST_ENABLE_DEBUG
#ifdef __BPF_TEST_ENABLE_DEBUG
#define __DEBUG
#define __DEBUG_ROUTING
#define __PRINT_ROUTING_RESULT
#endif
#define __BPF_TEST_DISABLE_LPM_CACHE  // Disable LPM cache in test mode

#include "../tproxy.c"
#include "./bpf_test.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map SEC(".maps") = {
	.values = {
		[0] = &tproxy_wan_egress_l2,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct domain_routing);
	__uint(max_entries, 1);
} test_domain_routing_scratch_map SEC(".maps");

struct test_routing_cache_ctx {
	struct tuples_key key;
	struct routing_result result;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct test_routing_cache_ctx);
	__uint(max_entries, 1);
} test_routing_cache_ctx_map SEC(".maps");

// Scratch storage for writing conn_state_map entries without placing a
// ~56-byte struct on the BPF stack, which would push multi-call setup
// programs such as testsetup_wan_tcp_cached_outbound_survives_connectivity_change
// past the 512-byte verifier limit on older (5.x) kernels.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct conn_state);
	__uint(max_entries, 1);
} test_conn_state_scratch_map SEC(".maps");

static __always_inline int
setup_cached_routing_result_for_proto(__u32 saddr, __u32 daddr,
				      __u16 sport, __u16 dport,
				      __u8 l4proto, __u8 outbound,
				      __u32 mark)
{
	struct test_routing_cache_ctx *ctx =
		bpf_map_lookup_elem(&test_routing_cache_ctx_map, &zero_key);

	if (!ctx)
		return TC_ACT_SHOT;

	__builtin_memset(ctx, 0, sizeof(*ctx));
	ctx->key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	ctx->key.sip.u6_addr32[3] = bpf_htonl(saddr);
	ctx->key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	ctx->key.dip.u6_addr32[3] = bpf_htonl(daddr);
	ctx->key.sport = bpf_htons(sport);
	ctx->key.dport = bpf_htons(dport);
	ctx->key.l4proto = l4proto;
	ctx->result.outbound = outbound;
	ctx->result.mark = mark;

	// Scheme3: Store routing result in conn_state_map instead of routing_tuples_map.
	// Use a percpu scratch map value instead of a stack-local struct, otherwise
	// deep call chains (setup -> do_tproxy_wan_egress -> ...) blow past the
	// 512-byte stack limit on 5.x kernels.
	struct conn_state *conn_state =
		bpf_map_lookup_elem(&test_conn_state_scratch_map, &zero_key);

	if (!conn_state)
		return TC_ACT_SHOT;
	__builtin_memset(conn_state, 0, sizeof(*conn_state));

	conn_state->is_wan_ingress_direction = false;
	conn_state->state = TCP_STATE_ACTIVE;
	conn_state->last_seen_ns = bpf_ktime_get_ns();
	conn_state->meta.data.has_routing = 1;
	conn_state->meta.data.outbound = outbound;
	conn_state->meta.data.mark = mark;
	conn_state->meta.data.must = 0;

	return bpf_map_update_elem(&conn_state_map, &ctx->key, conn_state, BPF_ANY);
}

static __always_inline int
setup_cached_routing_result(__u32 saddr, __u32 daddr,
			    __u16 sport, __u16 dport,
			    __u8 outbound, __u32 mark)
{
	return setup_cached_routing_result_for_proto(saddr, daddr, sport, dport,
					     IPPROTO_TCP, outbound, mark);
}

static __always_inline int
set_test_outbound_connectivity(__u8 outbound, __u8 l4proto, __u32 alive)
{
	__u32 domain_idx = l4proto == IPPROTO_UDP ? 2 : 0;
	__u32 key = ((__u32)outbound * 6) + (domain_idx * 2);

	return bpf_map_update_elem(&outbound_connectivity_map, &key, &alive,
				   BPF_ANY);
}

static __always_inline int
set_routing_epoch_port_rule(__u32 slot, __u16 port, __u8 outbound)
{
	struct match_set match_set = {};
	struct port_range port_range = {port, port};
	__u32 routing_key = slot * MAX_MATCH_SET_LEN;
	__u32 rules_len = 1;

	if (slot >= ROUTING_EPOCH_SLOT_NUM)
		return TC_ACT_SHOT;

	match_set.port_range = port_range;
	match_set.type = MatchType_Port;
	match_set.outbound = outbound;

	if (bpf_map_update_elem(&routing_map, &routing_key, &match_set, BPF_ANY))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&routing_meta_map, &slot, &rules_len, BPF_ANY))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
setup_routing_epoch_lan_ingress(struct __sk_buff *skb, __u32 active_slot)
{
	__u32 slot_zero = 0;
	int ret;

	if (set_routing_epoch_port_rule(0, 443, OUTBOUND_USER_DEFINED_MIN))
		return TC_ACT_SHOT;
	if (set_routing_epoch_port_rule(1, 443,
					OUTBOUND_USER_DEFINED_MIN + 1))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&active_slot, BPF_ANY))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&slot_zero, BPF_ANY))
		return TC_ACT_SHOT;
	return ret;
}

static __always_inline int
set_routing_epoch_domain_rule(__u32 slot, __u8 outbound, __u32 bitmap)
{
	struct match_set domain_rule = {};
	struct match_set fallback_rule = {};
	struct routing_epoch_ip ip_key = {};
	struct domain_routing *projection;
	__u32 scratch_key = 0;
	__u32 domain_key = slot * MAX_MATCH_SET_LEN;
	__u32 fallback_key = domain_key + 1;
	__u32 rules_len = 2;

	if (slot >= ROUTING_EPOCH_SLOT_NUM)
		return TC_ACT_SHOT;

	domain_rule.type = MatchType_DomainSet;
	domain_rule.outbound = outbound;
	if (bpf_map_update_elem(&routing_map, &domain_key, &domain_rule,
				BPF_ANY))
		return TC_ACT_SHOT;

	fallback_rule.type = MatchType_Fallback;
	fallback_rule.outbound = OUTBOUND_USER_DEFINED_MIN + 2;
	if (bpf_map_update_elem(&routing_map, &fallback_key, &fallback_rule,
				BPF_ANY))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&routing_meta_map, &slot, &rules_len,
				BPF_ANY))
		return TC_ACT_SHOT;

	// The packet generator below targets 198.51.100.20.
	ip_key.slot = slot;
	ip_key.addr[2] = bpf_htonl(0xffff);
	ip_key.addr[3] = bpf_htonl(0xc6336414);
	projection = bpf_map_lookup_elem(&test_domain_routing_scratch_map,
					 &scratch_key);
	if (!projection)
		return TC_ACT_SHOT;
	__builtin_memset(projection, 0, sizeof(*projection));
	projection->bitmap[0] = bitmap;
	return bpf_map_update_elem(&domain_routing_map, &ip_key, projection,
				   BPF_ANY);
}

static __always_inline int
setup_routing_epoch_domain_lan_ingress(struct __sk_buff *skb,
				       __u32 active_slot)
{
	__u32 zero_key = 0;
	int ret;

	// Only slot zero projects this destination into the domain rule.
	if (set_routing_epoch_domain_rule(0, OUTBOUND_USER_DEFINED_MIN, 1))
		return TC_ACT_SHOT;
	if (set_routing_epoch_domain_rule(1, OUTBOUND_USER_DEFINED_MIN + 1, 0))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&active_slot, BPF_ANY))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	zero_key = 0;
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&zero_key, BPF_ANY))
		return TC_ACT_SHOT;
	return ret;
}

static __always_inline int
check_routing_epoch_lan_ingress(struct __sk_buff *skb,
				__u32 expected_status_code,
				__u32 saddr, __u32 daddr,
				__u16 sport, __u16 dport,
				__u8 expected_outbound,
				__u8 expected_epoch_slot)
{
	struct tuples_key key = {};
	struct conn_state *conn_state;
	struct routing_handoff_entry *handoff;

	if (check_tcp_conn_state_ipv4_tcp(skb, expected_status_code,
					  saddr, daddr, sport, dport,
					  expected_outbound, 0, true))
		return TC_ACT_SHOT;

	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_TCP;

	conn_state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!conn_state || conn_state->routing_epoch_slot != expected_epoch_slot ||
	    conn_state->datapath_generation != PARAM.datapath_generation) {
		bpf_printk("conn_state routing epoch slot mismatch\n");
		return TC_ACT_SHOT;
	}

	handoff = bpf_map_lookup_elem(&routing_handoff_map, &key);
	if (!handoff || handoff->result.outbound != expected_outbound ||
	    handoff->result.routing_epoch_slot != expected_epoch_slot ||
	    handoff->result.datapath_generation != PARAM.datapath_generation) {
		bpf_printk("routing handoff epoch attribution mismatch\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/pktgen/dport_match")
int testpktgen_dport_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/dport_match")
int testsetup_dport_match(struct __sk_buff *skb)
{
	/* dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dport_match")
int testcheck_dport_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/dport_mismatch")
int testpktgen_dport_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/dport_mismatch")
int testsetup_dport_mismatch(struct __sk_buff *skb)
{
	/* dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dport_mismatch")
int testcheck_dport_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipset_match")
int testpktgen_ipset_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(100,64,0,2), 19233, 80);
}

SEC("tc/setup/ipset_match")
int testsetup_ipset_match(struct __sk_buff *skb)
{
	/* dip(100.64.0.0/16) -> direct */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x64400000); // 100.64.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_match")
int testcheck_ipset_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(100,64,0,2),
				      19233, 80);
}

SEC("tc/pktgen/ipset_mismatch")
int testpktgen_ipset_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(100,65,0,2), 19233, 80);
}

SEC("tc/setup/ipset_mismatch")
int testsetup_ipset_mismatch(struct __sk_buff *skb)
{
	// dip(100.64.0.0/16) -> direct
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x64400000); // 100.64.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_mismatch")
int testcheck_ipset_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(100,65,0,2),
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_match")
int testpktgen_source_ipset_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,50,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/source_ipset_match")
int testsetup_source_ipset_match(struct __sk_buff *skb)
{
	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_SourceIpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 120,
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xc0a83200); // 192.168.50.0
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/source_ipset_match")
int testcheck_source_ipset_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,50,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_mismatch")
int testpktgen_source_ipset_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,51,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/source_ipset_mismatch")
int testsetup_source_ipset_mismatch(struct __sk_buff *skb)
{
	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_SourceIpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 120,
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xc0a83200); // 192.168.50.0
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/source_ipset_mismatch")
int testcheck_source_ipset_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,51,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/sport_match")
int testpktgen_sport_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/sport_match")
int testsetup_sport_match(struct __sk_buff *skb)
{
	/* sport(19000-20000) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {19000, 20000};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_SourcePort;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/sport_match")
int testcheck_sport_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/sport_mismatch")
int testpktgen_sport_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/sport_mismatch")
int testsetup_sport_mismatch(struct __sk_buff *skb)
{
	/* sport(19230-19232) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {19230, 19232};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_SourcePort;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/sport_mismatch")
int testcheck_sport_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/tcp_non_syn_mark_restore")
int testpktgen_tcp_non_syn_mark_restore(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,0,1), IPV4(1,1,1,1),
				       19233, 80,
				       false, true, true);
}

SEC("tc/setup/tcp_non_syn_mark_restore")
int testsetup_tcp_non_syn_mark_restore(struct __sk_buff *skb)
{
	int ret = setup_cached_routing_result(IPV4(192,168,0,1), IPV4(1,1,1,1),
					      19233, 80, 0, TPROXY_MARK);

	if (ret)
		return TC_ACT_SHOT;

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/tcp_non_syn_mark_restore")
int testcheck_tcp_non_syn_mark_restore(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, TPROXY_MARK);
}

SEC("tc/pktgen/tcp_non_syn_cached_proxy_redirect")
int testpktgen_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,0,1), IPV4(8,8,8,8),
				       23456, 443,
				       false, true, false);
}

SEC("tc/setup/tcp_non_syn_cached_proxy_redirect")
int testsetup_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	int ret = setup_cached_routing_result(IPV4(192,168,0,1), IPV4(8,8,8,8),
					      23456, 443,
					      OUTBOUND_USER_DEFINED_MIN,
					      TPROXY_MARK);

	if (ret)
		return TC_ACT_SHOT;

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/tcp_non_syn_cached_proxy_redirect")
int testcheck_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	return check_redirect_non_syn_tcp(skb);
}

SEC("tc/pktgen/tcp_non_syn_stateless_passthrough")
int testpktgen_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,0,1), IPV4(8,8,4,4),
				       23456, 443,
				       false, true, true);
}

SEC("tc/setup/tcp_non_syn_stateless_passthrough")
int testsetup_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/tcp_non_syn_stateless_passthrough")
int testcheck_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/wan_egress_tcp_non_syn_cached_proxy_redirect")
int testpktgen_wan_egress_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,10,1), IPV4(9,9,9,9),
				       34567, 443,
				       false, true, false);
}

SEC("tc/setup/wan_egress_tcp_non_syn_cached_proxy_redirect")
int testsetup_wan_egress_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	int ret = setup_cached_routing_result(IPV4(192,168,10,1), IPV4(9,9,9,9),
					      34567, 443,
					      OUTBOUND_USER_DEFINED_MIN,
					      TPROXY_MARK);

	if (ret)
		return TC_ACT_SHOT;

	return do_tproxy_wan_egress(skb, 14);
}

SEC("tc/check/wan_egress_tcp_non_syn_cached_proxy_redirect")
int testcheck_wan_egress_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	return check_redirect_non_syn_tcp(skb);
}

SEC("tc/pktgen/wan_egress_tcp_non_syn_stateless_passthrough")
int testpktgen_wan_egress_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,10,2), IPV4(9,9,9,10),
				       34568, 443,
				       false, true, true);
}

SEC("tc/setup/wan_egress_tcp_non_syn_stateless_passthrough")
int testsetup_wan_egress_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_wan_egress(skb, 14);
}

SEC("tc/check/wan_egress_tcp_non_syn_stateless_passthrough")
int testcheck_wan_egress_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_PIPE, 0);
}

SEC("tc/pktgen/wan_egress_tcp_syn_redirect_track")
int testpktgen_wan_egress_tcp_syn_redirect_track(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,10,3), IPV4(9,9,9,11),
			    34569, 443);
}

SEC("tc/setup/wan_egress_tcp_syn_redirect_track")
int testsetup_wan_egress_tcp_syn_redirect_track(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_tcp_syn_redirect_track")
int testcheck_wan_egress_tcp_syn_redirect_track(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto_and_track_ipv4(skb,
								   IPPROTO_TCP,
								   1);
}

SEC("tc/pktgen/wan_egress_udp_redirect_track")
int testpktgen_wan_egress_udp_redirect_track(struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(skb,
					   IPV4(192,168,10,3), IPV4(9,9,9,11),
					   34569, 443, 0);
}

SEC("tc/setup/wan_egress_udp_redirect_track")
int testsetup_wan_egress_udp_redirect_track(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_udp_redirect_track")
int testcheck_wan_egress_udp_redirect_track(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto_and_track_ipv4(skb,
								   IPPROTO_UDP,
								   1);
}

SEC("tc/pktgen/tcp_active_idle_state_retained")
int testpktgen_tcp_active_idle_state_retained(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,20,1), IPV4(10,20,0,1),
			    41000, 443);
}

SEC("tc/setup/tcp_active_idle_state_retained")
int testsetup_tcp_active_idle_state_retained(struct __sk_buff *skb)
{
	struct conn_state state = {};
	(void)skb;

	state.state = TCP_STATE_ACTIVE;
	state.last_seen_ns = 1;
	if (tcp_conn_state_expired(&state, 120000000002ULL))
		return TC_ACT_SHOT;

	state.state = TCP_STATE_CLOSING;
	if (tcp_conn_state_expired(
		    &state, state.last_seen_ns + TCP_CONN_STATE_CLOSING_TIMEOUT_NS))
		return TC_ACT_SHOT;
	if (!tcp_conn_state_expired(
		    &state,
		    state.last_seen_ns + TCP_CONN_STATE_CLOSING_TIMEOUT_NS + 1))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

SEC("tc/check/tcp_active_idle_state_retained")
int testcheck_tcp_active_idle_state_retained(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/tcp_pure_syn_replaces_stale_state")
int testpktgen_tcp_pure_syn_replaces_stale_state(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,20,2), IPV4(10,20,0,2),
			    41001, 443);
}

SEC("tc/setup/tcp_pure_syn_replaces_stale_state")
int testsetup_tcp_pure_syn_replaces_stale_state(struct __sk_buff *skb)
{
	struct tuples_key key = {};
	struct conn_state stale_state = {};
	struct tcphdr tcph = {};
	struct conn_state *new_state;
	(void)skb;

	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,20,2));
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(10,20,0,2));
	key.sport = bpf_htons(41001);
	key.dport = bpf_htons(443);
	key.l4proto = IPPROTO_TCP;
	stale_state.state = TCP_STATE_ACTIVE;
	stale_state.last_seen_ns = 1;
	stale_state.meta.data.has_routing = 1;
	stale_state.meta.data.outbound = OUTBOUND_USER_DEFINED_MIN;
	if (bpf_map_update_elem(&conn_state_map, &key, &stale_state, BPF_ANY))
		return TC_ACT_SHOT;

	tcph.syn = 1;
	new_state = mark_tcp_seen(&key, &tcph, false,
				  NULL, NULL, NULL, NULL,
				  0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	if (!new_state || new_state->meta.data.has_routing ||
	    new_state->state != TCP_STATE_ACTIVE)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

SEC("tc/check/tcp_pure_syn_replaces_stale_state")
int testcheck_tcp_pure_syn_replaces_stale_state(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/lan_tcp_cached_outbound_survives_connectivity_change")
int testpktgen_lan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,20,3), IPV4(10,20,0,3),
				       41002, 443,
				       false, true, false);
}

SEC("tc/setup/lan_tcp_cached_outbound_survives_connectivity_change")
int testsetup_lan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result(IPV4(192,168,20,3),
					  IPV4(10,20,0,3), 41002, 443,
					  outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_TCP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/lan_tcp_cached_outbound_survives_connectivity_change")
int testcheck_lan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return check_redirect_non_syn_tcp(skb);
}

SEC("tc/pktgen/wan_tcp_cached_outbound_survives_connectivity_change")
int testpktgen_wan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,20,4), IPV4(10,20,0,4),
				       41003, 443,
				       false, true, false);
}

SEC("tc/setup/wan_tcp_cached_outbound_survives_connectivity_change")
int testsetup_wan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result(IPV4(192,168,20,4),
					  IPV4(10,20,0,4), 41003, 443,
					  outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_TCP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_tcp_cached_outbound_survives_connectivity_change")
int testcheck_wan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return check_redirect_non_syn_tcp(skb);
}

SEC("tc/pktgen/lan_udp_cached_outbound_survives_connectivity_change")
int testpktgen_lan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,20,5), IPV4(10,20,0,5), 41004, 8443, 0);
}

SEC("tc/setup/lan_udp_cached_outbound_survives_connectivity_change")
int testsetup_lan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result_for_proto(
		IPV4(192,168,20,5), IPV4(10,20,0,5), 41004, 8443,
		IPPROTO_UDP, outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_UDP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/lan_udp_cached_outbound_survives_connectivity_change")
int testcheck_lan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_UDP);
}

SEC("tc/pktgen/wan_udp_cached_outbound_survives_connectivity_change")
int testpktgen_wan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,20,6), IPV4(10,20,0,6), 41005, 8443, 0);
}

SEC("tc/setup/wan_udp_cached_outbound_survives_connectivity_change")
int testsetup_wan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result_for_proto(
		IPV4(192,168,20,6), IPV4(10,20,0,6), 41005, 8443,
		IPPROTO_UDP, outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_UDP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_udp_cached_outbound_survives_connectivity_change")
int testcheck_wan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto_and_track_ipv4(
		skb, IPPROTO_UDP, 1);
}

SEC("tc/pktgen/wan_tcp_new_outbound_obeys_connectivity_change")
int testpktgen_wan_tcp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,20,7), IPV4(10,20,0,7),
			    41006, 443);
}

SEC("tc/setup/wan_tcp_new_outbound_obeys_connectivity_change")
int testsetup_wan_tcp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	set_routing_fallback(outbound, false);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_tcp_new_outbound_obeys_connectivity_change")
int testcheck_wan_tcp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_SHOT, 0);
}

SEC("tc/pktgen/wan_udp_new_outbound_obeys_connectivity_change")
int testpktgen_wan_udp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,20,8), IPV4(10,20,0,8), 41007, 8443, 0);
}

SEC("tc/setup/wan_udp_new_outbound_obeys_connectivity_change")
int testsetup_wan_udp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	set_routing_fallback(outbound, false);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_udp_new_outbound_obeys_connectivity_change")
int testcheck_wan_udp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_SHOT, 0);
}

SEC("tc/pktgen/lan_ingress_udp_first_fragment_listener")
int testpktgen_lan_ingress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return set_ipv4_udp_first_fragment(skb,
					   IPV4(192,168,0,1), IPV4(8,8,8,8),
					   5353, 1053);
}

SEC("tc/setup/lan_ingress_udp_first_fragment_listener")
int testsetup_lan_ingress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_first_fragment_listener")
int testcheck_lan_ingress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_UDP);
}

SEC("tc/pktgen/lan_ingress_tcp_syn_first_fragment_listener")
int testpktgen_lan_ingress_tcp_syn_first_fragment_listener(struct __sk_buff *skb)
{
	return set_ipv4_tcp_first_fragment_with_flags(skb,
						      IPV4(192,168,0,1), IPV4(1,1,1,1),
						      19233, 443,
						      true, false, false);
}

SEC("tc/setup/lan_ingress_tcp_syn_first_fragment_listener")
int testsetup_lan_ingress_tcp_syn_first_fragment_listener(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_tcp_syn_first_fragment_listener")
int testcheck_lan_ingress_tcp_syn_first_fragment_listener(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_TCP);
}

SEC("tc/pktgen/lan_ingress_tcp_dscp_conn_state")
int testpktgen_lan_ingress_tcp_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   19233, 443, 10);
}

SEC("tc/setup/lan_ingress_tcp_dscp_conn_state")
int testsetup_lan_ingress_tcp_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_tcp_dscp_conn_state")
int testcheck_lan_ingress_tcp_dscp_conn_state(struct __sk_buff *skb)
{
	return check_tcp_conn_state_ipv4_tcp_dscp(skb,
						  TC_ACT_REDIRECT,
						  IPV4(192,168,0,1), IPV4(1,1,1,1),
						  19233, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/routing_epoch_slot_zero_handoff")
int testpktgen_routing_epoch_slot_zero_handoff(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,10), IPV4(1,1,1,1),
			    24560, 443);
}

SEC("tc/setup/routing_epoch_slot_zero_handoff")
int testsetup_routing_epoch_slot_zero_handoff(struct __sk_buff *skb)
{
	return setup_routing_epoch_lan_ingress(skb, 0);
}

SEC("tc/check/routing_epoch_slot_zero_handoff")
int testcheck_routing_epoch_slot_zero_handoff(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(skb, TC_ACT_REDIRECT,
						   IPV4(192,168,0,10), IPV4(1,1,1,1),
						   24560, 443,
						   OUTBOUND_USER_DEFINED_MIN,
						   routing_epoch_slot_encode(0));
}

SEC("tc/pktgen/routing_epoch_slot_one_handoff")
int testpktgen_routing_epoch_slot_one_handoff(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,11), IPV4(1,1,1,1),
			    24561, 443);
}

SEC("tc/setup/routing_epoch_slot_one_handoff")
int testsetup_routing_epoch_slot_one_handoff(struct __sk_buff *skb)
{
	return setup_routing_epoch_lan_ingress(skb, 1);
}

SEC("tc/check/routing_epoch_slot_one_handoff")
int testcheck_routing_epoch_slot_one_handoff(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(skb, TC_ACT_REDIRECT,
						   IPV4(192,168,0,11), IPV4(1,1,1,1),
						   24561, 443,
						   OUTBOUND_USER_DEFINED_MIN + 1,
						   routing_epoch_slot_encode(1));
}

SEC("tc/pktgen/routing_epoch_domain_projection_slot_zero")
int testpktgen_routing_epoch_domain_projection_slot_zero(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(198,51,100,20),
			    19233, 443);
}

SEC("tc/setup/routing_epoch_domain_projection_slot_zero")
int testsetup_routing_epoch_domain_projection_slot_zero(struct __sk_buff *skb)
{
	return setup_routing_epoch_domain_lan_ingress(skb, 0);
}

SEC("tc/check/routing_epoch_domain_projection_slot_zero")
int testcheck_routing_epoch_domain_projection_slot_zero(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(
		skb, TC_ACT_REDIRECT, IPV4(192,168,0,1),
		IPV4(198,51,100,20), 19233, 443, OUTBOUND_USER_DEFINED_MIN,
		routing_epoch_slot_encode(0));
}

SEC("tc/pktgen/routing_epoch_domain_projection_slot_one")
int testpktgen_routing_epoch_domain_projection_slot_one(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(198,51,100,20),
			    19233, 443);
}

SEC("tc/setup/routing_epoch_domain_projection_slot_one")
int testsetup_routing_epoch_domain_projection_slot_one(struct __sk_buff *skb)
{
	return setup_routing_epoch_domain_lan_ingress(skb, 1);
}

SEC("tc/check/routing_epoch_domain_projection_slot_one")
int testcheck_routing_epoch_domain_projection_slot_one(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(
		skb, TC_ACT_REDIRECT, IPV4(192,168,0,1),
		IPV4(198,51,100,20), 19233, 443, OUTBOUND_USER_DEFINED_MIN + 2,
		routing_epoch_slot_encode(1));
}

SEC("tc/pktgen/lan_ingress_tcp_ipv6_dscp_conn_state")
int testpktgen_lan_ingress_tcp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv6_tcp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   19233, 443, 10);
}

SEC("tc/setup/lan_ingress_tcp_ipv6_dscp_conn_state")
int testsetup_lan_ingress_tcp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_tcp_ipv6_dscp_conn_state")
int testcheck_lan_ingress_tcp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return check_tcp_conn_state_ipv6_tcp_dscp(skb,
						  TC_ACT_REDIRECT,
						  0x20010db8, 0, 0, 0x10,
						  0x26064700, 0, 0, 0x1111,
						  19233, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/lan_ingress_udp_dscp_conn_state")
int testpktgen_lan_ingress_udp_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   24567, 443, 10);
}

SEC("tc/setup/lan_ingress_udp_dscp_conn_state")
int testsetup_lan_ingress_udp_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_dscp_conn_state")
int testcheck_lan_ingress_udp_dscp_conn_state(struct __sk_buff *skb)
{
	return check_udp_conn_state_ipv4_udp_dscp(skb,
						  TC_ACT_REDIRECT,
						  IPV4(192,168,0,1), IPV4(1,1,1,1),
						  24567, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/lan_ingress_udp_ipv6_dscp_conn_state")
int testpktgen_lan_ingress_udp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv6_udp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   24567, 443, 10);
}

SEC("tc/setup/lan_ingress_udp_ipv6_dscp_conn_state")
int testsetup_lan_ingress_udp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_ipv6_dscp_conn_state")
int testcheck_lan_ingress_udp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return check_udp_conn_state_ipv6_udp_dscp(skb,
						  TC_ACT_REDIRECT,
						  0x20010db8, 0, 0, 0x10,
						  0x26064700, 0, 0, 0x1111,
						  24567, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/wan_egress_udp_first_fragment_listener")
int testpktgen_wan_egress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return set_ipv4_udp_first_fragment(skb,
					   IPV4(127,0,0,1), IPV4(8,8,4,4),
					   45678, 2053);
}

SEC("tc/setup/wan_egress_udp_first_fragment_listener")
int testsetup_wan_egress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_udp_first_fragment_listener")
int testcheck_wan_egress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_UDP);
}

SEC("tc/pktgen/lan_ingress_udp_non_initial_fragment_passthrough")
int testpktgen_lan_ingress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_udp_non_initial_fragment(skb,
						 IPV4(192,168,0,1), IPV4(8,8,8,8));
}

SEC("tc/setup/lan_ingress_udp_non_initial_fragment_passthrough")
int testsetup_lan_ingress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_non_initial_fragment_passthrough")
int testcheck_lan_ingress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/wan_egress_udp_non_initial_fragment_passthrough")
int testpktgen_wan_egress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_udp_non_initial_fragment(skb,
						 IPV4(127,0,0,1), IPV4(8,8,4,4));
}

SEC("tc/setup/wan_egress_udp_non_initial_fragment_passthrough")
int testsetup_wan_egress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_udp_non_initial_fragment_passthrough")
int testcheck_wan_egress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_PIPE, 0);
}

SEC("tc/pktgen/wan_egress_direct_mark_reroute")
int testpktgen_wan_egress_direct_mark_reroute(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,1), IPV4(9,9,9,9),
			    24567, 80);
}

SEC("tc/setup/wan_egress_direct_mark_reroute")
int testsetup_wan_egress_direct_mark_reroute(struct __sk_buff *skb)
{
	struct tuples_key key = {};
	struct tcphdr tcph = {};
	__u8 outbound = OUTBOUND_DIRECT;
	__u32 mark = TPROXY_MARK;
	__u8 must = 0;

	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,0,1));
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(9,9,9,9));
	key.sport = bpf_htons(24567);
	key.dport = bpf_htons(80);
	key.l4proto = IPPROTO_TCP;
	tcph.syn = true;

	if (!mark_tcp_seen(&key, &tcph, false,
			   &outbound, &mark, &must, NULL,
			   0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_direct_mark_reroute")
int testcheck_wan_egress_direct_mark_reroute(struct __sk_buff *skb)
{
	return check_tcp_conn_state_ipv4_tcp(skb,
					     TC_ACT_OK,
					     IPV4(192,168,0,1), IPV4(9,9,9,9),
					     24567, 80,
					     OUTBOUND_DIRECT,
					     TPROXY_MARK,
					     true);
}

SEC("tc/pktgen/conntrack_args_scratch_reset")
int testpktgen_conntrack_args_scratch_reset(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,1), IPV4(1,1,1,1),
			    19233, 443);
}

SEC("tc/setup/conntrack_args_scratch_reset")
int testsetup_conntrack_args_scratch_reset(struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	__u32 mark = 0x12345678;
	__u8 must = 1;
	char pname[TASK_COMM_LEN] = "conntrack-test";
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero_key);

	if (!args)
		return TC_ACT_SHOT;

	conntrack_args_set(args, &outbound, &mark, &must, NULL, 11, pname, 99,
			   ROUTING_EPOCH_SLOT_UNKNOWN);
	conntrack_args_set(args, NULL, NULL, NULL, NULL, 0, NULL, 0,
			   ROUTING_EPOCH_SLOT_UNKNOWN);

	if (args->flags != 0) {
		bpf_printk("args->flags(%u) != 0\n", args->flags);
		return TC_ACT_SHOT;
	}
	if (args->dscp != 0) {
		bpf_printk("args->dscp(%u) != 0\n", args->dscp);
		return TC_ACT_SHOT;
	}
	if (conntrack_args_pname_or_null(args)) {
		bpf_printk("conntrack_args_pname_or_null(args) != NULL\n");
		return TC_ACT_SHOT;
	}
	for (int i = 0; i < TASK_COMM_LEN; i++) {
		if (args->pname[i] != 0) {
			bpf_printk("args->pname[%d](%u) != 0\n", i,
				   args->pname[i]);
			return TC_ACT_SHOT;
		}
	}
	if (args->pid != 0) {
		bpf_printk("args->pid(%u) != 0\n", args->pid);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/check/conntrack_args_scratch_reset")
int testcheck_conntrack_args_scratch_reset(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/l4proto_match")
int testpktgen_l4proto_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/l4proto_match")
int testsetup_l4proto_match(struct __sk_buff *skb)
{
	/* l4proto(tcp) -> proxy */
	struct match_set ms = {};

	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/l4proto_match")
int testcheck_l4proto_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/l4proto_mismatch")
int testpktgen_l4proto_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/l4proto_mismatch")
int testsetup_l4proto_mismatch(struct __sk_buff *skb)
{
	/* l4proto(udp) -> proxy */
	struct match_set ms = {};

	ms.l4proto_type = L4ProtoType_UDP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/l4proto_mismatch")
int testcheck_l4proto_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipversion_match")
int testpktgen_ipversion_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/ipversion_match")
int testsetup_ipversion_match(struct __sk_buff *skb)
{
	/* ipversion(4) -> proxy */
	struct match_set ms = {};

	ms.ip_version = IpVersionType_4;
	ms.not = false;
	ms.type = MatchType_IpVersion;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipversion_match")
int testcheck_ipversion_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipversion_mismatch")
int testpktgen_ipversion_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/ipversion_mismatch")
int testsetup_ipversion_mismatch(struct __sk_buff *skb)
{
	/* ipversion(6) -> proxy */
	struct match_set ms = {};

	ms.ip_version = IpVersionType_6;
	ms.not = false;
	ms.type = MatchType_IpVersion;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipversion_mismatch")
int testcheck_ipversion_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/mac_match")
int testpktgen_mac_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/mac_match")
int testsetup_mac_match(struct __sk_buff *skb)
{
	/* mac('06:07:08:09:0a:0b') -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_Mac;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 128,
	};
	__u8 *data = (__u8 *)&lpm_key.data;

	data[10] = 0x6;
	data[11] = 0x7;
	data[12] = 0x8;
	data[13] = 0x9;
	data[14] = 0xa;
	data[15] = 0xb;
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/mac_match")
int testcheck_mac_match(struct __sk_buff *skb)
{
	struct lpm_key lpm_key = {
		.prefixlen = 128,
	};
	__u8 *data = (__u8 *)&lpm_key.data;

	data[10] = 0x6;
	data[11] = 0x7;
	data[12] = 0x8;
	data[13] = 0x9;
	data[14] = 0xa;
	data[15] = 0xb;
	bpf_map_delete_elem(&unused_lpm_type, &lpm_key);

	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/mac_mismatch")
int testpktgen_mac_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/mac_mismatch")
int testsetup_mac_mismatch(struct __sk_buff *skb)
{
	/* mac('00:01:02:03:04:05') -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_Mac;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 128,
	};
	__u8 *data = (__u8 *)&lpm_key.data;

	data[10] = 0x0;
	data[11] = 0x1;
	data[12] = 0x2;
	data[13] = 0x3;
	data[14] = 0x4;
	data[15] = 0x5;
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/mac_mismatch")
int testcheck_mac_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_match")
int testpktgen_dscp_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   19233, 79, 4);
}

SEC("tc/setup/dscp_match")
int testsetup_dscp_match(struct __sk_buff *skb)
{
	/* dscp(4) -> proxy */
	struct match_set ms = {};

	ms.dscp = 4;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_match")
int testcheck_dscp_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_ipv6_match")
int testpktgen_dscp_ipv6_match(struct __sk_buff *skb)
{
	return set_ipv6_tcp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   19233, 79, 4);
}

SEC("tc/setup/dscp_ipv6_match")
int testsetup_dscp_ipv6_match(struct __sk_buff *skb)
{
	struct match_set ms = {};

	ms.dscp = 4;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_ipv6_match")
int testcheck_dscp_ipv6_match(struct __sk_buff *skb)
{
	return check_routing_ipv6_tcp(skb,
				      TC_ACT_REDIRECT,
				      0x20010db8, 0, 0, 0x10,
				      0x26064700, 0, 0, 0x1111,
				      19233, 79);
}

SEC("tc/pktgen/dscp_mismatch")
int testpktgen_dscp_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   19233, 79, 4);
}

SEC("tc/setup/dscp_mismatch")
int testsetup_dscp_mismatch(struct __sk_buff *skb)
{
	/* dscp(5) -> proxy */
	struct match_set ms = {};

	ms.dscp = 5;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_mismatch")
int testcheck_dscp_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_ipv6_mismatch")
int testpktgen_dscp_ipv6_mismatch(struct __sk_buff *skb)
{
	return set_ipv6_tcp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   19233, 79, 4);
}

SEC("tc/setup/dscp_ipv6_mismatch")
int testsetup_dscp_ipv6_mismatch(struct __sk_buff *skb)
{
	struct match_set ms = {};

	ms.dscp = 5;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_ipv6_mismatch")
int testcheck_dscp_ipv6_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv6_tcp(skb,
				      TC_ACT_PIPE,
				      0x20010db8, 0, 0, 0x10,
				      0x26064700, 0, 0, 0x1111,
				      19233, 79);
}

SEC("tc/pktgen/and_match_1")
int testpktgen_and_match_1(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/and_match_1")
int testsetup_and_match_1(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	struct port_range pr = {1, 1023};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_LOGICAL_OR;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &two_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	pr.port_start = 8443;
	pr.port_end = 8443;
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &three_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = OUTBOUND_DIRECT;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &four_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_match_1")
int testcheck_and_match_1(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/and_match_2")
int testpktgen_and_match_2(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 8443);
}

SEC("tc/setup/and_match_2")
int testsetup_and_match_2(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	struct port_range pr = {1, 1023};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_LOGICAL_OR;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &two_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	pr.port_start = 8443;
	pr.port_end = 8443;
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &three_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = OUTBOUND_DIRECT;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &four_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_match_2")
int testcheck_and_match_2(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 8443);
}

SEC("tc/pktgen/and_mismatch")
int testpktgen_and_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 2333);
}

SEC("tc/setup/and_mismatch")
int testsetup_and_mismatch(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);

	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	struct port_range pr = {1, 1023};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_LOGICAL_OR;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &two_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	pr.port_start = 8443;
	pr.port_end = 8443;
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &three_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = OUTBOUND_DIRECT;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &four_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_mismatch")
int testcheck_and_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 2333);
}

SEC("tc/pktgen/not_match")
int testpktgen_not_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/not_match")
int testsetup_not_match(struct __sk_buff *skb)
{
	/* !dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};

	ms.port_range = pr;
	ms.not = true;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/not_match")
int testcheck_not_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_PIPE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/not_mismtach")
int testpktgen_not_mismtach(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/not_mismtach")
int testsetup_not_mismtach(struct __sk_buff *skb)
{
	/* !dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};

	ms.port_range = pr;
	ms.not = true;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/not_mismtach")
int testcheck_not_mismtach(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}
