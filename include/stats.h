#pragma once

struct LatencyCounters
{
	uint64_t total_cycles;
	uint64_t total_pkts;
	uint64_t blocked_cycles;
	uint64_t blocked_pkts;
};

class ThreadStats
{
public:
	uint64_t redirected_domains;
	uint64_t redirected_urls;
	uint64_t sended_rst;
	uint64_t ip_packets;
	uint64_t total_bytes;
	uint64_t matched_ssl;
	uint64_t matched_ssl_ip;
	uint64_t matched_ip_port;
	uint64_t total_packets;
	uint64_t analyzed_packets;
	uint64_t matched_domains;
	uint64_t matched_urls;
	uint64_t ipv4_packets;
	uint64_t ipv6_packets;
	uint64_t ndpi_flows_count;
	uint64_t ndpi_ipv4_flows_count;
	uint64_t ndpi_ipv6_flows_count;
	uint64_t max_ipv4_flows;
	uint64_t max_ipv6_flows;
	uint64_t ndpi_flows_deleted;
	uint64_t missed_packets;
	uint64_t enqueued_packets;
	uint64_t ipv4_short_packets;
	uint64_t ipv4_fragments;
	uint64_t ipv6_fragments;
	uint64_t already_detected_blocked;
	uint64_t reassembled_flows;
	struct LatencyCounters latency_counters;
	ThreadStats() : redirected_domains(0), redirected_urls(0), sended_rst(0), ip_packets(0), total_bytes(0), matched_ssl(0), matched_ssl_ip(0), matched_ip_port(0),total_packets(0), analyzed_packets(0), matched_domains(0), matched_urls(0), ipv4_packets(0), ipv6_packets(0), ndpi_flows_count(0), ndpi_ipv4_flows_count(0), ndpi_ipv6_flows_count(0), max_ipv4_flows(0), max_ipv6_flows(0), ndpi_flows_deleted(0), missed_packets(0), enqueued_packets(0), ipv4_short_packets(0), ipv4_fragments(0), ipv6_fragments(0), already_detected_blocked(0), reassembled_flows(0), latency_counters{0,0,0,0}  {}

	void clear() { redirected_domains = 0; redirected_urls = 0; sended_rst = 0; ip_packets = 0; total_bytes = 0; matched_ssl = 0; matched_ssl_ip = 0; matched_ip_port = 0; total_packets = 0; analyzed_packets = 0; matched_domains = 0; matched_urls = 0; ipv4_packets = 0; ipv6_packets = 0; ndpi_flows_count = 0; ndpi_flows_deleted = 0; missed_packets = 0; enqueued_packets = 0; ipv4_short_packets = 0; ipv4_fragments = 0; ipv6_fragments = 0; ndpi_ipv4_flows_count = 0; ndpi_ipv6_flows_count = 0; max_ipv4_flows = 0; max_ipv6_flows = 0; already_detected_blocked = 0; reassembled_flows = 0; latency_counters = {0, 0, 0, 0}; }


};

