/*
*
*    Copyright (C) Max <max1976@mail.ru>
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/

#pragma once

#include <rte_config.h>
#include <rte_malloc.h>

struct LatencyCounters
{
	uint64_t total_cycles;
	uint64_t total_pkts;
	uint64_t blocked_cycles;
	uint64_t unblocked_cycles;
	uint64_t blocked_pkts;
	uint64_t unblocked_pkts;
};

struct ThreadStats
{
	uint64_t ip_packets;
	uint64_t total_bytes;
	uint64_t matched_ssl_sni;
	uint64_t matched_ssl_ip;
	uint64_t matched_ip_port;
	uint64_t total_packets;
	uint64_t analyzed_packets;
	uint64_t ipv4_packets;
	uint64_t ipv6_packets;
	uint64_t missed_packets;
	uint64_t ipv4_short_packets;
	uint64_t ipv4_fragments;
	uint64_t ipv6_fragments;
	uint64_t reassembled_flows;
	struct LatencyCounters latency_counters;
	uint64_t dpi_no_mempool_http;
	uint64_t dpi_no_mempool_ssl;
	uint64_t dpi_ssl_partial_packets;
	uint64_t dpi_alloc_ssl;
	uint64_t dpi_alloc_http;

	uint64_t ssl_packets;
	uint64_t http_packets;

	// ipv4
	uint64_t recycling_flow;
	uint64_t no_create_flow;
	uint64_t new_flow;
	uint64_t error_alloc_flow;
	uint64_t close_flow;
	uint64_t alfs_fail_flow;
	uint64_t reuse_flow;
	uint64_t hash_add_fail_flow;
	uint64_t seen_already_blocked_http_ipv4;
	uint64_t seen_already_blocked_ssl_ipv4;
	uint64_t sended_rst_ipv4;
	uint64_t sended_forbidden_ipv4;
	uint64_t matched_http_bl_ipv4;
	uint64_t redirected_http_bl_ipv4;

	// ipv6
	uint64_t recycling_flow_ipv6;
	uint64_t no_create_flow_ipv6;
	uint64_t new_flow_ipv6;
	uint64_t error_alloc_flow_ipv6;
	uint64_t close_flow_ipv6;
	uint64_t alfs_fail_flow_ipv6;
	uint64_t reuse_flow_ipv6;
	uint64_t hash_add_fail_flow_ipv6;
	uint64_t seen_already_blocked_http_ipv6;
	uint64_t seen_already_blocked_ssl_ipv6;
	uint64_t sended_rst_ipv6;
	uint64_t sended_forbidden_ipv6;
	uint64_t matched_http_bl_ipv6;
	uint64_t redirected_http_bl_ipv6;

	uint64_t tx_dropped;

	ThreadStats()
	{
		memset(this, 0, sizeof(ThreadStats));
	}

	void clear()
	{
		memset(this, 0, sizeof(ThreadStats));
	}
} __rte_cache_aligned;;

