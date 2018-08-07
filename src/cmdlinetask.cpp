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

#include <cinttypes>
#include "cmdlinetask.h"
#include <Poco/Exception.h>
#include <netinet/in.h>
#include <unistd.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <cmdline.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <poll.h>
#include <rte_ethdev.h>
#include <pthread.h>
#include "notification.h"
#include "main.h"
#include "cfg.h"
#include <Poco/Net/NetException.h>

#include <iostream>

static void print_ethaddr(struct cmdline* cl, const char* name, const struct ether_addr* eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	cmdline_printf(cl, "%s%s\n", name, buf);
}

// Quit command

struct cmd_quit_result
{
	cmdline_fixed_string_t quit;
};

static void cmd_quit_parsed(__attribute__((unused)) void *parsed_result, struct cmdline *cl, __attribute__((unused)) void *data)
{
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_token = TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

#define MAKE_STRUCT(num, func, data, help_str )\
	cmdline_parse_inst_t *t = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + num * sizeof(void *)); \
	t->f = func; \
	t->data = data; \
	t->help_str = help_str; \
	t->[



static cmdline_parse_inst_t * init_cmd_quit()
{
	static cmdline_parse_inst_t *cmd_quit;
	cmd_quit = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 2);
	cmd_quit->f = cmd_quit_parsed;
	cmd_quit->data = nullptr;
	cmd_quit->help_str = "Quit from the cli";
	cmd_quit->tokens[0] = &cmd_quit_token.hdr;
	cmd_quit->tokens[1] = nullptr;
	return cmd_quit;
}
// end quit command



// SHOW PORT INFO
static void nic_stats_clear(struct cmdline* cl, uint8_t port_id)
{
	rte_eth_stats_reset(port_id);
	cmdline_printf(cl, "\n  NIC statistics for port %d cleared\n", port_id);
}

static void nic_xstats_clear(struct cmdline* cl, uint8_t port_id)
{
	rte_eth_xstats_reset(port_id);
	cmdline_printf(cl, "\n  NIC extra statistics for port %d cleared\n", port_id);
}

static void port_infos_display(struct cmdline* cl, uint8_t port_id)
{
	struct ether_addr mac_addr;
	struct rte_eth_link link;
	int vlan_offload;
	static const char* info_border = "=====================";

	rte_eth_link_get_nowait(port_id, &link);
	cmdline_printf(cl, "\n%s Infos for port %-2d %s\n", info_border, port_id, info_border);
	rte_eth_macaddr_get(port_id, &mac_addr);
	print_ethaddr(cl, "MAC address: ", &mac_addr);

	cmdline_printf(cl, "\nLink status: %s\n", (link.link_status) ? ("up") : ("down"));
	cmdline_printf(cl, "Link speed: %u Mbps\n", (unsigned)link.link_speed);
	cmdline_printf(cl, "Link duplex: %s\n", (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex"));
	cmdline_printf(cl, "Promiscuous mode: %s\n", rte_eth_promiscuous_get(port_id) ? "enabled" : "disabled");
	cmdline_printf(cl, "Allmulticast mode: %s\n", rte_eth_allmulticast_get(port_id) ? "enabled" : "disabled");

	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);
	if (vlan_offload >= 0) {
		cmdline_printf(cl, "VLAN offload: \n");
		if (vlan_offload & ETH_VLAN_STRIP_OFFLOAD)
			cmdline_printf(cl, "  strip on \n");
		else
			cmdline_printf(cl, "  strip off \n");

		if (vlan_offload & ETH_VLAN_FILTER_OFFLOAD)
			cmdline_printf(cl, "  filter on \n");
		else
			cmdline_printf(cl, "  filter off \n");

		if (vlan_offload & ETH_VLAN_EXTEND_OFFLOAD)
			cmdline_printf(cl, "  qinq(extend) on \n");
		else
			cmdline_printf(cl, "  qinq(extend) off \n");
	}
}

void nic_stats_display(struct cmdline* cl, uint8_t port_id, int option)
{
	struct rte_eth_stats stats;
	uint8_t i;

	static const char* nic_stats_border = "=======================";

	rte_eth_stats_get(port_id, &stats);

	if (option)
	{
		cmdline_printf(cl, "{\"portid\": %d, "
			       "\"rx\": {\"packets\": %" PRIu64
			       ", \"errors\": %" PRIu64 ", \"bytes\": %" PRIu64
			       ", "
			       ", \"nombuf\": %" PRIu64
			       ", \"imissed\": %" PRIu64
			       ", "
			       "\"tx\": {\"packets\": %" PRIu64
			       ", \"errors\": %" PRIu64 ", \"bytes\": %" PRIu64
			       ", ",
			       port_id, stats.ipackets, stats.ierrors,
			       stats.ibytes, stats.rx_nombuf, stats.imissed, stats.opackets,
			       stats.oerrors, stats.obytes);

		cmdline_printf(cl, "\"queues\": [");

		for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
			cmdline_printf(cl,
				       "{\"queueid\": %d, "
				       "\"rx\": {\"packets\": %" PRIu64
				       ", \"errors\": %" PRIu64
				       ", \"bytes\": %" PRIu64
				       "}, "
				       "\"tx\": {\"packets\": %" PRIu64
				       ", \"bytes\": %" PRIu64 "}}, ",
				       i, stats.q_ipackets[i],
				       stats.q_errors[i], stats.q_ibytes[i],
				       stats.q_opackets[i], stats.q_obytes[i]);
		}

		// add a null object to end the array
		cmdline_printf(cl, "{}");

		cmdline_printf(cl, "]}\n");

	} else {
		cmdline_printf(cl, "\n  %s NIC statistics for port %-2d %s\n",
			       nic_stats_border, port_id, nic_stats_border);

		cmdline_printf(cl, "  RX-packets:              %10" PRIu64
				   "    RX-errors: %10" PRIu64
				   "    RX-bytes: %10" PRIu64 "\n",
			       stats.ipackets, stats.ierrors, stats.ibytes);
		cmdline_printf(cl, "  RX-nombuf:               %10" PRIu64
				   "    RX-missed: %10" PRIu64 "\n",
			       stats.rx_nombuf, stats.imissed);
		cmdline_printf(cl, "  TX-packets:              %10" PRIu64
				   "    TX-errors: %10" PRIu64
				   "    TX-bytes: %10" PRIu64 "\n",
			       stats.opackets, stats.oerrors, stats.obytes);

		cmdline_printf(cl, "\n");
		for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
			cmdline_printf(cl,
				       "  Stats reg %2d RX-packets: %10" PRIu64
				       "    RX-errors: %10" PRIu64
				       "    RX-bytes: %10" PRIu64 "\n",
				       i, stats.q_ipackets[i],
				       stats.q_errors[i], stats.q_ibytes[i]);
		}
		cmdline_printf(cl, "\n");
		for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
			cmdline_printf(
			    cl,
			    "  Stats reg %2d TX-packets: %10" PRIu64
			    "                             TX-bytes: %10" PRIu64
			    "\n",
			    i, stats.q_opackets[i], stats.q_obytes[i]);
		}

		cmdline_printf(cl, "  %s=======================%s\n",
			       nic_stats_border, nic_stats_border);
	}
}

void nic_xstats_display(struct cmdline* cl, uint8_t port_id, int option)
{
	struct rte_eth_xstat* xstats;
	struct rte_eth_xstat_name *names;

	int len, ret, i;

	len = rte_eth_xstats_get(port_id, NULL, 0);
	if (len < 0)
	{
		cmdline_printf(cl, "Cannot get xstats count\n");
		return;
	}
	xstats = (rte_eth_xstat *)malloc(sizeof(xstats[0]) * len);
	if (xstats == NULL) {
		cmdline_printf(cl, "Cannot allocate memory for xstats\n");
		return;
	}
	ret = rte_eth_xstats_get(port_id, xstats, len);
	if (ret < 0 || ret > len)
	{
		cmdline_printf(cl, "Cannot get xstats\n");
		free(xstats);
		return;
	}
	len = rte_eth_xstats_get_names(port_id, NULL, 0);
	if(len < 0)
	{
		cmdline_printf(cl, "Cannot get xstats names\n");
		return;
	
	}
	names = (struct rte_eth_xstat_name *)malloc(sizeof(names[0])*len);
	
	ret = rte_eth_xstats_get_names(port_id, names, len);
	if (ret < 0 || ret > len)
	{
		cmdline_printf(cl, "Cannot get xstats names\n");
		free(xstats);
		free(names);
		return;
	}
	
	if (option)
	{
		cmdline_printf(cl, "{\"portid\": %d, ", port_id);

		for (i = 0; i < len; i++)
			cmdline_printf(cl, "%s\"%s\": %" PRIu64, (i != 0) ? ", " : "", names[xstats[i].id].name, xstats[i].value);

		cmdline_printf(cl, "}\n");

	} else {
		cmdline_printf(cl, "===== NIC extended statistics for port %-2d\n", port_id);

		for (i = 0; i < len; i++)
			cmdline_printf(cl, "%s: %" PRIu64 "\n", names[xstats[i].id].name, xstats[i].value);
	}

	free(xstats);
	free(names);
}


struct cmd_showport_result
{
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t what;
	uint8_t portnum;
	cmdline_fixed_string_t option;
};

static void cmd_showport_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_showport_result* res = (struct cmd_showport_result*)parsed_result;
	if (!strcmp(res->show, "clear"))
	{
		if (!strcmp(res->what, "stats"))
			nic_stats_clear(cl, res->portnum);
		else if (!strcmp(res->what, "xstats"))
			nic_xstats_clear(cl, res->portnum);
	} else if (!strcmp(res->what, "info"))
		port_infos_display(cl, res->portnum);
	else if (!strcmp(res->what, "stats"))
		nic_stats_display(cl, res->portnum, (intptr_t)data);
	else if (!strcmp(res->what, "xstats"))
		nic_xstats_display(cl, res->portnum, (intptr_t)data);
}

cmdline_parse_token_string_t cmd_showport_show = TOKEN_STRING_INITIALIZER(struct cmd_showport_result, show, "show#clear");
cmdline_parse_token_string_t cmd_showport_port = TOKEN_STRING_INITIALIZER(struct cmd_showport_result, port, "port");
cmdline_parse_token_string_t cmd_showport_what = TOKEN_STRING_INITIALIZER(struct cmd_showport_result, what, "info#stats#xstats");
cmdline_parse_token_num_t cmd_showport_portnum = TOKEN_NUM_INITIALIZER(struct cmd_showport_result, portnum, UINT8);
cmdline_parse_token_string_t cmd_showport_option = TOKEN_STRING_INITIALIZER(struct cmd_showport_result, option, "-j#json");


static cmdline_parse_inst_t * init_cmd_showport()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 5);
	cmd_showport->f = cmd_showport_parsed;
	cmd_showport->data = nullptr;
	cmd_showport->help_str = "show|clear port info|stats|xstats X (X = port number)";
	cmd_showport->tokens[0] = &cmd_showport_show.hdr;
	cmd_showport->tokens[1] = &cmd_showport_port.hdr;
	cmd_showport->tokens[2] = &cmd_showport_what.hdr;
	cmd_showport->tokens[3] = &cmd_showport_portnum.hdr;
	cmd_showport->tokens[4] = nullptr;
	return cmd_showport;
}

static cmdline_parse_inst_t * init_cmd_showport_json()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 6);
	cmd_showport->f = cmd_showport_parsed;
	cmd_showport->data = (void *)1;
	cmd_showport->help_str = "show|clear port info|stats|xstats X (X = port number) -s|json";
	cmd_showport->tokens[0] = &cmd_showport_show.hdr;
	cmd_showport->tokens[1] = &cmd_showport_port.hdr;
	cmd_showport->tokens[2] = &cmd_showport_what.hdr;
	cmd_showport->tokens[3] = &cmd_showport_portnum.hdr;
	cmd_showport->tokens[4] = &cmd_showport_option.hdr;
	cmd_showport->tokens[5] = nullptr;
	return cmd_showport;
}

// end show port info


// show worker
struct cmd_showworker_result
{
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t worker;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t workernum;
	cmdline_fixed_string_t option;
};

extern "C" uint32_t ssl_max_packet_size;
extern "C" uint64_t ssl_mallocs;
extern "C" uint64_t ssl_reallocs;

static void display_worker_stats(struct cmdline* cl,const ThreadStats &stats)
{
	cmdline_printf(cl, "  Seen packets: %" PRIu64 "\n", stats.total_packets);
	cmdline_printf(cl, "  IP packets: %" PRIu64 " (IPv4 packets: %" PRIu64 ", IPv6 packets: %" PRIu64 ")\n", stats.ip_packets, stats.ipv4_packets, stats.ipv6_packets);
	cmdline_printf(cl, "  Total bytes: %" PRIu64 "\n", stats.total_bytes);
	cmdline_printf(cl, "  HTTP packets: %" PRIu64 "\n", stats.http_packets);
	cmdline_printf(cl, "  SSL/TLS packets: %" PRIu64 "\n", stats.ssl_packets);
	cmdline_printf(cl, "  SSL/TLS partial packets: %" PRIu64 "\n", stats.dpi_ssl_partial_packets);

	cmdline_printf(cl, "  DPI parsers:\n");
	cmdline_printf(cl, "    Allocs:\n");
	cmdline_printf(cl, "      HTTP: %" PRIu64 "\n", stats.dpi_alloc_http);
	cmdline_printf(cl, "      SSL: %" PRIu64 "\n", stats.dpi_alloc_ssl);
	cmdline_printf(cl, "    Memory pools usage:\n");
	cmdline_printf(cl, "      HTTP: %d\n", rte_mempool_in_use_count(common_data->mempools.http_entries.mempool));
	cmdline_printf(cl, "      SSL: %d\n", rte_mempool_in_use_count(common_data->mempools.ssl_entries.mempool));
	cmdline_printf(cl, "    Memory pools free:\n");
	cmdline_printf(cl, "      HTTP: %d\n", rte_mempool_avail_count(common_data->mempools.http_entries.mempool));
	cmdline_printf(cl, "      SSL: %d\n", rte_mempool_avail_count(common_data->mempools.ssl_entries.mempool));
	cmdline_printf(cl, "  DPI errors:\n");
	cmdline_printf(cl, "    No memory http: %" PRIu64 "\n",stats.dpi_no_mempool_http);
	cmdline_printf(cl, "    No memory ssl: %" PRIu64 "\n",stats.dpi_no_mempool_ssl);

	if(stats.ip_packets && stats.total_bytes)
	{
		uint32_t avg_pkt_size = (unsigned int)(stats.total_bytes/stats.ip_packets);
		cmdline_printf(cl, "  Average packet size: %" PRIu32 "\n", avg_pkt_size);
	}
	cmdline_printf(cl, "  Fragments:\n");
	cmdline_printf(cl, "    IPv4: %" PRIu64 "\n", stats.ipv4_fragments);
	cmdline_printf(cl, "    IPv6: %" PRIu64 "\n", stats.ipv6_fragments);
	cmdline_printf(cl, "  IPv4 short packets: %" PRIu64 "\n", stats.ipv4_short_packets);
	cmdline_printf(cl, "  Matched by:\n");
	cmdline_printf(cl, "    ACL ip/port: %" PRIu64 "\n", stats.matched_ip_port);
	cmdline_printf(cl, "    SSL SNI: %" PRIu64 "\n", stats.matched_ssl_sni);
	cmdline_printf(cl, "    ACL SSL: %" PRIu64 "\n", stats.matched_ssl_ip);
	cmdline_printf(cl, "    HTTP: %" PRIu64 "\n", stats.matched_http_bl_ipv4 + stats.matched_http_bl_ipv6);
	cmdline_printf(cl, "      IPv4: %" PRIu64 "\n", stats.matched_http_bl_ipv4);
	cmdline_printf(cl, "      IPv6: %" PRIu64 "\n", stats.matched_http_bl_ipv6);
	cmdline_printf(cl, "  Redirected:\n");
	cmdline_printf(cl, "    HTTP blacklisted: %" PRIu64 "\n", stats.redirected_http_bl_ipv4 + stats.redirected_http_bl_ipv6);
	cmdline_printf(cl, "      IPv4: %" PRIu64 "\n", stats.redirected_http_bl_ipv4);
	cmdline_printf(cl, "      IPv6: %" PRIu64 "\n", stats.redirected_http_bl_ipv6);
	cmdline_printf(cl, "  Sended rst:\n");
	cmdline_printf(cl, "    IPv4: %" PRIu64 "\n",stats.sended_rst_ipv4);
	cmdline_printf(cl, "    IPv6: %" PRIu64 "\n",stats.sended_rst_ipv6);
	cmdline_printf(cl, "  Sended forbidden:\n");
	cmdline_printf(cl, "    IPv4: %" PRIu64 "\n",stats.sended_forbidden_ipv4);
	cmdline_printf(cl, "    IPv6: %" PRIu64 "\n",stats.sended_forbidden_ipv6);
	cmdline_printf(cl, "  Already blocked:\n");
	cmdline_printf(cl, "    IPv4:\n");
	cmdline_printf(cl, "      HTTP : %" PRIu64 "\n", stats.seen_already_blocked_http_ipv4);
	cmdline_printf(cl, "      SSL  : %" PRIu64 "\n", stats.seen_already_blocked_ssl_ipv4);
	cmdline_printf(cl, "    IPv6:\n");
	cmdline_printf(cl, "      HTTP : %" PRIu64 "\n", stats.seen_already_blocked_http_ipv6);
	cmdline_printf(cl, "      SSL  : %" PRIu64 "\n", stats.seen_already_blocked_ssl_ipv6);
	cmdline_printf(cl, "  Flows:\n");
	cmdline_printf(cl, "    IPv4:\n");
	cmdline_printf(cl, "      New:       %" PRIu64 "\n", stats.new_flow);
	cmdline_printf(cl, "      Recycling: %" PRIu64 "\n", stats.recycling_flow);
	cmdline_printf(cl, "      Reuse:     %" PRIu64 "\n", stats.reuse_flow);
	cmdline_printf(cl, "      Close:     %" PRIu64 "\n", stats.close_flow);
	cmdline_printf(cl, "      No create: %" PRIu64 "\n", stats.no_create_flow);
	cmdline_printf(cl, "      No memory: %" PRIu64 "\n", stats.error_alloc_flow);
	cmdline_printf(cl, "      Alfs fail: %" PRIu64 "\n", stats.alfs_fail_flow);
	cmdline_printf(cl, "    IPv6:\n");
	cmdline_printf(cl, "      New:       %" PRIu64 "\n", stats.new_flow_ipv6);
	cmdline_printf(cl, "      Recycling: %" PRIu64 "\n", stats.recycling_flow_ipv6);
	cmdline_printf(cl, "      Reuse:     %" PRIu64 "\n", stats.reuse_flow_ipv6);
	cmdline_printf(cl, "      Close:     %" PRIu64 "\n", stats.close_flow_ipv6);
	cmdline_printf(cl, "      No create: %" PRIu64 "\n", stats.no_create_flow_ipv6);
	cmdline_printf(cl, "      No memory: %" PRIu64 "\n", stats.error_alloc_flow_ipv6);
	cmdline_printf(cl, "      Alfs fail: %" PRIu64 "\n", stats.alfs_fail_flow_ipv6);

}

static uint32_t total_allocated_flows_ipv4 = 0;
static uint64_t total_reused_flows_ipv4 = 0;
static uint32_t total_allocated_flows_ipv6 = 0;
static uint64_t total_reused_flows_ipv6 = 0;

static uint32_t alfs_short_allocated_ipv4 = 0;
static uint64_t alfs_short_oldest_ipv4 = 0;
static uint64_t alfs_short_alien_ipv4 = 0;
static uint64_t alfs_short_error_ipv4 = 0;

static uint32_t alfs_long_allocated_ipv4 = 0;
static uint64_t alfs_long_oldest_ipv4 = 0;
static uint64_t alfs_long_alien_ipv4 = 0;
static uint64_t alfs_long_error_ipv4 = 0;

static uint32_t alfs_short_allocated_ipv6 = 0;
static uint64_t alfs_short_oldest_ipv6 = 0;
static uint64_t alfs_short_alien_ipv6 = 0;
static uint64_t alfs_short_error_ipv6 = 0;

static uint32_t alfs_long_allocated_ipv6 = 0;
static uint64_t alfs_long_oldest_ipv6 = 0;
static uint64_t alfs_long_alien_ipv6 = 0;
static uint64_t alfs_long_error_ipv6 = 0;

static void display_worker_memory_stats(struct cmdline *cl, uint8_t worker_id)
{
	cmdline_printf(cl, "  Flows memory usage:\n");
	cmdline_printf(cl, "    IPv4:\n");
	cmdline_printf(cl, "      Parameters:\n");
	cmdline_printf(cl, "        Total:        %" PRIu32 "\n", global_prm->memory_configs.ipv4.flows_number);
	cmdline_printf(cl, "        Parts:        %d\n", (int) global_prm->memory_configs.ipv4.parts_of_flow);
	cmdline_printf(cl, "        Parts mask:   %" PRIu32 "\n", global_prm->memory_configs.ipv4.mask_parts_flow);
	cmdline_printf(cl, "        Cache size:   %" PRIu32 "\n", global_prm->memory_configs.ipv4.recs_number);
	cmdline_printf(cl, "      Current usage:\n");

	cmdline_printf(cl, "        Per part:\n");
	uint32_t total_allocated = 0;
	uint64_t total_reused = 0;
	for(int i=0; i < global_prm->memory_configs.ipv4.parts_of_flow; i++)
	{
		cmdline_printf(cl, "          Part %d:\n", i);
		FlowStorageIPV4 *fs_ipv4 = (FlowStorageIPV4 *) worker_params[worker_id].flows_ipv4.flows[i];
		cmdline_printf(cl, "            Allocated: %" PRIu32 "\n", fs_ipv4->counters.alloc);
		cmdline_printf(cl, "            Reused:    %" PRIu64 "\n", fs_ipv4->counters.reuse);
		total_allocated += fs_ipv4->counters.alloc;
		total_reused += fs_ipv4->counters.reuse;
		cmdline_printf(cl, "            Alfs:\n");
		cmdline_printf(cl, "              Short:\n");
		cmdline_printf(cl, "                Allctd: %" PRIu32 "\n", fs_ipv4->short_alfs.getAllocated());
		cmdline_printf(cl, "                Oldest: %" PRIu64 "\n", fs_ipv4->short_alfs.counters.oldest);
		cmdline_printf(cl, "                Alien:  %" PRIu64 "\n", fs_ipv4->short_alfs.counters.alien_rec);
		cmdline_printf(cl, "                No mem: %" PRIu64 "\n", fs_ipv4->short_alfs.counters.err_alloc);
		cmdline_printf(cl, "              Long:\n");
		cmdline_printf(cl, "                Allctd: %" PRIu32 "\n", fs_ipv4->long_alfs.getAllocated());
		cmdline_printf(cl, "                Oldest: %" PRIu64 "\n", fs_ipv4->long_alfs.counters.oldest);
		cmdline_printf(cl, "                Alien:  %" PRIu64 "\n", fs_ipv4->long_alfs.counters.alien_rec);
		cmdline_printf(cl, "                No mem: %" PRIu64 "\n", fs_ipv4->long_alfs.counters.err_alloc);
		alfs_short_allocated_ipv4 += fs_ipv4->short_alfs.getAllocated();
		alfs_short_oldest_ipv4 += fs_ipv4->short_alfs.counters.oldest;
		alfs_short_alien_ipv4 += fs_ipv4->short_alfs.counters.alien_rec;
		alfs_short_error_ipv4 += fs_ipv4->short_alfs.counters.err_alloc;

		alfs_long_allocated_ipv4 += fs_ipv4->long_alfs.getAllocated();
		alfs_long_oldest_ipv4 += fs_ipv4->long_alfs.counters.oldest;
		alfs_long_alien_ipv4 += fs_ipv4->long_alfs.counters.alien_rec;
		alfs_long_error_ipv4 += fs_ipv4->long_alfs.counters.err_alloc;

	}
	total_allocated_flows_ipv4 += total_allocated;
	total_reused_flows_ipv4 += total_reused;
	cmdline_printf(cl, "        All parts:\n");
	cmdline_printf(cl, "          Allocated:    %" PRIu32 "\n", total_allocated);
	cmdline_printf(cl, "          Reused:       %" PRIu64 "\n", total_reused);

	cmdline_printf(cl, "    IPv6:\n");
	cmdline_printf(cl, "      Parameters:\n");
	cmdline_printf(cl, "        Total:        %" PRIu32 "\n", global_prm->memory_configs.ipv6.flows_number);
	cmdline_printf(cl, "        Parts:        %d\n", (int) global_prm->memory_configs.ipv6.parts_of_flow);
	cmdline_printf(cl, "        Parts mask:   %" PRIu32 "\n", global_prm->memory_configs.ipv6.mask_parts_flow);
	cmdline_printf(cl, "        Cache size:   %" PRIu32 "\n", global_prm->memory_configs.ipv6.recs_number);
	cmdline_printf(cl, "      Current usage:\n");

	cmdline_printf(cl, "        Per part:\n");

	uint32_t total_allocated_ipv6 = 0;
	uint64_t total_reused_ipv6 = 0;

	for(int i=0; i < global_prm->memory_configs.ipv6.parts_of_flow; i++)
	{
		cmdline_printf(cl, "          Part %d:\n", i);
		FlowStorageIPV6 *fs_ipv6 = (FlowStorageIPV6 *) worker_params[worker_id].flows_ipv6.flows[i];
		cmdline_printf(cl, "            Allocated: %" PRIu32 "\n", fs_ipv6->counters.alloc);
		cmdline_printf(cl, "            Reused:    %" PRIu64 "\n", fs_ipv6->counters.reuse);
		total_allocated_ipv6 += fs_ipv6->counters.alloc;
		total_reused_ipv6 += fs_ipv6->counters.reuse;
		cmdline_printf(cl, "            Alfs:\n");
		cmdline_printf(cl, "              Short:\n");
		cmdline_printf(cl, "                Allctd: %" PRIu32 "\n", fs_ipv6->short_alfs.getAllocated());
		cmdline_printf(cl, "                Oldest: %" PRIu64 "\n", fs_ipv6->short_alfs.counters.oldest);
		cmdline_printf(cl, "                Alien:  %" PRIu64 "\n", fs_ipv6->short_alfs.counters.alien_rec);
		cmdline_printf(cl, "                No mem: %" PRIu64 "\n", fs_ipv6->short_alfs.counters.err_alloc);
		cmdline_printf(cl, "              Long:\n");
		cmdline_printf(cl, "                Allctd: %" PRIu32 "\n", fs_ipv6->long_alfs.getAllocated());
		cmdline_printf(cl, "                Oldest: %" PRIu64 "\n", fs_ipv6->long_alfs.counters.oldest);
		cmdline_printf(cl, "                Alien:  %" PRIu64 "\n", fs_ipv6->long_alfs.counters.alien_rec);
		cmdline_printf(cl, "                No mem: %" PRIu64 "\n", fs_ipv6->long_alfs.counters.err_alloc);
		alfs_short_allocated_ipv6 += fs_ipv6->short_alfs.getAllocated();
		alfs_short_oldest_ipv6 += fs_ipv6->short_alfs.counters.oldest;
		alfs_short_alien_ipv6 += fs_ipv6->short_alfs.counters.alien_rec;
		alfs_short_error_ipv6 += fs_ipv6->short_alfs.counters.err_alloc;
		alfs_long_allocated_ipv6 += fs_ipv6->long_alfs.getAllocated();
		alfs_long_oldest_ipv6 += fs_ipv6->long_alfs.counters.oldest;
		alfs_long_alien_ipv6 += fs_ipv6->long_alfs.counters.alien_rec;
		alfs_long_error_ipv6 += fs_ipv6->long_alfs.counters.err_alloc;
	}
	total_allocated_flows_ipv6 += total_allocated_ipv6;
	total_reused_flows_ipv6 += total_reused_ipv6;
	cmdline_printf(cl, "        All parts:\n");
	cmdline_printf(cl, "          Allocated:    %" PRIu32 "\n", total_allocated_ipv6);
	cmdline_printf(cl, "          Reused:       %" PRIu64 "\n", total_reused_ipv6);
}

static void display_worker_memory_stats_all(struct cmdline *cl)
{
	cmdline_printf(cl, "    Total alfs ipv4:\n");
	cmdline_printf(cl, "      Short:\n");
	cmdline_printf(cl, "        Allctd: %" PRIu32 "\n", alfs_short_allocated_ipv4);
	cmdline_printf(cl, "        Oldest: %" PRIu64 "\n", alfs_short_oldest_ipv4);
	cmdline_printf(cl, "        Alien:  %" PRIu64 "\n", alfs_short_alien_ipv4);
	cmdline_printf(cl, "        No mem: %" PRIu64 "\n", alfs_short_error_ipv4);
	cmdline_printf(cl, "      Long:\n");
	cmdline_printf(cl, "        Allctd: %" PRIu32 "\n", alfs_long_allocated_ipv4);
	cmdline_printf(cl, "        Oldest: %" PRIu64 "\n", alfs_long_oldest_ipv4);
	cmdline_printf(cl, "        Alien:  %" PRIu64 "\n", alfs_long_alien_ipv4);
	cmdline_printf(cl, "        No mem: %" PRIu64 "\n", alfs_long_error_ipv4);

	cmdline_printf(cl, "    Total alfs ipv6:\n");
	cmdline_printf(cl, "      Short:\n");
	cmdline_printf(cl, "        Allctd: %" PRIu32 "\n", alfs_short_allocated_ipv6);
	cmdline_printf(cl, "        Oldest: %" PRIu64 "\n", alfs_short_oldest_ipv6);
	cmdline_printf(cl, "        Alien:  %" PRIu64 "\n", alfs_short_alien_ipv6);
	cmdline_printf(cl, "        No mem: %" PRIu64 "\n", alfs_short_error_ipv6);
	cmdline_printf(cl, "      Long:\n");
	cmdline_printf(cl, "        Allctd: %" PRIu32 "\n", alfs_long_allocated_ipv6);
	cmdline_printf(cl, "        Oldest: %" PRIu64 "\n", alfs_long_oldest_ipv6);
	cmdline_printf(cl, "        Alien:  %" PRIu64 "\n", alfs_long_alien_ipv6);
	cmdline_printf(cl, "        No mem: %" PRIu64 "\n", alfs_long_error_ipv6);

	cmdline_printf(cl, "    Total allocated ipv4 flows: %" PRIu32 "\n", total_allocated_flows_ipv4);
	cmdline_printf(cl, "    Total allocated ipv6 flows: %" PRIu32 "\n", total_allocated_flows_ipv6);
	cmdline_printf(cl, "    Total reused ipv4 flows: %" PRIu64 "\n", total_reused_flows_ipv4);
	cmdline_printf(cl, "    Total reused ipv6 flows: %" PRIu64 "\n", total_reused_flows_ipv6);
	cmdline_printf(cl, "    Free ipv4 flows: %" PRIu32 "\n", (global_prm->memory_configs.ipv4.flows_number - total_allocated_flows_ipv4));
	cmdline_printf(cl, "    Free ipv6 flows: %" PRIu32 "\n", (global_prm->memory_configs.ipv6.flows_number - total_allocated_flows_ipv6));
}

static void cmd_showworker_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_showworker_result* res = (struct cmd_showworker_result*)parsed_result;
	if (!strcmp(res->show, "clear"))
	{
		if (!strcmp(res->what, "stats"))
		{
			if(!strcmp(res->workernum,"all"))
			{
				extFilter *f = extFilter::instance();
				for(auto const &thread : f->getThreadsVec())
				{
					(static_cast<WorkerThread*>(thread))->clearStats();
				}
			} else {
				int core_id = ::atoi(res->workernum);
				extFilter *f = extFilter::instance();
				for(auto const &thread : f->getThreadsVec())
				{
					if(core_id == (int)thread->getCoreId())
					{
						(static_cast<WorkerThread*>(thread))->clearStats();
					}
				}
			}
		}
	} else if (!strcmp(res->what, "stats"))
	{
		if(!strcmp(res->workernum,"all"))
		{
			extFilter *f = extFilter::instance();
			cmdline_printf(cl, "Working %lu workers:\n", f->getThreadsVec().size());
			for(auto const &thread : f->getThreadsVec())
			{
				const ThreadStats stats=(static_cast<WorkerThread*>(thread))->getStats();
				cmdline_printf(cl, "Worker '%s' on core %d\n", (static_cast<WorkerThread*>(thread))->getThreadName().c_str(), (int)thread->getCoreId());
				display_worker_stats(cl, stats);
				cmdline_printf(cl, "\n");
			}
		} else {
			int worker_id = ::atoi(res->workernum);
			extFilter *f = extFilter::instance();
			for(auto const &thread : f->getThreadsVec())
			{
				if(worker_id == (static_cast<WorkerThread*>(thread))->getWorkerID())
				{
					const ThreadStats stats=(static_cast<WorkerThread*>(thread))->getStats();
					cmdline_printf(cl, "Worker '%s' on core %d\n", (static_cast<WorkerThread*>(thread))->getThreadName().c_str(), (int)thread->getCoreId());
					display_worker_stats(cl, stats);
					cmdline_printf(cl, "\n");
				}
			}
		}
	} else if (!strcmp(res->what, "memory"))
	{
		total_allocated_flows_ipv4 = 0;
		total_allocated_flows_ipv6 = 0;

		alfs_short_allocated_ipv4 = 0;
		alfs_short_oldest_ipv4 = 0;
		alfs_short_alien_ipv4 = 0;
		alfs_short_error_ipv4 = 0;
		alfs_short_allocated_ipv6 = 0;
		alfs_short_oldest_ipv6 = 0;
		alfs_short_alien_ipv6 = 0;
		alfs_short_error_ipv6 = 0;

		alfs_long_allocated_ipv4 = 0;
		alfs_long_oldest_ipv4 = 0;
		alfs_long_alien_ipv4 = 0;
		alfs_long_error_ipv4 = 0;

		alfs_long_allocated_ipv6 = 0;
		alfs_long_oldest_ipv6 = 0;
		alfs_long_alien_ipv6 = 0;
		alfs_long_error_ipv6 = 0;

		if(!strcmp(res->workernum,"all"))
		{
			extFilter *f = extFilter::instance();
			cmdline_printf(cl, "Working %lu workers:\n", f->getThreadsVec().size());
			for(auto const &thread : f->getThreadsVec())
			{
				cmdline_printf(cl, "Worker '%s' on core %d\n", (static_cast<WorkerThread*>(thread))->getThreadName().c_str(), (int)thread->getCoreId());
				display_worker_memory_stats(cl, (static_cast<WorkerThread*>(thread))->getWorkerID());
				cmdline_printf(cl, "\n");
			}
			display_worker_memory_stats_all(cl);
			cmdline_printf(cl, "\n");
		} else {
			int worker_id = ::atoi(res->workernum);
			extFilter *f = extFilter::instance();
			for(auto const &thread : f->getThreadsVec())
			{
				if(worker_id == (static_cast<WorkerThread*>(thread))->getWorkerID())
				{
					cmdline_printf(cl, "Worker '%s' on core %d\n", (static_cast<WorkerThread*>(thread))->getThreadName().c_str(), (int)thread->getCoreId());
					display_worker_memory_stats(cl, (static_cast<WorkerThread*>(thread))->getWorkerID());
					cmdline_printf(cl, "\n");
				}
			}
		}
	}
}

cmdline_parse_token_string_t cmd_showworker_show = TOKEN_STRING_INITIALIZER(struct cmd_showworker_result, show, "show#clear");
cmdline_parse_token_string_t cmd_showworker_worker = TOKEN_STRING_INITIALIZER(struct cmd_showworker_result, worker, "worker");
cmdline_parse_token_string_t cmd_showworker_what = TOKEN_STRING_INITIALIZER(struct cmd_showworker_result, what, "stats#memory");
cmdline_parse_token_string_t cmd_showworker_workernum = TOKEN_STRING_INITIALIZER(struct cmd_showworker_result, workernum, NULL);
cmdline_parse_token_string_t cmd_showworker_option = TOKEN_STRING_INITIALIZER(struct cmd_showworker_result, option, "-j#json");

static cmdline_parse_inst_t * init_cmd_showworker_json()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 6);
	cmd_showport->f = cmd_showworker_parsed;
	cmd_showport->data = (void *)1;
	cmd_showport->help_str = "show|clear worker stats|memory X (X = core id or all) -j|json";
	cmd_showport->tokens[0] = &cmd_showworker_show.hdr;
	cmd_showport->tokens[1] = &cmd_showworker_worker.hdr;
	cmd_showport->tokens[2] = &cmd_showworker_what.hdr;
	cmd_showport->tokens[3] = &cmd_showworker_workernum.hdr;
	cmd_showport->tokens[4] = &cmd_showworker_option.hdr;
	cmd_showport->tokens[5] = nullptr;
	return cmd_showport;
}

static cmdline_parse_inst_t * init_cmd_showworker()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 5);
	cmd_showport->f = cmd_showworker_parsed;
	cmd_showport->data = nullptr;
	cmd_showport->help_str = "show|clear worker stats|memory X (X = core id or all)";
	cmd_showport->tokens[0] = &cmd_showworker_show.hdr;
	cmd_showport->tokens[1] = &cmd_showworker_worker.hdr;
	cmd_showport->tokens[2] = &cmd_showworker_what.hdr;
	cmd_showport->tokens[3] = &cmd_showworker_workernum.hdr;
	cmd_showport->tokens[5] = nullptr;
	return cmd_showport;
}

// end show worker

// show subscriber notify
struct cmd_showsub_result
{
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t subscriber;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t ip;
};

static void cmd_showsub_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_showsub_result* res = (struct cmd_showsub_result*)parsed_result;
	if(!strcmp(res->what, "notify"))
	{
		if(!strcmp(res->ip,"all"))
		{
			NotifyManager::printSubscribers(cl, 0);
		} else {
			try {
				Poco::Net::IPAddress ip(res->ip);
				NotifyManager::printSubscribers(cl, *(uint32_t *)ip.addr());
			} catch (Poco::Net::InvalidAddressException ex)
			{
				cmdline_printf(cl, "Invalid ip address\n");
			}
		}
	}
}

cmdline_parse_token_string_t cmd_showsub_show = TOKEN_STRING_INITIALIZER(struct cmd_showsub_result, show, "show");
cmdline_parse_token_string_t cmd_showsub_sub = TOKEN_STRING_INITIALIZER(struct cmd_showsub_result, subscriber, "subscriber");
cmdline_parse_token_string_t cmd_showsub_what = TOKEN_STRING_INITIALIZER(struct cmd_showsub_result, what, "notify");
cmdline_parse_token_string_t cmd_showsub_ip = TOKEN_STRING_INITIALIZER(struct cmd_showsub_result, ip, NULL);

/*static cmdline_parse_inst_t * init_cmd_showworker_json()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 6);
	cmd_showport->f = cmd_showworker_parsed;
	cmd_showport->data = (void *)1;
	cmd_showport->help_str = "show|clear worker info|stats X (X = worker number) -j|json";
	cmd_showport->tokens[0] = &cmd_showworker_show.hdr;
	cmd_showport->tokens[1] = &cmd_showworker_worker.hdr;
	cmd_showport->tokens[2] = &cmd_showworker_what.hdr;
	cmd_showport->tokens[3] = &cmd_showworker_workernum.hdr;
	cmd_showport->tokens[4] = &cmd_showworker_option.hdr;
	cmd_showport->tokens[5] = nullptr;
	return cmd_showport;
}*/

static cmdline_parse_inst_t * init_cmd_showsub()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 5);
	cmd_showport->f = cmd_showsub_parsed;
	cmd_showport->data = nullptr;
	cmd_showport->help_str = "show subscriber notify X (X = subscriber ip)";
	cmd_showport->tokens[0] = &cmd_showsub_show.hdr;
	cmd_showport->tokens[1] = &cmd_showsub_sub.hdr;
	cmd_showport->tokens[2] = &cmd_showsub_what.hdr;
	cmd_showport->tokens[3] = &cmd_showsub_ip.hdr;
	cmd_showport->tokens[5] = nullptr;
	return cmd_showport;
}

// end subscriber notify

// notify

struct cmd_notify_result
{
	cmdline_fixed_string_t notify;
	cmdline_fixed_string_t action;
};

static void cmd_notify_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_notify_result* res = (struct cmd_notify_result*)parsed_result;
	if (!strcmp(res->action, "disable"))
	{
		extFilter *f=extFilter::instance();
		f->setNotifyEnabled(false);
		cmdline_printf(cl, "Notification disabled on all workers\n");
	} else if (!strcmp(res->action, "enable"))
	{
		extFilter *f=extFilter::instance();
		f->setNotifyEnabled(true);
		cmdline_printf(cl, "Notification enabled on all workers\n");
	}
}

cmdline_parse_token_string_t cmd_notify = TOKEN_STRING_INITIALIZER(struct cmd_notify_result, notify, "notify");
cmdline_parse_token_string_t cmd_notify_action = TOKEN_STRING_INITIALIZER(struct cmd_notify_result, action, "disable#enable");

static cmdline_parse_inst_t * init_cmd_notify()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 3);
	cmd_showport->f = cmd_notify_parsed;
	cmd_showport->data = nullptr;
	cmd_showport->help_str = "notify disable|enable";
	cmd_showport->tokens[0] = &cmd_notify.hdr;
	cmd_showport->tokens[1] = &cmd_notify_action.hdr;
	cmd_showport->tokens[2] = nullptr;
	return cmd_showport;
}

// end notify

// show acl
// acl reload
// acl port_ip file_name
// acl ssl_ip file_name
// acl notify file_name

struct cmd_acl_result
{
	cmdline_fixed_string_t acl;
	cmdline_fixed_string_t action;
};

static void cmd_acl_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_acl_result* res = (struct cmd_acl_result*)parsed_result;
	if(!strcmp(res->acl,"acl"))
	{
		if(!strcmp(res->action, "reload"))
		{
			extFilter *f = extFilter::instance();
			if(f->loadACL())
			{
				cmdline_printf(cl, "Unable to reload ACL\n");
			} else {
				cmdline_printf(cl, "ACL successfully reloaded\n");
			}
		}
	} else if(!strcmp(res->acl,"show"))
	{
		if(!strcmp(res->action,"acl"))
		{
			extFilter *f = extFilter::instance();
			cmdline_printf(cl, "ACL for ip:port blocking: %s\n", f->getHostsFile().c_str());
			cmdline_printf(cl, "ACL for SSL ip blocking: %s\n", f->getSSLIpsFile().c_str());
			cmdline_printf(cl, "ACL for notification: %s\n", f->getNotifyFile().c_str());
		}
	}
}

cmdline_parse_token_string_t cmd_acl = TOKEN_STRING_INITIALIZER(struct cmd_acl_result, acl, "acl");
cmdline_parse_token_string_t cmd_acl_action = TOKEN_STRING_INITIALIZER(struct cmd_acl_result, action, "reload");

cmdline_parse_token_string_t cmd_acl_show = TOKEN_STRING_INITIALIZER(struct cmd_acl_result, acl, "show");
cmdline_parse_token_string_t cmd_acl_acl = TOKEN_STRING_INITIALIZER(struct cmd_acl_result, action, "acl");

static cmdline_parse_inst_t * init_cmd_acl()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 3);
	cmd_showport->f = cmd_acl_parsed;
	cmd_showport->data = nullptr;
	cmd_showport->help_str = "acl reload";
	cmd_showport->tokens[0] = &cmd_acl.hdr;
	cmd_showport->tokens[1] = &cmd_acl_action.hdr;
	cmd_showport->tokens[2] = nullptr;
	return cmd_showport;
}

static cmdline_parse_inst_t * init_cmd_show_acl()
{
	static cmdline_parse_inst_t *cmd_showport = NULL;
	cmd_showport = (cmdline_parse_inst_t *)calloc(1, sizeof(cmdline_parse_inst_t) + sizeof(void *) * 3);
	cmd_showport->f = cmd_acl_parsed;
	cmd_showport->data = nullptr;
	cmd_showport->help_str = "show acl";
	cmd_showport->tokens[0] = &cmd_acl_show.hdr;
	cmd_showport->tokens[1] = &cmd_acl_acl.hdr;
	cmd_showport->tokens[2] = nullptr;
	return cmd_showport;
}



// end acl

CmdLineTask::CmdLineTask(int port, Poco::Net::IPAddress &ip):
	Task("CmdLineTask"),
	_logger(Poco::Logger::get("CmdLineTask")),
	_port(port),
	_max_connections(5)
{
	struct sockaddr_in serv_addr;
	_sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (_sockfd < 0)
		throw Poco::Exception("Can't create socket, error: %d", errno);
	int z = 1;
	int ret = ::setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, &z, sizeof(int));
	if (ret < 0)
		throw Poco::Exception("Setsockopt failed, error: %d", errno);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = *(uint32_t *)ip.addr();
	serv_addr.sin_port = htons(_port);

	if (::bind(_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		throw Poco::Exception("Can't binding, error %d", errno);

	if (::listen(_sockfd, _max_connections) < 0)
		throw Poco::Exception("Can't listening, error %d", errno);

	cmds.push_back(init_cmd_quit());
	cmds.push_back(init_cmd_showport());
	cmds.push_back(init_cmd_showport_json());
	cmds.push_back(init_cmd_showworker());
	cmds.push_back(init_cmd_showworker_json());
	cmds.push_back(init_cmd_showsub());
	cmds.push_back(init_cmd_notify());
	cmds.push_back(init_cmd_acl());
	cmds.push_back(init_cmd_show_acl());
	build_ctx();
}


CmdLineTask::~CmdLineTask()
{
	::close(_sockfd);
	for(auto const &cmd : cmds)
	{
		free(cmd);
	}
	free(_main_ctx);
}

void CmdLineTask::build_ctx()
{
	_main_ctx = (cmdline_parse_inst_t **)calloc(1, sizeof(cmdline_parse_inst_t *)*(cmds.size()+1));
	int i=0;
	for(auto const &cmd : cmds)
	{
		_main_ctx[i++] = cmd;
	}
}

static void * cmdline_thread(void *arg)
{
	struct cmdline *cl;
//	int ret;
//	uint8_t telnet_opt[] = {0xff, 0xfb, 0x03, 0xff, 0xfb, 0x01};
	char thread_name[RTE_MAX_THREAD_NAME_LEN];

	cl = (struct cmdline *)arg;

	snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, "extFilter cli");
	rte_thread_setname(pthread_self(), thread_name);

/*	ret = send(cl->s_out, telnet_opt, sizeof(telnet_opt), 0);
	if (ret != sizeof(telnet_opt))
	{
		throw Poco::Exception("Can't init telnet session");
	}
*/
	cmdline_interact(cl);
	cmdline_free(cl);
	return NULL;
}

void CmdLineTask::runTask()
{
	_logger.debug("Running CmdLineTask...");
	pthread_t tid = pthread_self();
	pthread_setname_np(tid, name().c_str());
	struct sockaddr_in cl_addr;
	socklen_t socklen = sizeof(cl_addr);
	struct cmdline *cl;
	struct pollfd fds[1];
	int nfds = 1;
	fds[0].events = POLLIN;
	fds[0].fd = _sockfd;
	int inst=0;
	while(!isCancelled())
	{
		int res = poll(fds, nfds, 500);
		if (res < 0) {
			if (errno == EINTR)
				break;
			_logger.error("Error during poll: %d", errno);
			break;
		}
		if (fds[0].revents & POLLIN)
		{
			int newsockfd = ::accept(_sockfd, (struct sockaddr *) &cl_addr, &socklen);
			if (newsockfd == -1)
			{
				_logger.error("Accept failed with error %d", errno);
				continue;
			}

			cl = cmdline_new(_main_ctx, "extfilter> ", newsockfd, newsockfd);
			if (cl == NULL)
			{
				_logger.fatal("Can't allocate memory for command line");
				throw Poco::Exception("Can't allocate memory for command line");
			}

			int ret = pthread_create(&tid, NULL, cmdline_thread, cl);
			if (ret)
			{
				_logger.fatal("Thread create failed");
				throw Poco::Exception("Thread create failed");
			}
			std::string thread_name("CmdLineTaskWorker-"+std::to_string(++inst));
			pthread_setname_np(tid, thread_name.c_str());
			ret = pthread_detach(tid);
			if (ret)
			{
				_logger.fatal("Thread detach failed");
				throw Poco::Exception("Thread detach failed");
			}
		}
	}
	_logger.debug("Stopping CmdLineTask...");
}


