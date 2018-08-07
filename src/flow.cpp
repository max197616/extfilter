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

#include "flow.h"
#include "params.h"
#include "cfg.h"

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <Poco/Util/ServerApplication.h>

//#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
//#else
//#include <rte_jhash.h>
//#define DEFAULT_HASH_FUNC       rte_jhash
//#endif

rte_xmm_t mask0 = {.u32 = {BIT_8_TO_15, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS} };
rte_xmm_t mask1 = {.u32 = {BIT_16_TO_23, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS} };
rte_xmm_t mask2 = {.u32 = {ALL_32_BITS, ALL_32_BITS, 0, 0} };

static int compare_ipv4(const void *key1, const void *key2, size_t key_len)
{
	ipv4_5tuple_host *flow = (ipv4_5tuple_host *) key1;
	ipv4_5tuple_host *pkt_infos = (ipv4_5tuple_host *) key2;

	return !((flow->ip_src == pkt_infos->ip_src &&
		 flow->ip_dst == pkt_infos->ip_dst &&
		 flow->port_src == pkt_infos->port_src &&
		 flow->port_dst == pkt_infos->port_dst) ||
		(flow->ip_src == pkt_infos->ip_dst &&
		 flow->ip_dst == pkt_infos->ip_src &&
		 flow->port_src == pkt_infos->port_dst &&
		 flow->port_dst == pkt_infos->port_src)) &&
		 flow->proto == pkt_infos->proto;
}

static int compare_ipv6(const void *key1, const void *key2, size_t key_len)
{
	ipv6_5tuple_host *flow = (ipv6_5tuple_host *) key1;
	ipv6_5tuple_host *pkt_infos = (ipv6_5tuple_host *) key2;

	u_int8_t i;

	/*1: src=src and dst=dst. 2: src=dst and dst=src. */
	u_int8_t direction=0;

	for(i=0; i< 16; i++)
	{
		if(direction!=2 &&
		  pkt_infos->ip_src[i] == flow->ip_src[i] &&
		  pkt_infos->ip_dst[i] == flow->ip_dst[i])
		{
			direction=1;
		}else if(direction!=1 &&
			  pkt_infos->ip_src[i] == flow->ip_dst[i] &&
			  pkt_infos->ip_dst[i] == flow->ip_src[i])
		{
			direction=2;
		}else
			return 1;
	}

	if(direction==1)
		return !(flow->port_src == pkt_infos->port_src &&
			   flow->port_dst == pkt_infos->port_dst &&
			   flow->proto == pkt_infos->proto);
	else if(direction==2)
		return !(flow->port_src == pkt_infos->port_dst &&
			   flow->port_dst == pkt_infos->port_src &&
			   flow->proto == pkt_infos->proto);
	else
		return 1;

}

void initFlowStorages()
{
	int socketid = 0;
	Poco::Util::Application& app = Poco::Util::Application::instance();

	// allocate mempool for all flows
	app.logger().information("Allocating %Lu bytes (%u entries) for ipv4 flow pool", (uint64_t) ((global_prm->memory_configs.ipv4.flows_number)*sizeof(struct ext_dpi_flow_info_ipv4)), global_prm->memory_configs.ipv4.flows_number);
	rte_mempool *flows_pool_ipv4 = rte_mempool_create("ipv4_flows_p", global_prm->memory_configs.ipv4.flows_number, sizeof(struct ext_dpi_flow_info_ipv4), 0, 0, NULL, NULL, NULL, NULL, socketid, 0);
	if(flows_pool_ipv4 == nullptr)
	{
		app.logger().fatal("Not enough memory for ipv4 flows pool. Tried to allocate %Lu bytes on socket %d", (uint64_t) ((global_prm->memory_configs.ipv4.flows_number)*sizeof(struct ext_dpi_flow_info_ipv4)), socketid);
		throw Poco::Exception("Not enough memory for flows pool");
	}

	app.logger().information("Allocating %Lu bytes (%u entries) for ipv6 flow pool", (uint64_t) ((global_prm->memory_configs.ipv6.flows_number)*sizeof(struct ext_dpi_flow_info_ipv6)), global_prm->memory_configs.ipv6.flows_number);

	rte_mempool *flows_pool_ipv6 = rte_mempool_create("ipv6_flows_p", (global_prm->memory_configs.ipv6.flows_number), sizeof(struct ext_dpi_flow_info_ipv6), 0, 0, NULL, NULL, NULL, NULL, socketid, 0);
	if(flows_pool_ipv6 == nullptr)
	{
		app.logger().fatal("Not enough memory for ipv6 flows pool. Tried to allocate %Lu bytes on socket %d", (uint64_t) ((global_prm->memory_configs.ipv6.flows_number )*sizeof(struct ext_dpi_flow_info_ipv6)), socketid);
		throw Poco::Exception("Not enough memory for flows pool");
	}

	flow_storage_params_t prm;
	prm.p_lifetime = global_prm->flow_lifetime;
	for(int i=0; i < global_prm->workers_number; i++)
	{
		prm.worker_id = i;
		prm.mempool = flows_pool_ipv4;
		prm.recs_number = global_prm->memory_configs.ipv4.recs_number / global_prm->memory_configs.ipv4.parts_of_flow;
		flow_storage_t *flows = &worker_params[i].flows_ipv4;
		if(global_prm->memory_configs.ipv4.parts_of_flow > 0)
		{
			flows->flows = new (std::nothrow) FlowStorage*[global_prm->memory_configs.ipv4.parts_of_flow];
			if(!flows->flows)
			{
				app.logger().fatal("Not enough memory for FlowStorage pointers");
				throw Poco::Exception("Not enough memory for FlowStorage pointers");
			}
			memset(flows->flows, 0, sizeof(FlowStorage *)*global_prm->memory_configs.ipv4.parts_of_flow);
			for(int z=0; z < global_prm->memory_configs.ipv4.parts_of_flow; z++)
			{
				prm.part_no = z;
				flows->flows[z] = new FlowStorageIPV4(&prm);
				if(flows->flows[z]->init(&prm))
				{
					app.logger().fatal("Unable to init FlowStorageIPV4");
					throw Poco::Exception("Unable to init FlowStorageIPV4");
				}
			}
		}

		prm.mempool = flows_pool_ipv6;
		prm.recs_number = global_prm->memory_configs.ipv6.recs_number / global_prm->memory_configs.ipv6.parts_of_flow;
		flows = &worker_params[i].flows_ipv6;
		// setup ipv6
		if(global_prm->memory_configs.ipv6.parts_of_flow > 0)
		{
			flows->flows = new (std::nothrow) FlowStorage*[global_prm->memory_configs.ipv6.parts_of_flow];
			if(!flows->flows)
			{
				app.logger().fatal("Not enough memory for FlowStorage pointers");
				throw Poco::Exception("Not enough memory for FlowStorage pointers");
			}
			memset(flows->flows, 0, sizeof(FlowStorage *)*global_prm->memory_configs.ipv6.parts_of_flow);
			for(int z=0; z < global_prm->memory_configs.ipv6.parts_of_flow; z++)
			{
				prm.part_no = z;
				flows->flows[z] = new FlowStorageIPV6(&prm);
				if(flows->flows[z]->init(&prm))
				{
					app.logger().fatal("Unable to init FlowStorageIPV6");
					throw Poco::Exception("Unable to init FlowStorageIPV6");
				}
			}
		}

	}
}

// ipv4
FlowStorageIPV4::FlowStorageIPV4(flow_storage_params_t *prm) : FlowStorage(prm->mempool),
	_logger(Poco::Logger::get("FlowStorageIPV4"))
{
	// init hash
	_logger.information("Allocate %d bytes (%d entries, element size %z) for flow hash ipv4", (int)(prm->recs_number * sizeof(union ipv4_5tuple_host)), (int)prm->recs_number, sizeof(union ipv4_5tuple_host));
	struct rte_hash_parameters ipv4_hash_params = {0};
	ipv4_hash_params.entries = prm->recs_number;
	ipv4_hash_params.key_len = sizeof(union ipv4_5tuple_host);
	ipv4_hash_params.hash_func = ipv4_hash_crc;
	ipv4_hash_params.hash_func_init_val = 0;
	std::string hash_name("ipv4_fh" + std::to_string(prm->worker_id) + "_" + std::to_string(prm->part_no));
	ipv4_hash_params.name = hash_name.c_str();
	hash = rte_hash_create(&ipv4_hash_params);
	if(!hash)
	{
		_logger.fatal("Unable to create ipv4 flow hash");
		throw Poco::Exception("Unable to create ipv4 flow hash");
	}
	rte_hash_set_cmp_func(hash, compare_ipv4);

	// init pointers for hash data
	std::string mem_name("ipv4_f" + std::to_string(prm->worker_id) + "_" + std::to_string(prm->part_no));
	_logger.information("Allocating %d bytes (%d entries) for ipv4_flows", (int) (sizeof(struct ext_dpi_flow_info_ipv4 *) * prm->recs_number), (int)prm->recs_number);
	data = (struct ext_dpi_flow_info_ipv4 **)rte_zmalloc(mem_name.c_str(), prm->recs_number * sizeof(struct ext_dpi_flow_info_ipv4 *), RTE_CACHE_LINE_SIZE);
	if(data == nullptr)
	{
		_logger.fatal("Not enough memory for ipv4 flows");
		throw Poco::Exception("Not enough memory for ipv4 flows");
	}
	
}

FlowStorageIPV4::~FlowStorageIPV4()
{
	// delete hash
	rte_hash_free(hash);
	// delete data
	rte_free(data);
}

int FlowStorageIPV4::init(flow_storage_params_t *prm)
{
	if(short_alfs.init(prm->recs_number, prm->worker_id, en_alfs_short, prm->p_lifetime[0], 32))
		return -1;
	return long_alfs.init(prm->recs_number, prm->worker_id, en_alfs_long, prm->p_lifetime[1], 8);
}

// ipv6
FlowStorageIPV6::FlowStorageIPV6(flow_storage_params_t *prm) : FlowStorage(prm->mempool),
	_logger(Poco::Logger::get("FlowStorageIPV6"))
{
	// init hash
	_logger.information("Allocate %d bytes (%d entries, element size %z) for flow hash ipv6", (int)(prm->recs_number * sizeof(union ipv6_5tuple_host)), (int)prm->recs_number, sizeof(union ipv6_5tuple_host));
	struct rte_hash_parameters ipv6_hash_params = {0};
	ipv6_hash_params.entries = prm->recs_number;
	ipv6_hash_params.key_len = sizeof(union ipv6_5tuple_host);
	ipv6_hash_params.hash_func = ipv6_hash_crc;
	ipv6_hash_params.hash_func_init_val = 0;
	std::string hash_name("ipv6_fh" + std::to_string(prm->worker_id) + "_" + std::to_string(prm->part_no));
	ipv6_hash_params.name = hash_name.c_str();
	hash = rte_hash_create(&ipv6_hash_params);
	if(!hash)
	{
		_logger.fatal("Unable to create ipv6 flow hash");
		throw Poco::Exception("Unable to create ipv6 flow hash");
	}
	rte_hash_set_cmp_func(hash, compare_ipv6);
	// init pointers for hash data
	std::string mem_name("ipv6_f" + std::to_string(prm->worker_id) + "_" + std::to_string(prm->part_no));
	_logger.information("Allocating %d bytes (%d entries) for ipv6_flows", (int) (sizeof(struct ext_dpi_flow_info_ipv6 *) * prm->recs_number), (int)prm->recs_number);
	data = (struct ext_dpi_flow_info_ipv6 **)rte_zmalloc(mem_name.c_str(), prm->recs_number * sizeof(struct ext_dpi_flow_info_ipv6 *), RTE_CACHE_LINE_SIZE);
	if(data == nullptr)
	{
		_logger.fatal("Not enough memory for ipv6 flows");
		throw Poco::Exception("Not enough memory for ipv6 flows");
	}
}

FlowStorageIPV6::~FlowStorageIPV6()
{
	// delete hash
	rte_hash_free(hash);
	// delete data
	rte_free(data);
}

int FlowStorageIPV6::init(flow_storage_params_t *prm)
{
	if(short_alfs.init(prm->recs_number, prm->worker_id, en_alfs_short, prm->p_lifetime[0], 32))
		return -1;
	return long_alfs.init(prm->recs_number, prm->worker_id, en_alfs_long, prm->p_lifetime[1], 8);
}
