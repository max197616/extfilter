
#include "flow.h"

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

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
			   flow->port_src == pkt_infos->port_dst &&
			   flow->proto ==pkt_infos->proto);
	else
		return 1;

}

flowHash::flowHash(int socket_id, int thread_id, uint32_t flowHashSizeIPv4, uint32_t flowHashSizeIPv6) : _logger(Poco::Logger::get("FlowHash_" + std::to_string(thread_id))),
	_flowHashSizeIPv4(flowHashSizeIPv4),
	_flowHashSizeIPv6(flowHashSizeIPv6)
{
	struct rte_hash_parameters ipv4_hash_params = {0};
	std::string ipv4_hash_name("ipv4_flow_hash_" + std::to_string(thread_id));
	ipv4_hash_params.entries = _flowHashSizeIPv4;
	ipv4_hash_params.key_len = sizeof(union ipv4_5tuple_host);
	ipv4_hash_params.hash_func = ipv4_hash_crc;
	ipv4_hash_params.hash_func_init_val = 0;
	ipv4_hash_params.name = ipv4_hash_name.c_str();
	ipv4_FlowHash = rte_hash_create(&ipv4_hash_params);
	if(!ipv4_FlowHash)
	{
		_logger.fatal("Unable to create ipv4 flow hash");
		throw Poco::Exception("Unable to create ipv4 flow hash");
	}
	rte_hash_set_cmp_func(ipv4_FlowHash, compare_ipv4);
	std::string ipv6_hash_name("ipv6_flow_hash_" + std::to_string(thread_id));
	struct rte_hash_parameters ipv6_hash_params = {0};
	ipv6_hash_params.entries = _flowHashSizeIPv6;
	ipv6_hash_params.key_len = sizeof(union ipv6_5tuple_host);
	ipv6_hash_params.hash_func = ipv6_hash_crc;
	ipv6_hash_params.hash_func_init_val = 0;
	ipv6_hash_params.name = ipv6_hash_name.c_str();
	ipv6_FlowHash = rte_hash_create(&ipv6_hash_params);
	if(!ipv4_FlowHash)
	{
		_logger.fatal("Unable to create ipv6 flow hash");
		throw Poco::Exception("Unable to create ipv6 flow hash");
	}
	rte_hash_set_cmp_func(ipv6_FlowHash, compare_ipv6);
}


flowHash::~flowHash()
{
	rte_hash_free(ipv4_FlowHash);
	rte_hash_free(ipv6_FlowHash);
}

