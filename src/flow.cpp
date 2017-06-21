
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


flowHash::flowHash(int socket_id, int thread_id, int flowHashSize) : _logger(Poco::Logger::get("FlowHash_" + std::to_string(thread_id))),
	_flowHashSize(flowHashSize)
{
	struct rte_hash_parameters ipv4_hash_params = {0};
	std::string ipv4_hash_name("ipv4_flow_hash_" + std::to_string(thread_id));
	ipv4_hash_params.entries = _flowHashSize;
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
	std::string ipv6_hash_name("ipv6_flow_hash_" + std::to_string(thread_id));
	struct rte_hash_parameters ipv6_hash_params = {0};
	ipv6_hash_params.entries = _flowHashSize;
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
}


flowHash::~flowHash()
{
	rte_hash_free(ipv4_FlowHash);
	rte_hash_free(ipv6_FlowHash);
}

