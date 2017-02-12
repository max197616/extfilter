
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

int ndpi_workflow_node_cmp(const void *a, const void *b)
{
	
	struct ndpi_flow_info *fa = (struct ndpi_flow_info*)a;
	struct ndpi_flow_info *fb = (struct ndpi_flow_info*)b;

	if(fa->hash < fb->hash)
	{
		return -1;
	} else {
		if(fa->hash > fb->hash)
			return 1;
	}
/*	if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
	if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
	if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
	if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
	if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }
*/
	return(0);
}

flowHash::flowHash(int socket_id, int thread_id, int flowHashSize) : _logger(Poco::Logger::get("FlowHash_" + std::to_string(thread_id))),
	_flowHashSize(flowHashSize)
{
	struct rte_hash_parameters ipv4_hash_params = {0};
	std::string ipv4_hash_name("ipv4_flow_hash_" + std::to_string(thread_id));
	ipv4_hash_params.entries = _flowHashSize;
	ipv4_hash_params.key_len = sizeof(struct ipv4_5tuple);
	ipv4_hash_params.hash_func = DEFAULT_HASH_FUNC;
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
	ipv6_hash_params.key_len = sizeof(struct ipv6_5tuple);
	ipv6_hash_params.hash_func = DEFAULT_HASH_FUNC;
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


void flowHash::makeIPv4Key(struct ipv4_hdr *ipv4_hdr, struct ipv4_5tuple *key)
{
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;

	key->ip_dst = ipv4_hdr->dst_addr;
	key->ip_src = ipv4_hdr->src_addr;
	key->proto = ipv4_hdr->next_proto_id;

	switch (ipv4_hdr->next_proto_id)
	{
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
			key->port_dst = rte_be_to_cpu_16(tcp->dst_port);
			key->port_src = rte_be_to_cpu_16(tcp->src_port);
			break;

		case IPPROTO_UDP:
			udp = (struct udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
			key->port_dst = rte_be_to_cpu_16(udp->dst_port);
			key->port_src = rte_be_to_cpu_16(udp->src_port);
			break;

		default:
			key->port_dst = 0;
			key->port_src = 0;
			break;
	}
}

void flowHash::makeIPv6Key(struct ipv6_hdr *ipv6_hdr, struct ipv6_5tuple *key)
{
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;

	rte_mov16(key->ip_dst, (const uint8_t*) ipv6_hdr->dst_addr);
	rte_mov16(key->ip_src, (const uint8_t*) ipv6_hdr->src_addr);

	key->proto = ipv6_hdr->proto;

	switch (ipv6_hdr->proto)
	{
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *)((unsigned char *) ipv6_hdr + sizeof(struct ipv6_hdr));
			key->port_dst = rte_be_to_cpu_16(tcp->dst_port);
			key->port_src = rte_be_to_cpu_16(tcp->src_port);
			break;

		case IPPROTO_UDP:
			udp = (struct udp_hdr *)((unsigned char *) ipv6_hdr + sizeof(struct ipv6_hdr));
			key->port_dst = rte_be_to_cpu_16(udp->dst_port);
			key->port_src = rte_be_to_cpu_16(udp->src_port);
			break;

		default:
			key->port_dst = 0;
			key->port_src = 0;
			break;
	}
}

void flowHash::makeIPKey(Poco::Net::IPAddress &src_ip, Poco::Net::IPAddress &dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol, struct ip_5tuple *key)
{
	if(src_ip.family() == Poco::Net::IPAddress::IPv4)
	{
		memset(key->ip_dst, 0, sizeof(key->ip_dst));
		memset(key->ip_src, 0, sizeof(key->ip_src));
		memcpy(key->ip_dst, dst_ip.addr(), 4);
		memcpy(key->ip_src, src_ip.addr(), 4);
		key->proto = protocol;

		key->port_dst = rte_be_to_cpu_16(dst_port);
		key->port_src = rte_be_to_cpu_16(src_port);
	}
	if(src_ip.family() == Poco::Net::IPAddress::IPv6)
	{
		rte_mov16(key->ip_dst, (const uint8_t*) dst_ip.addr());
		rte_mov16(key->ip_src, (const uint8_t*) src_ip.addr());
		key->proto = protocol;
		key->port_dst = rte_be_to_cpu_16(dst_port);
		key->port_src = rte_be_to_cpu_16(src_port);
	}
}