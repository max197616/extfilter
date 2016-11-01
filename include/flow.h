
#pragma once

#include <ndpi_api.h>
#include <string>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <Poco/Logger.h>
#include "utils.h"

#define FLOW_HASH_ENTRIES (1024*1024) // default 1M. Must be power of 2.

//#define FLOW_HASH_ENTRIES (250000) // default 1M
#define FLOW_PURGE_FRACTION 32 // work 1/N at:
#define FLOW_PURGE_FREQUECY 1 // seconds

#define FLOW_IDLE_TIME 30 // seconds

#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))


struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));

#define IPV6_ADDR_LEN 16

struct ipv6_5tuple {
	uint8_t  ip_dst[IPV6_ADDR_LEN];
	uint8_t  ip_src[IPV6_ADDR_LEN];
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));

struct ip_5tuple
{
	uint8_t  ip_dst[IPV6_ADDR_LEN];
	uint8_t  ip_src[IPV6_ADDR_LEN];
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));


// flow tracking
struct ndpi_flow_info
{
	uint32_t hash;
	bool detection_completed;
	struct ndpi_flow_struct *ndpi_flow;
	u_int8_t ip_version;
	u_int64_t last_seen;
	u_int64_t bytes;
	u_int32_t packets;
	// keys
	union
	{
		struct ipv4_5tuple ipv4_key;
		struct ipv6_5tuple ipv6_key;
	} keys;

	ndpi_protocol detected_protocol;


	void *src_id;
	void *dst_id;

	uint64_t expire;
	bool cli2srv_direction;
	ndpi_flow_info(uint8_t ip_ver, uint64_t l_seen) :
		hash(0),
		detection_completed(false),
		ndpi_flow(NULL),
		ip_version(ip_ver),
		last_seen(l_seen),
		bytes(0),
		packets(0),
		src_id(NULL),
		dst_id(NULL),
		expire(0),
		cli2srv_direction(true)
	{
	}

	ndpi_flow_info() :
		hash(0),
		detection_completed(false),
		ndpi_flow(NULL),
		ip_version(0),
		last_seen(0),
		bytes(0),
		packets(0),
		src_id(NULL),
		dst_id(NULL),
		expire(0),
		cli2srv_direction(true)
	{ }

	bool isIdle(uint64_t time)
	{
		return (expire < time);
	}
	
	void free_mem()
	{
		ndpi_free_flow(ndpi_flow);
		if(src_id)
			free(src_id);
		if(dst_id)
			free(dst_id);
	}
};

class flowHash
{
private:
	Poco::Logger& _logger;
	struct rte_hash *ipv4_FlowHash;
	struct rte_hash *ipv6_FlowHash;
public:
	flowHash(int socket_id);
	~flowHash();
	inline struct rte_hash *getIPv4Hash()
	{
		return ipv4_FlowHash;
	}
	inline struct rte_hash *getIPv6Hash()
	{
		return ipv6_FlowHash;
	}

	void makeIPv4Key(struct ipv4_hdr *ipv4_hdr, struct ipv4_5tuple *key);
	void makeIPv6Key(struct ipv6_hdr *ipv6_hdr, struct ipv6_5tuple *key);
	void makeIPKey(Poco::Net::IPAddress &src_ip, Poco::Net::IPAddress &dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol, struct ip_5tuple *key);
};

