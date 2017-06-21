
#pragma once

#include <string>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_vect.h>
#include <rte_hash_crc.h>
#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>
#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/Task.h>

#include "flowtrk.h"

/*
 * FlowHash создается на каждый worker.
*/


#define FLOW_HASH_ENTRIES (1024*1024) // default 1M. Must be power of 2.

//#define FLOW_HASH_ENTRIES (250000) // default 1M
#define FLOW_PURGE_FRACTION 32 // work 1/N at:
#define FLOW_PURGE_FREQUECY 1 // seconds

#define FLOW_IDLE_TIME 30 // seconds

#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))


#define __FLOW_TRACKING 1

#define IPV6_ADDR_LEN 16

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	xmm_t xmm;
};

#define XMM_NUM_IN_IPV6_5TUPLE 3

union ipv6_5tuple_host {
	struct {
		uint16_t pad0;
		uint8_t  proto;
		uint8_t  pad1;
		uint8_t  ip_src[IPV6_ADDR_LEN];
		uint8_t  ip_dst[IPV6_ADDR_LEN];
		uint16_t port_src;
		uint16_t port_dst;
		uint64_t reserve;
	};
	xmm_t xmm[XMM_NUM_IN_IPV6_5TUPLE];
};

// структура, создаваемая для прикрепления к udata in the mbuf
struct packet_info
{
	union
	{
		union ipv4_5tuple_host ipv4_key;
		union ipv6_5tuple_host ipv6_key;
	} keys;
	uint8_t *l3;
	uint64_t timestamp; // packet timestamp (ticks)
	uint32_t acl_res; // result of acl_classify
};

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
	u_int8_t ip_version;
	u_int64_t last_seen;
	u_int64_t bytes;
	u_int32_t packets;
	struct http
	{
		char *url;
		uint8_t method;
	} http;
	struct ssl
	{
		char *client_certificate;
	} ssl;
	uint8_t l7_proto;
	int seen_flows;
#ifdef __FLOW_TRACKING
	FlowTracker *flow_tracker;
#endif
	uint64_t expire;
	bool cli2srv_direction;
	bool block;
	ndpi_flow_info(uint8_t ip_ver, uint64_t l_seen) :
		hash(0),
		detection_completed(false),
		ip_version(ip_ver),
		last_seen(l_seen),
		bytes(0),
		packets(0),
		expire(0),
		cli2srv_direction(true),
		block(false)
	{
	}

	ndpi_flow_info() :
		hash(0),
		detection_completed(false),
		ip_version(0),
		last_seen(0),
		bytes(0),
		packets(0),
		expire(0),
		cli2srv_direction(true),
		block(false)
	{
	}

	bool isIdle(uint64_t time)
	{
		return (expire < time);
	}
	
	void free_mem()
	{
		if(flow_tracker)
			delete flow_tracker;
		if(http.url)
			free(http.url);
		if(ssl.client_certificate)
			free(ssl.client_certificate);
	}
};

class flowHash
{
private:
	Poco::Logger& _logger;
	struct rte_hash *ipv4_FlowHash;
	struct rte_hash *ipv6_FlowHash;
	int _flowHashSize;
public:
	flowHash(int socket_id, int thread_id, int flowHashSize=FLOW_HASH_ENTRIES);
	~flowHash();
	inline struct rte_hash *getIPv4Hash()
	{
		return ipv4_FlowHash;
	}
	inline struct rte_hash *getIPv6Hash()
	{
		return ipv6_FlowHash;
	}

/*	void makeIPv4Key(struct ipv4_hdr *ipv4_hdr, struct ipv4_5tuple *key);
	void makeIPv6Key(struct ipv6_hdr *ipv6_hdr, struct ipv6_5tuple *key);
	void makeIPKey(Poco::Net::IPAddress &src_ip, Poco::Net::IPAddress &dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol, struct ip_5tuple *key);*/
	inline int getHashSize()
	{
		return _flowHashSize;
	}
};

static inline uint32_t ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = (const union ipv4_5tuple_host *)data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
	return init_val;
}

static inline uint32_t ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const union ipv6_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;
	const uint32_t  *ip_src0, *ip_src1, *ip_src2, *ip_src3;
	const uint32_t  *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
	k = (const union ipv6_5tuple_host *)data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;
	ip_src0 = (const uint32_t *) k->ip_src;
	ip_src1 = (const uint32_t *)(k->ip_src+4);
	ip_src2 = (const uint32_t *)(k->ip_src+8);
	ip_src3 = (const uint32_t *)(k->ip_src+12);
	ip_dst0 = (const uint32_t *) k->ip_dst;
	ip_dst1 = (const uint32_t *)(k->ip_dst+4);
	ip_dst2 = (const uint32_t *)(k->ip_dst+8);
	ip_dst3 = (const uint32_t *)(k->ip_dst+12);
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(*ip_src0, init_val);
	init_val = rte_hash_crc_4byte(*ip_src1, init_val);
	init_val = rte_hash_crc_4byte(*ip_src2, init_val);
	init_val = rte_hash_crc_4byte(*ip_src3, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
	return init_val;
}

#if defined(__SSE2__)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	__m128i data = _mm_loadu_si128((__m128i *)(key));

	return _mm_and_si128(data, mask);
}
#elif defined(RTE_MACHINE_CPUFLAG_NEON)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	int32x4_t data = vld1q_s32((int32_t *)key);

	return vandq_s32(data, mask);
}
#elif defined(RTE_MACHINE_CPUFLAG_ALTIVEC)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	xmm_t data = vec_ld(0, (xmm_t *)(key));

	return vec_and(data, mask);
}
#else
#error No vector engine (SSE, NEON, ALTIVEC) available, check your toolchain
#endif

#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
#define BIT_16_TO_23 0x00ff0000

extern rte_xmm_t mask0;
extern rte_xmm_t mask1;
extern rte_xmm_t mask2;
