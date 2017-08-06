
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
#include <api.h>

//#define _SIMPLE_HASH 1

extern "C" void dpi_reordering_tcp_delete_all_fragments(dpi_tracking_informations_t *victim);

#define IPV6_ADDR_LEN 16

struct ext_dpi_flow_info
{
	
	u_int16_t srcport;
	u_int16_t dstport;
	u_int8_t l4prot;

	union src_addr{ /** Addresses mantained in network byte order. **/
		struct in6_addr ipv6_srcaddr;
		u_int32_t ipv4_srcaddr;
	} src_addr_t;
	union dst_addr{
		struct in6_addr ipv6_dstaddr;
		u_int32_t ipv4_dstaddr;
	} dst_addr_t;

	dpi_flow_infos_t infos;
	uint64_t last_timestamp;
//	u_int64_t bytes;
//	u_int32_t packets;

	inline void free_mem(dpi_flow_cleaner_callback* flow_cleaner_callback)
	{
		if(flow_cleaner_callback != nullptr)
			(*(flow_cleaner_callback))(infos.tracking.flow_specific_user_data);
		if(infos.tracking.http_informations[0].temp_buffer != nullptr)
			free(infos.tracking.http_informations[0].temp_buffer);
		if(infos.tracking.http_informations[1].temp_buffer != nullptr)
			free(infos.tracking.http_informations[1].temp_buffer);
		if(infos.tracking.ssl_information[0].pkt_buffer != nullptr)
			free(infos.tracking.ssl_information[0].pkt_buffer);
		if(infos.tracking.ssl_information[1].pkt_buffer != nullptr)
			free(infos.tracking.ssl_information[1].pkt_buffer);
		dpi_reordering_tcp_delete_all_fragments(&(infos.tracking));
	}
};


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


#ifdef __SIMPLE_HASH
static inline uint32_t ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const union ipv4_5tuple_host *in = (const union ipv4_5tuple_host *)data;
	return in->port_src+in->port_dst+in->ip_src+in->ip_dst+in->proto+init_val;
}


static inline uint32_t ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const union ipv6_5tuple_host *in = (const union ipv6_5tuple_host *)data;
	u_int8_t i;
	u_int32_t partsrc = 0, partdst = 0;
	for(i=0; i< 16; i++){
		partsrc += in->ip_src[i];
		partdst += in->ip_dst[i];
	}
	return in->port_src+in->port_dst+partsrc+partdst+in->proto+init_val;
}

#else

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

#endif

/// rte_hash holder
class flowHash
{
private:
	Poco::Logger& _logger;
	struct rte_hash *ipv4_FlowHash;
	struct rte_hash *ipv6_FlowHash;
	uint32_t _flowHashSizeIPv4;
	uint32_t _flowHashSizeIPv6;
public:
	flowHash(int socket_id, int thread_id, uint32_t flowHashSizeIPv4, uint32_t flowHashSizeIPv6);
	~flowHash();
	inline struct rte_hash *getIPv4Hash()
	{
		return ipv4_FlowHash;
	}
	inline struct rte_hash *getIPv6Hash()
	{
		return ipv6_FlowHash;
	}
	inline uint32_t getHashSizeIPv4()
	{
		return _flowHashSizeIPv4;
	}
	inline uint32_t getHashSizeIPv6()
	{
		return _flowHashSizeIPv6;
	}

};


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
