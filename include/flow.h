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

#include <string>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_vect.h>
#include <rte_hash_crc.h>
#include <rte_mempool.h>

#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>
#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/Task.h>
#include <api.h>

#include "params.h"
#include "arr.h"
#include "dtypes.h"

//#define _SIMPLE_HASH 1

extern "C" void dpi_reordering_tcp_delete_all_fragments(dpi_tracking_informations_t *victim);

void initFlowStorages();

#define IPV6_ADDR_LEN 16

struct flow_common_data_t
{
	uint64_t last_timestamp;
	uint8_t last_worker_id;
	uint8_t owner_worker_id;
	en_alfs_type_t alfs_type;
	uint32_t idx_alfs;
	int32_t hash_idx;
	bool blocked;
};

struct flow_base_t
{
	u_int16_t srcport;
	u_int16_t dstport;
	u_int8_t l4prot;
	dpi_flow_infos_t infos;
	uint64_t last_timestamp;
	flow_common_data_t cmn;

	inline void free_mem(dpi_flow_cleaner_callback* flow_cleaner_callback)
	{
		if(flow_cleaner_callback != nullptr && infos.tracking.flow_specific_user_data != nullptr)
			(*(flow_cleaner_callback))(infos.tracking.flow_specific_user_data);
		if(infos.tracking.http_informations[0].temp_buffer != nullptr)
			free(infos.tracking.http_informations[0].temp_buffer);
		if(infos.tracking.http_informations[1].temp_buffer != nullptr)
			free(infos.tracking.http_informations[1].temp_buffer);
		if(infos.tracking.ssl_information[0].pkt_buffer != nullptr)
			free(infos.tracking.ssl_information[0].pkt_buffer);
		if(infos.tracking.ssl_information[1].pkt_buffer != nullptr)
			free(infos.tracking.ssl_information[1].pkt_buffer);
		if(infos.tracking.ssl_information[0].mempool != nullptr)
			rte_mempool_put(((struct pool_holder_t*)infos.tracking.ssl_information[0].mempool)->mempool, infos.tracking.ssl_information[0].mempool);
		if(infos.tracking.ssl_information[1].mempool != nullptr)
			rte_mempool_put(((struct pool_holder_t*)infos.tracking.ssl_information[1].mempool)->mempool, infos.tracking.ssl_information[1].mempool);
		infos.tracking.flow_specific_user_data = nullptr;
		infos.tracking.http_informations[0].temp_buffer = nullptr;
		infos.tracking.http_informations[1].temp_buffer = nullptr;
		infos.tracking.ssl_information[0].pkt_buffer = nullptr;
		infos.tracking.ssl_information[1].pkt_buffer = nullptr;
		dpi_reordering_tcp_delete_all_fragments(&(infos.tracking));
		infos.tracking.segments[0] = nullptr;
		infos.tracking.segments[1] = nullptr;
	}

	inline void init_b(uint64_t tm, uint8_t owner_worker_id, uint8_t worker_id, uint32_t idx_alfs, int32_t hash_idx)
	{
		memset(this, 0, sizeof(struct flow_base_t));
		cmn.last_timestamp = tm;
		cmn.last_worker_id = worker_id;
		cmn.owner_worker_id = owner_worker_id;
		cmn.idx_alfs = idx_alfs;
		cmn.hash_idx = hash_idx;
	}

};

struct ext_dpi_flow_info_ipv4 : flow_base_t
{
	union src_addr{ /** Addresses mantained in network byte order. **/
		u_int32_t ipv4_srcaddr;
	} src_addr_t;
	union dst_addr{
		u_int32_t ipv4_dstaddr;
	} dst_addr_t;

	inline void init(uint64_t tm, uint8_t owner_worker_id, uint8_t worker_id, uint32_t idx_alfs, int32_t hash_idx)
	{
		init_b(tm, owner_worker_id, worker_id, idx_alfs, hash_idx);
//		src_addr_t.ipv4_srcaddr = 0;
//		dst_addr_t.ipv4_dstaddr = 0;
	}
} __rte_cache_aligned;

struct ext_dpi_flow_info_ipv6 : flow_base_t
{
	union src_addr{ /** Addresses mantained in network byte order. **/
		struct in6_addr ipv6_srcaddr;
	} src_addr_t;
	union dst_addr{
		struct in6_addr ipv6_dstaddr;
	} dst_addr_t;

	inline void init(uint64_t tm, uint8_t owner_worker_id, uint8_t worker_id, uint32_t idx_alfs, int32_t hash_idx)
	{
		init_b(tm, owner_worker_id, worker_id, idx_alfs, hash_idx);
	}

} __rte_cache_aligned;

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
} __rte_cache_aligned;

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

/// base class

class FlowStorage
{
public:
	struct cntrs
	{
		uint32_t alloc;
		uint64_t free;
		uint64_t reuse; // количество повторно использованных записей
	} counters;

	rte_mempool *mempool;
	rte_hash *hash;
	FlowStorage(rte_mempool *mempool_)
	{
		counters = { 0 };
		mempool = mempool_;
		hash = nullptr;
	}
	~FlowStorage()
	{
	}
	// initialize arrays
	virtual int init(flow_storage_params_t *prm) = 0;

};

class __rte_cache_aligned FlowStorageIPV4 : public FlowStorage
{
public:
	FlowStorageIPV4(flow_storage_params_t *prm);
	int init(flow_storage_params_t *prm);
	~FlowStorageIPV4();

	inline ext_dpi_flow_info_ipv4 *searchFlow(uint8_t *key, uint32_t sig, dpi_pkt_infos_t *pkt_infos, int32_t *idx)
	{
		int32_t ret = rte_hash_lookup_with_hash(hash, key, sig);
		if(ret >= 0)
		{
			*idx = ret;
			return data[ret];
		}
		return nullptr;
	}

	inline int removeFlow(int32_t idx)
	{
		void *key_ptr;
		if(unlikely(data[idx] == nullptr))
		{
			_logger.error("Data in the ipv4 hash at pos %d is null!", (int) idx);
			return -1;
		}
		int fr=rte_hash_get_key_with_position(hash, idx, &key_ptr);
		if(unlikely(fr < 0))
		{
			_logger.error("Key not found in the ipv4 hash for the position %d", (int) idx);
			return -1;
		} else {
			int32_t delr=rte_hash_del_key(hash, key_ptr);
			if(unlikely(delr < 0))
			{
				_logger.error("Error (%d) occured while delete data from the ipv4 flow hash table", (int)delr);
				return -1;
			}
			data[idx] = nullptr;
		}
		return 0;
	}

	inline int reuseFlow(uint8_t *key, uint32_t sig, ext_dpi_flow_info_ipv4 *node)
	{
		int32_t ret = rte_hash_add_key_with_hash(hash, key, sig);
		if(unlikely(ret == -EINVAL))
		{
			_logger.fatal("Bad parameters in hash add");
			return -1;
		}
		if(unlikely(ret == -ENOSPC))
		{
			_logger.fatal("There is no space in the ipv4 flow hash");
			return -1;
		}
		node->cmn.hash_idx = ret;
		data[ret] = node;
		counters.reuse++;
		return 0;
	}

	inline ext_dpi_flow_info_ipv4 *newFlow()
	{
		struct ext_dpi_flow_info_ipv4 *newflow;
		if(unlikely(rte_mempool_get(mempool, (void **)&newflow) != 0))
		{
			return nullptr;
		}
		counters.alloc++;
		return newflow;
	}

	inline int addFlow(uint8_t *key, uint32_t sig, ext_dpi_flow_info_ipv4 *node)
	{
		int32_t ret = rte_hash_add_key_with_hash(hash, key, sig);
		if(unlikely(ret == -EINVAL))
		{
			_logger.fatal("Bad parameters in hash add");
			return -1;
		}
		if(unlikely(ret == -ENOSPC))
		{
			_logger.fatal("There is no space in the ipv4 flow hash");
			return -1;
		}
		node->cmn.hash_idx = ret;
		data[ret] = node;
		return 0;
	}

	ext_dpi_flow_info_ipv4 **data;
	ArrayListFixedSize<ext_dpi_flow_info_ipv4> short_alfs;
	ArrayListFixedSize<ext_dpi_flow_info_ipv4> long_alfs;
private:
	Poco::Logger& _logger;
};


class __rte_cache_aligned FlowStorageIPV6 : public FlowStorage
{
public:
	FlowStorageIPV6(flow_storage_params_t *prm);
	int init(flow_storage_params_t *prm);
	~FlowStorageIPV6();

	inline ext_dpi_flow_info_ipv6 *searchFlow(uint8_t *key, uint32_t sig, dpi_pkt_infos_t *pkt_infos, int32_t *idx)
	{
		int32_t ret = rte_hash_lookup_with_hash(hash, key, sig);
		if(unlikely(ret >= 0))
		{
			*idx = ret;
			return data[ret];
		}
		return nullptr;
	}

	inline int removeFlow(int32_t idx)
	{
		void *key_ptr;
		if(unlikely(data[idx] == nullptr))
		{
			_logger.error("Data in the ipv6 hash at pos %d is null!", (int) idx);
			return -1;
		}
		int fr=rte_hash_get_key_with_position(hash, idx, &key_ptr);
		if(unlikely(fr < 0))
		{
			_logger.error("Key not found in the ipv6 hash for the position %d", (int) idx);
			return -1;
		} else {
			int32_t delr=rte_hash_del_key(hash, key_ptr);
			if(unlikely(delr < 0))
			{
				_logger.error("Error (%d) occured while delete data from the ipv6 flow hash table", (int)delr);
				return -1;
			}
			data[idx] = nullptr;
		}
		return 0;
	}

	inline int reuseFlow(uint8_t *key, uint32_t sig, ext_dpi_flow_info_ipv6 *node)
	{
		int32_t ret = rte_hash_add_key_with_hash(hash, key, sig);
		if(unlikely(ret == -EINVAL))
		{
			_logger.fatal("Bad parameters in hash add");
			return -1;
		}
		if(unlikely(ret == -ENOSPC))
		{
			_logger.fatal("There is no space in the ipv6 flow hash");
			return -1;
		}
		node->cmn.hash_idx = ret;
		data[ret] = node;
		counters.reuse++;
		return 0;
	}

	inline ext_dpi_flow_info_ipv6 *newFlow()
	{
		struct ext_dpi_flow_info_ipv6 *newflow;
		if(unlikely(rte_mempool_get(mempool, (void **)&newflow) != 0))
		{
			return nullptr;
		}
		counters.alloc++;
		return newflow;
	}

	inline int addFlow(uint8_t *key, uint32_t sig, ext_dpi_flow_info_ipv6 *node)
	{
		int32_t ret = rte_hash_add_key_with_hash(hash, key, sig);
		if(unlikely(ret == -EINVAL))
		{
			_logger.fatal("Bad parameters in hash add");
			return -1;
		}
		if(unlikely(ret == -ENOSPC))
		{
			_logger.fatal("There is no space in the ipv6 flow hash");
			return -1;
		}
		node->cmn.hash_idx = ret;
		data[ret] = node;
		return 0;
	}

	ext_dpi_flow_info_ipv6 **data;
	ArrayListFixedSize<ext_dpi_flow_info_ipv6> short_alfs;
	ArrayListFixedSize<ext_dpi_flow_info_ipv6> long_alfs;
private:
	Poco::Logger& _logger;

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
