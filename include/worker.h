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

#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <iostream>
#include <Poco/Mutex.h>
#include <Poco/HashMap.h>
#include <Poco/Logger.h>
#include <rte_hash.h>
#include <rte_cycles.h>
#include <api.h>
#include "flow.h"
#include "stats.h"
#include "dpdk.h"
#include "sender.h"
#include "http.h"
#include "ssl.h"
#include "acl.h"
#include "cfg.h"

#define CERT_RESERVATION_SIZE 1024

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

class NotifyManager;
class ESender;

struct WorkerConfig
{
	bool block_ssl_no_sni;
	bool notify_enabled;
	NotifyManager *nm;

	uint8_t sender_port;
	uint16_t tx_queue_id;

	WorkerConfig()
	{
		block_ssl_no_sni = false;
		notify_enabled = false;
		nm = nullptr;
	}
};

class WorkerThread : public DpdkWorkerThread
{
	friend class ESender;
	friend class BWorkerThread;
private:
	WorkerConfig m_WorkerConfig;
	bool m_Stop;
	Poco::Logger& _logger;
	ThreadStats m_ThreadStats;


	uint64_t last_time;

	dpi_library_state_t *dpi_state;

	bool analyzePacket(struct rte_mbuf* mBuf, uint64_t timestamp);

//	bool analyzePacketIPv4(struct rte_mbuf* mBuf, uint64_t timestamp);

	dpi_identification_result_t getAppProtocol(uint8_t *host_key, uint64_t timestamp, uint32_t sig, dpi_pkt_infos_t *pkt_infos);
	dpi_identification_result_t identifyAppProtocol(const unsigned char* pkt, u_int32_t length, const uint8_t *l2_pkt, u_int32_t current_time, struct packet_info *pkt_info, uint32_t sig);

	bool checkSSL();
	std::string _name;
	bool _need_block;

	/// for sender through dpdk
	int _n_send_pkts;
//	struct filter_tx _sender_buf[EXTFILTER_WORKER_BURST_SIZE];
	struct rte_mbuf* _sender_buf[EXTFILTER_WORKER_BURST_SIZE];
	bool _sender_buf_flags[EXTFILTER_WORKER_BURST_SIZE];
	ESender *_snd;
	struct rte_mempool *_dpi_http_mempool;
	struct rte_mempool *_dpi_ssl_mempool;

	uint8_t _worker_id;
	uint32_t ipv4_flow_mask;
	uint32_t ipv6_flow_mask;

	struct packet_info _pkt_infos[EXTFILTER_CAPTURE_BURST_SIZE];
public:

	WorkerThread(uint8_t worker_id, const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, struct ESender::nparams &sp, struct rte_mempool *mp);
	~WorkerThread();

	bool checkURLBlocked(const char *host, size_t host_len, const char *uri, size_t uri_len, dpi_pkt_infos_t* pkt);
	bool checkSNIBlocked(const char *sni, size_t sni_len, dpi_pkt_infos_t* pkt);

	inline void setNeedBlock(bool b)
	{
		_need_block = b;
	}

	bool run(uint32_t coreId);

	void stop()
	{
		// assign the stop flag which will cause the main loop to end
		m_Stop = true;
	}

	inline ThreadStats& getStats()
	{
		return m_ThreadStats;
	}


	inline WorkerConfig& getConfig()
	{
		return m_WorkerConfig;
	}

	inline uint64_t getLastTime()
	{
		return last_time;
	}

	inline std::string &getThreadName()
	{
		return _name;
	}

	inline void clearStats()
	{
		m_ThreadStats.clear();
	}

	inline struct http::http_req_buf *allocateHTTPBuf()
	{
		struct http::http_req_buf *res;
		if(rte_mempool_get(_dpi_http_mempool, (void **)&res) != 0)
		{
			_logger.error("Unable to allocate memory for the http buffer");
			return nullptr;
		}
		res->init();
		res->mempool = _dpi_http_mempool;
		m_ThreadStats.dpi_alloc_http++;
		return res;
	}

	inline struct rte_mempool *getHTTPMempool()
	{
		return _dpi_http_mempool;
	}

	inline struct ssl_state *allocateSSLState()
	{
		struct ssl_state *res;
		if(rte_mempool_get(_dpi_ssl_mempool, (void **)&res) != 0)
		{
			_logger.error("Unable to allocate memory for the ssl buffer");
			return nullptr;
		}
		res->init();
		res->mempool = _dpi_ssl_mempool;
		m_ThreadStats.dpi_alloc_ssl++;
		return res;
	}

	inline struct rte_mempool *getSSLMempool()
	{
		return _dpi_ssl_mempool;
	}

	inline uint8_t getWorkerID()
	{
		return _worker_id;
	}

	// qconf - core config
	// n - number of packets
	// port - port to send
	inline int send_burst(struct lcore_conf *qconf, uint16_t n, uint16_t port)
	{
		struct rte_mbuf **m_table;
		int ret;
		uint16_t queueid;

		queueid = qconf->tx_queue_id[port];
		m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

		ret = rte_eth_tx_burst(port, queueid, m_table, n);
		if (unlikely(ret < n))
		{
			m_ThreadStats.tx_dropped += (n - ret);
			do {
				rte_pktmbuf_free(m_table[ret]);
			} while (++ret < n);
		}
		return 0;
	}

	/* Enqueue a single packet, and send burst if queue is filled */
	inline int send_single_packet(struct lcore_conf *qconf, struct rte_mbuf *m, uint16_t port)
	{
		uint16_t len;

		len = qconf->tx_mbufs[port].len;
		qconf->tx_mbufs[port].m_table[len] = m;
		len++;

		/* enough pkts to be sent */
		if (unlikely(len == EXTFILTER_WORKER_BURST_SIZE))
		{
			send_burst(qconf, EXTFILTER_WORKER_BURST_SIZE, port);
			len = 0;
		}

		qconf->tx_mbufs[port].len = len;
		return 0;
	}

};

static inline void parsePtype(struct rte_mbuf *m, struct packet_info *pkt_info)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;
	uint8_t *l3;
	int hdr_len;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;

	pkt_info->timestamp = rte_rdtsc(); // timestamp

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	l3 = (uint8_t *)eth_hdr + sizeof(struct ether_hdr);

	if(ether_type == ETHER_TYPE_VLAN || ether_type == 0x8847)
	{
		while(1)
		{
			if(ether_type == ETHER_TYPE_VLAN)
			{
				struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)(l3);
				ether_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
				l3 += sizeof(struct vlan_hdr);
			} else if(ether_type == 0x8847)
			{
				uint8_t bos = ((uint8_t *)l3)[2] & 0x1;
				l3 += 4;
				if(bos)
				{
					ether_type = ETHER_TYPE_IPv4;
					break;
				}
			} else
				break;
		}
	}

	if (ether_type == ETHER_TYPE_IPv4)
	{
		ipv4_hdr = (struct ipv4_hdr *)l3;
		hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
		if (hdr_len == sizeof(struct ipv4_hdr))
		{
			packet_type |= RTE_PTYPE_L3_IPV4;
			if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
				packet_type |= RTE_PTYPE_L4_TCP;
			else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
				packet_type |= RTE_PTYPE_L4_UDP;
		} else
			packet_type |= RTE_PTYPE_L3_IPV4_EXT;
	} else if (ether_type == ETHER_TYPE_IPv6)
	{
		ipv6_hdr = (struct ipv6_hdr *)l3;
		if (ipv6_hdr->proto == IPPROTO_TCP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		else if (ipv6_hdr->proto == IPPROTO_UDP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		else
			packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
	}
	m->packet_type = packet_type;
	pkt_info->l3 = l3;
	pkt_info->acl_res = ACL::ACL_DEFAULT_POLICY;
	m->userdata = pkt_info;
	uint32_t tcp_or_udp = packet_type & (RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP);
	uint32_t l3_ptypes = packet_type & RTE_PTYPE_L3_MASK;
	if(tcp_or_udp && (l3_ptypes == RTE_PTYPE_L3_IPV6))
	{
		void *ipv6_hdr = l3 + offsetof(struct ipv6_hdr, payload_len);
		void *data0 = ipv6_hdr;
		void *data1 = ((uint8_t *)ipv6_hdr) + sizeof(xmm_t);
		void *data2 = ((uint8_t *)ipv6_hdr) + sizeof(xmm_t) + sizeof(xmm_t);
		pkt_info->keys.ipv6_key.xmm[0] = em_mask_key(data0, mask1.x);
		pkt_info->keys.ipv6_key.xmm[1] = _mm_loadu_si128((__m128i *)(data1));
		pkt_info->keys.ipv6_key.xmm[2] = em_mask_key(data2, mask2.x);
		m->hash.usr = ipv6_hash_crc(&pkt_info->keys.ipv6_key,0,0);
	} else if (tcp_or_udp && (l3_ptypes == RTE_PTYPE_L3_IPV4))
	{
		void *ipv4_hdr = l3 + offsetof(struct ipv4_hdr, time_to_live);
		pkt_info->keys.ipv4_key.xmm = em_mask_key(ipv4_hdr, mask0.x);
		m->hash.usr = ipv4_hash_crc(&pkt_info->keys.ipv4_key,0,0);
	}
};

/*
 * Put one packet in acl_search struct according to the packet ol_flags
 */
static inline void prepare_one_packet(struct rte_mbuf** pkts_in, struct ACL::acl_search_t* acl, int index, struct packet_info *pkt_info)
{
	struct rte_mbuf* pkt = pkts_in[index];

	parsePtype(pkt, pkt_info);
	uint32_t l3_ptypes = pkt->packet_type & RTE_PTYPE_L3_MASK;

	// XXX we cannot filter non IP packet yet
	if (l3_ptypes == RTE_PTYPE_L3_IPV4)
	{
		/* Fill acl structure */
		acl->data_ipv4[acl->num_ipv4] = ((struct packet_info *)pkt->userdata)->l3 + offsetof(struct ipv4_hdr, next_proto_id);
		acl->m_ipv4[(acl->num_ipv4)++] = pkt;
	} else if (l3_ptypes == RTE_PTYPE_L3_IPV6)
	{
		/* Fill acl structure */
		acl->data_ipv6[acl->num_ipv6] = ((struct packet_info *)pkt->userdata)->l3 + offsetof(struct ipv6_hdr, proto);
		acl->m_ipv6[(acl->num_ipv6)++] = pkt;
	}
};

/*
 * Loop through all packets and classify them if acl_search if possible.
 */
static inline void prepare_acl_parameter(struct rte_mbuf** pkts_in, struct ACL::acl_search_t* acl, int nb_rx, struct packet_info *pkt_infos)
{
	int i = 0, j = 0;

	acl->num_ipv4 = 0;
	acl->num_ipv6 = 0;

#define PREFETCH()                                          \
	rte_prefetch0(rte_pktmbuf_mtod(pkts_in[i], void*)); \
	i++;                                                \
	j++;

	// we prefetch0 packets 3 per 3
	switch (nb_rx % PREFETCH_OFFSET) {
		while (nb_rx != i) {
		case 0:
			PREFETCH();
		case 2:
			PREFETCH();
		case 1:
			PREFETCH();
			while (j > 0)
			{
				prepare_one_packet(pkts_in, acl, i - j, &pkt_infos[i-j]);
				--j;
			}
		}
	}
};
