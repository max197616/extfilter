#include <cinttypes>
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/NumberParser.h>
#include <Poco/FileStream.h>
#include <Poco/TaskManager.h>
#include <Poco/StringTokenizer.h>
#include <Poco/URI.h>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <sys/resource.h>
#include <cmath>
#include "worker.h"
#include "main.h"
#include "dpi.h"
#include <api.h>

#include "AhoCorasickPlus.h"
#include "sendertask.h"
#include "statistictask.h"
#include "reloadtask.h"
#include "acl.h"
#include "cmdlinetask.h"
#include "notification.h"
#include "config.h"

#define MBUF_CACHE_SIZE 256

#define DPDK_CONFIG_HEADER_SPLIT	0 /**< Header Split disabled */
#define DPDK_CONFIG_SPLIT_HEADER_SIZE	0
#define DPDK_CONFIG_HW_IP_CHECKSUM	0 /**< IP checksum offload disabled */
#define DPDK_CONFIG_HW_VLAN_FILTER	0 /**< VLAN filtering disabled */
#define DPDK_CONFIG_JUMBO_FRAME		0 /**< Jumbo Frame Support disabled */
#define DPDK_CONFIG_HW_STRIP_CRC	0 /**< CRC stripped by hardware disabled */
#define DPDK_CONFIG_MQ_MODE		ETH_MQ_RX_RSS

uint64_t extFilter::_tsc_hz;

extFilter *extFilter::_instance = NULL;

struct rte_mempool *extFilter::packet_info_pool[NB_SOCKETS];
struct ether_addr extFilter::ports_eth_addr[RTE_MAX_ETHPORTS];
uint8_t port_types[RTE_MAX_ETHPORTS];
struct lcore_conf extFilter::_lcore_conf[RTE_MAX_LCORE];

uint8_t sender_mac[6];

void flow_delete_cb(void* flow_specific_user_data)
{
	if(flow_specific_user_data)
	{
		struct dpi_flow_info *u = (struct dpi_flow_info *) flow_specific_user_data;
		u->free_mem();
		if(u->dpi_mempool == nullptr)
			free(u);
		else
			rte_mempool_put(u->dpi_mempool, u);
	}
}

extFilter::extFilter(): _helpRequested(false),
	_listDPDKPorts(false),
	_numa_on(1),
	_enabled_port_mask(0)
{
	for(int i=0; i < NB_SOCKETS; i++)
	{
		_pktmbuf_pool[i] = NULL;
		packet_info_pool[i] = NULL;
	}
	for(int i=0; i < RTE_MAX_LCORE; i++)
	{
		memset(&_lcore_conf[i], 0, sizeof(lcore_conf));
	}
	_instance = this;
//	Poco::ErrorHandler::set(&_errorHandler);
}


extFilter::~extFilter()
{
}


uint8_t m_RSSKey[40] = {
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

static inline unsigned get_port_max_rx_queues(uint8_t port_id)
{
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(port_id, &dev_info);
	return dev_info.max_rx_queues;
}

static inline unsigned get_port_max_tx_queues(uint8_t port_id)
{
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(port_id, &dev_info);
	return dev_info.max_tx_queues;
}


static inline void em_parse_ptype(struct rte_mbuf *m)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;
	uint8_t *l3;
	int hdr_len;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;

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

	if (ether_type == ETHER_TYPE_IPv4) {
		ipv4_hdr = (struct ipv4_hdr *)l3;
		hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
		if (hdr_len == sizeof(struct ipv4_hdr)) {
			packet_type |= RTE_PTYPE_L3_IPV4;
			if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
				packet_type |= RTE_PTYPE_L4_TCP;
			else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
				packet_type |= RTE_PTYPE_L4_UDP;
		} else
			packet_type |= RTE_PTYPE_L3_IPV4_EXT;
	} else if (ether_type == ETHER_TYPE_IPv6) {
		ipv6_hdr = (struct ipv6_hdr *)l3;
		if (ipv6_hdr->proto == IPPROTO_TCP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		else if (ipv6_hdr->proto == IPPROTO_UDP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		else
			packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
	}
	m->packet_type = packet_type;
	struct packet_info *pkt_info;
	if(rte_mempool_get(extFilter::getPktInfoPool(), (void **)&pkt_info) != 0)
	{
		Poco::Util::Application& app = Poco::Util::Application::instance();
		app.logger().fatal("Not enough memory for the packet_info in the packet_info_pool");
		return ;
	}
	pkt_info->timestamp = rte_rdtsc(); // timestamp
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
}

uint16_t cb_parse_ptype(uint8_t port __rte_unused, uint16_t queue __rte_unused, struct rte_mbuf *pkts[], uint16_t nb_pkts, uint16_t max_pkts __rte_unused, void *user_param __rte_unused)
{
	unsigned i;
	for (i = 0; i < nb_pkts; ++i)
		em_parse_ptype(pkts[i]);
	return nb_pkts;
}

int extFilter::initSenderPort(uint8_t port, struct ether_addr *addr, uint8_t nb_tx_queue)
{
	int retval;
	struct rte_eth_conf portConf;
	memset(&portConf,0,sizeof(rte_eth_conf));
	portConf.rxmode.split_hdr_size = DPDK_CONFIG_SPLIT_HEADER_SIZE;
	portConf.rxmode.header_split = DPDK_CONFIG_HEADER_SPLIT;
	portConf.rxmode.hw_ip_checksum = DPDK_CONFIG_HW_IP_CHECKSUM;
	portConf.rxmode.hw_vlan_filter = DPDK_CONFIG_HW_VLAN_FILTER;
	portConf.rxmode.jumbo_frame = DPDK_CONFIG_JUMBO_FRAME;
	portConf.rxmode.hw_strip_crc = DPDK_CONFIG_HW_STRIP_CRC;
	portConf.rxmode.mq_mode = DPDK_CONFIG_MQ_MODE;
	portConf.rx_adv_conf.rss_conf.rss_key = m_RSSKey;
	portConf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV6;
	portConf.txmode.mq_mode = ETH_MQ_TX_NONE;

	retval = rte_eth_dev_configure(port, 1, nb_tx_queue, &portConf);
	if (retval != 0)
		return retval;

	struct rte_mempool *mpool = rte_pktmbuf_pool_create("Sender RX", 1000, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_eth_dev_socket_id(port));

	logger().information("sender port=%d rx_queueid=%d nb_rxd=%d", (int) port, (int) 0, (int) _nb_rxd);
	retval = rte_eth_rx_queue_setup(port, 0, _nb_rxd, rte_eth_dev_socket_id(port), NULL, mpool);
	if (retval < 0)
	{
		logger().fatal("rte_eth_rx_queue_setup: err=%d (%s) port=%d", (int) retval, rte_strerror(-retval), (int)port);
		return retval;
	}

	for(auto z=0; z < nb_tx_queue; z++)
	{
		logger().information("sender port=%d tx_queueid=%d tb_rxd=%d", (int) port, (int) z, (int) _nb_txd);
		retval = rte_eth_tx_queue_setup(port, z, _nb_txd, rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
		{
			logger().fatal("rte_eth_tx_queue_setup: err=%d (%s), port=%d, nb_tx_queue=%d, nb_txd=%d, socketid=%d", retval, rte_strerror(-retval), (int)port, (int)z, (int)_nb_txd, (int) rte_eth_dev_socket_id(port));
			return retval;
		}
	}

	rte_eth_macaddr_get(port, addr);
	char buffer[100];
	sprintf(buffer,"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8, addr->addr_bytes[0], addr->addr_bytes[1], addr->addr_bytes[2], addr->addr_bytes[3],addr->addr_bytes[4], addr->addr_bytes[5]);
	std::string mac_addr(buffer);
	logger().information("Port %d MAC: %s", (int)port, mac_addr);

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	struct rte_eth_link link;

	for (int count = 0; count <= MAX_CHECK_TIME; count++)
	{
		rte_eth_link_get_nowait(port, &link);
		if(!link.link_status)
		{
			rte_delay_ms(CHECK_INTERVAL);
		} else {
			break;
		}
	}

	if (!link.link_status)
	{
		logger().warning("Link down on port %d", (int) port);
	}

	return 0;
}

int extFilter::initPort(uint8_t port, struct ether_addr *addr, bool no_promisc)
{
	int16_t queueid;
	unsigned lcore_id;
	struct lcore_conf* qconf;

	uint8_t nb_tx_queue, queue;
	uint8_t nb_rx_queue, socketid;

	struct rte_eth_conf portConf;
	memset(&portConf,0,sizeof(rte_eth_conf));
	portConf.rxmode.split_hdr_size = DPDK_CONFIG_SPLIT_HEADER_SIZE;
	portConf.rxmode.header_split = DPDK_CONFIG_HEADER_SPLIT;
	portConf.rxmode.hw_ip_checksum = DPDK_CONFIG_HW_IP_CHECKSUM;
	portConf.rxmode.hw_vlan_filter = DPDK_CONFIG_HW_VLAN_FILTER;
	portConf.rxmode.jumbo_frame = DPDK_CONFIG_JUMBO_FRAME;
	portConf.rxmode.hw_strip_crc = DPDK_CONFIG_HW_STRIP_CRC;
	portConf.rxmode.mq_mode = DPDK_CONFIG_MQ_MODE;
//<---->portConf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;

	portConf.rx_adv_conf.rss_conf.rss_key = m_RSSKey;
	portConf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV6;


//	portConf.rx_adv_conf.rss_conf.rss_key = NULL;
//	portConf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;

//	portConf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_TCP | ETH_RSS_UDP;

	portConf.txmode.mq_mode = ETH_MQ_TX_NONE;

	int retval;

	nb_rx_queue = _get_port_n_rx_queues(port);
	nb_tx_queue = nb_rx_queue;
	if (nb_rx_queue > get_port_max_rx_queues(port))
	{
		logger().fatal("Number of rx queues %d exceeds max number of rx queues %d for port %d", (int)nb_rx_queue, (int)get_port_max_rx_queues(port), (int)port);
		return -1;
	}
	if (nb_tx_queue > get_port_max_tx_queues(port))
	{
		logger().fatal("Number of tx queues %d exceeds max number of tx queues %d for port %d", (int)nb_tx_queue, (int)get_port_max_tx_queues(port), (int)port);
		return -1;
	}
	logger().information("Port %d creating queues: rx queue=%d, tx queue=%d", (int) port, (int) nb_rx_queue, (int) nb_tx_queue);

	retval = rte_eth_dev_configure(port, nb_rx_queue, nb_tx_queue, &portConf);
	if (retval != 0)
		return retval;

	nb_tx_queue = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
	{
		if (rte_lcore_is_enabled(lcore_id) == 0) {
			continue;
		}

		if (_numa_on)
			socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		qconf = &_lcore_conf[lcore_id];
		queueid = -1;

		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue)
		{
			if (port != qconf->rx_queue_list[queue].port_id)
			{
				// we skip that queue
				continue;
			}
			queueid = qconf->rx_queue_list[queue].queue_id;

			logger().information("port=%d rx_queueid=%d nb_rxd=%d core=%d", (int) port, (int) queueid, (int) _nb_rxd, (int) lcore_id);
			retval = rte_eth_rx_queue_setup(port, queueid, _nb_rxd, socketid, NULL, _pktmbuf_pool[socketid]);
			if (retval < 0)
			{
				logger().fatal("rte_eth_rx_queue_setup: err=%d port=%d", (int) retval, (int)port);
				return retval;
			}
			if (!rte_eth_add_rx_callback(port, queueid, cb_parse_ptype, NULL))
			{
				logger().error("Unable to add rx callback to port %d", (int) port);
				return -1;
			}

		}
		if (queueid == -1) {
			// no rx_queue set, don't need to setup tx_queue for
			// that core
			continue;
		}
//		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);

		logger().information("port=%d tx_queueid=%d nb_txd=%d core=%d", (int) port, (int) nb_tx_queue, (int) _nb_txd, (int) lcore_id);
		retval = rte_eth_tx_queue_setup(port, nb_tx_queue, _nb_txd, socketid, NULL);
		if (retval < 0)
		{
			logger().fatal("rte_eth_tx_queue_setup: err=%d, port=%d, nb_tx_queue=%d, nb_txd=%d, socketid=%d", retval, (int)port, (int)nb_tx_queue, (int)_nb_txd, (int) socketid);
			return retval;
		}
		qconf->tx_queue_id[port] = nb_tx_queue++;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	struct rte_eth_link link;

	for (int count = 0; count <= MAX_CHECK_TIME; count++)
	{
		rte_eth_link_get_nowait(port, &link);
		if(!link.link_status)
		{
			rte_delay_ms(CHECK_INTERVAL);
		} else {
			break;
		}
	}

	if (!link.link_status)
	{
		logger().warning("Link down on port %d", (int) port);
	}


	rte_eth_macaddr_get(port, addr);
	char buffer[100];
	sprintf(buffer,"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8, addr->addr_bytes[0], addr->addr_bytes[1], addr->addr_bytes[2], addr->addr_bytes[3],addr->addr_bytes[4], addr->addr_bytes[5]);
	std::string mac_addr(buffer);
	logger().information("Port %d MAC: %s", (int)port, mac_addr);

	if(!no_promisc)
		rte_eth_promiscuous_enable(port);


	return 0;
}

uint8_t extFilter::_get_ports_n_rx_queues(void)
{
	uint8_t nb_queue = 0;
	uint16_t i;

	for (i = 0; i < _nb_lcore_params; ++i) {
		if (_enabled_port_mask & 1 << _lcore_params[i].port_id)
			nb_queue++;
	}
	return nb_queue;
}

uint8_t extFilter::_get_port_n_rx_queues(uint8_t port)
{
	int nb_queue = 0;
	uint16_t i;

	for (i = 0; i < _nb_lcore_params; ++i) {
		if (_lcore_params[i].port_id == port)
			nb_queue++;
	}
	return nb_queue;
}

int extFilter::_init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < _nb_lcore_params; ++i)
	{
		lcore = _lcore_params[i].lcore_id;
		nb_rx_queue = _lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE)
		{
			logger().error("Too many queues (%d) for lcore %d", (int) nb_rx_queue+1, (int)lcore);
			return -1;
		} else {
			_lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id = _lcore_params[i].port_id;
			_lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id = _lcore_params[i].queue_id;
			_lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_type = _lcore_params[i].port_type;
			_lcore_conf[lcore].n_rx_queue++;
		}
	}
	return 0;
}

int extFilter::_check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i;
	int socketid;

	for (i = 0; i < _nb_lcore_params; ++i)
	{
		queue = _lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT)
		{
			logger().error("Invalid queue number: %d", (int)queue);
			return -1;
		}
		if (queue >= get_port_max_rx_queues(_lcore_params[i].port_id))
		{
			logger().error("Invalid queue number: %d (nic supported maximum %d)", (int)queue, (int)get_port_max_rx_queues(_lcore_params[i].port_id));
			return -1;
		}
		lcore = _lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore))
		{
			logger().error("Lcore %d is not enabled in lcore mask", (int) lcore);
			return -1;
		}
		if ((socketid = rte_lcore_to_socket_id(lcore) != 0) && (_numa_on == 0))
		{
			logger().warning("Lcore %d is on socket %d with numa off", (int) lcore, (int) socketid);
		}
	}
	return 0;
}

int extFilter::_check_port_config(const unsigned nb_ports)
{
	unsigned portid;
	uint16_t i;

	for (i = 0; i < _nb_lcore_params; ++i)
	{
		portid = _lcore_params[i].port_id;
		if ((_enabled_port_mask & (1 << portid)) == 0)
		{
			logger().error("Port %d is not enabled in port mask", (int) portid);
			return -1;
		}
		if (portid >= nb_ports)
		{
			logger().error("Port %d is not present on the board", (int) portid);
			return -1;
		}
	}
	return 0;
}

int extFilter::initMemory(uint8_t nb_ports)
{
	struct lcore_conf* qconf;
	int socketid;
	unsigned lcore_id;
//	uint8_t port;
	char s[64];
	size_t nb_mbuf;
	uint32_t nb_lcores;
	uint8_t nb_tx_queue;
	uint8_t nb_rx_queue;

	nb_lcores = rte_lcore_count();
	nb_rx_queue = _get_ports_n_rx_queues();
	nb_tx_queue = nb_rx_queue;

	nb_mbuf = RTE_MAX((nb_ports * nb_rx_queue * EXTF_RX_DESC_DEFAULT +
		 nb_ports * nb_lcores * EXTFILTER_CAPTURE_BURST_SIZE +
		 nb_ports * nb_tx_queue * EXTF_TX_DESC_DEFAULT +
		 nb_lcores * MBUF_CACHE_SIZE),
		(unsigned)16384);

	logger().information("Setting mbuf size to %d", (int) nb_mbuf);

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
	{
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (_numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= NB_SOCKETS)
		{
			logger().fatal("Socket %d of lcore %d is out of range %d", (int) socketid, (int) lcore_id, (int) NB_SOCKETS);
			return -1;
		}
		if (_pktmbuf_pool[socketid] == NULL)
		{
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			_pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(s, nb_mbuf, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (_pktmbuf_pool[socketid] == NULL)
			{
				logger().fatal("Cannot init mbuf pool on socket %d", (int) socketid);
				return -1;
			}
			else
			{
				logger().information("Allocated mbuf pool (%d entries) on socket %d", (int) nb_mbuf, (int) socketid);
			}
			// setup hash
//			setup_lpm(socketid);
		}
		if(packet_info_pool[socketid] == NULL)
		{
			snprintf(s, sizeof(s), "packet_info_pool_%d", socketid);
			packet_info_pool[socketid] = rte_mempool_create(s, nb_mbuf, sizeof(struct packet_info), 0, 0, NULL, NULL, NULL, NULL, socketid, 0);
			if(packet_info_pool[socketid] == NULL)
			{
				logger().fatal("Cannot allocate memory pool on socket %d", (int) socketid);
				return -1;
			}
			logger().information("Allocated memory pool (%d entries) for packet info on sockets %d", (int) nb_mbuf, (int) socketid);
		}

		qconf = &_lcore_conf[lcore_id];
/*
		qconf->ipv4_lookup_struct = ipv4_pktj_lookup_struct[socketid];
		qconf->neighbor4_struct = neighbor4_struct[socketid];
		qconf->ipv6_lookup_struct = ipv6_pktj_lookup_struct[socketid];
		qconf->neighbor6_struct = neighbor6_struct[socketid];
*/
		qconf->cur_acx_ipv4 = ACL::ipv4_acx[socketid];
		qconf->cur_acx_ipv6 = ACL::ipv6_acx[socketid];
	}
	return 0;
}

void extFilter::initialize(Application& self)
{
	loadConfiguration();
	ServerApplication::initialize(self);

	_dpi_max_active_flows_ipv4 = config().getInt("dpi.max_active_flows_ipv4", 1000000);
	_dpi_max_active_flows_ipv6 = config().getInt("dpi.max_active_flows_ipv6", 20000);
	_dpi_fragmentation_ipv6_state = config().getBool("dpi.fragmentation_ipv6_state", true);
	_dpi_fragmentation_ipv4_state = config().getBool("dpi.fragmentation_ipv4_state", true);
	if(_dpi_fragmentation_ipv4_state)
		_dpi_fragmentation_ipv4_table_size = config().getInt("dpi.fragmentation_ipv4_table_size", 512);
	if(_dpi_fragmentation_ipv6_state)
		_dpi_fragmentation_ipv6_table_size = config().getInt("dpi.fragmentation_ipv6_table_size", 512);
	_dpi_tcp_reordering = config().getBool("dpi.tcp_reordering", true);
	_dpi_maximum_url_size = config().getInt("dpi.max_url_size", 600);

	_num_of_senders = config().getInt("num_of_senders", 1);
	_lower_host = config().getBool("lower_host", false);
	_match_url_exactly = config().getBool("match_url_exactly", false);
	_block_ssl_no_sni = config().getBool("block_ssl_no_sni", false);
	_http_redirect = config().getBool("http_redirect", true);
	_url_normalization = config().getBool("url_normalization", true);
	_remove_dot = config().getBool("remove_dot", false);
	_statistic_interval = config().getInt("statistic_interval", 0);
	_urlsFile = config().getString("urllist","");
	_domainsFile = config().getString("domainlist","");
	_sslIpsFile = config().getString("sslips","");
	if(!_block_ssl_no_sni)
	{
		_sslIpsFile.assign("");
	}
	_sslFile = config().getString("ssllist","");
	_hostsFile = config().getString("hostlist","");
	_statisticsFile = config().getString("statisticsfile","");

	std::string http_code=config().getString("http_code","");
	if(!http_code.empty())
	{
		http_code.erase(std::remove(http_code.begin(), http_code.end(), '"'), http_code.end());
		_sender_params.code=http_code;
		logger().debug("HTTP code set to %s", http_code);
	}
	_sender_params.redirect_url=config().getString("redirect_url","");
	_sender_params.send_rst_to_server=config().getBool("rst_to_server",false);
	_sender_params.mtu=config().getInt("out_mtu",1500);

	std::string add_p_type=config().getString("url_additional_info","none");
	std::transform(add_p_type.begin(), add_p_type.end(), add_p_type.begin(), ::tolower);

	std::map<std::string, ADD_P_TYPES> add_type_s;
	add_type_s["none"]=A_TYPE_NONE;
	add_type_s["line"]=A_TYPE_ID;
	add_type_s["url"]=A_TYPE_URL;

	std::map<std::string, ADD_P_TYPES>::iterator it=add_type_s.find(add_p_type);
	if(it == add_type_s.end())
	{
		throw Poco::Exception("Unknown url_additional_info type '" + add_p_type + "'",404);
	}
	_add_p_type=it->second;
	logger().debug("URL additional info set to %s", add_p_type);

	_notify_enabled = config().getBool("notify_enabled", false);
	_notify_acl_file = config().getString("notify_acl_file","");

	_protocolsFile=config().getString("protocols","");


	_cmdline_port = config().getInt("cli_port", 0);
	std::string cli_address = config().getString("cli_address", "");
	if(!cli_address.empty() && _cmdline_port)
		_cmdline_ip = Poco::Net::IPAddress::parse(cli_address);

	int _mem_channels = config().getInt("memory_channels", 2);
	
	int coreMaskToUse=config().getInt("core_mask", 0);


	// initialize DPDK
	std::stringstream dpdkParamsStream;
	dpdkParamsStream << commandName().c_str() << " ";
	dpdkParamsStream << "-n ";
	dpdkParamsStream << _mem_channels << " ";
	dpdkParamsStream << "-c ";
	dpdkParamsStream << "0x" << std::hex << std::setw(2) << std::setfill('0') << coreMaskToUse << " ";
	dpdkParamsStream << "--master-lcore ";
	dpdkParamsStream << "0";


	int initDpdkArgc=7;
	std::string dpdkParamsArray[initDpdkArgc];
	char** initDpdkArgv = new char*[initDpdkArgc];
	int i = 0;
	while (dpdkParamsStream.good() && i < initDpdkArgc)
	{
		dpdkParamsStream >> dpdkParamsArray[i];
		initDpdkArgv[i] = new char[dpdkParamsArray[i].size()+1];
		strcpy(initDpdkArgv[i], dpdkParamsArray[i].c_str());
		i++;
	}

	char* lastParam = initDpdkArgv[i-1];

	for (i = 0; i < initDpdkArgc; i++)
	{
		std::string arg(initDpdkArgv[i]);
		logger().debug("DPDK command line: %s", arg);
	}

	optind = 1;
	// init the EAL
	int ret = rte_eal_init(initDpdkArgc, (char**)initDpdkArgv);
	if (ret < 0)
		throw Poco::Exception("Can't initialize EAL - invalid EAL arguments");

	for (i = 0; i < initDpdkArgc-1; i++)
	{
		delete [] initDpdkArgv[i];
	}
	delete [] lastParam;

	delete [] initDpdkArgv;

	uint32_t n_ports = 0;
	std::vector<std::string> keys;
	config().keys(keys);
	for(auto i=keys.begin(); i != keys.end(); i++)
	{
		std::string key(*i);
		std::transform(key.begin(), key.end(), key.begin(), ::tolower);
		std::size_t pos = key.find("port ");
		if(pos != std::string::npos)
			n_ports++;
		pos = key.find("notify ");
		if(pos != std::string::npos)
		{
			std::string group_num = key.substr(pos+7, key.length());
			int group_id = Poco::NumberParser::parse(group_num);
			if(group_id > 15)
			{
				logger().fatal("Too big number of notify group, maximum 15");
				throw Poco::Exception("Too big number of notify group");
			}
			struct NotificationParams p;
			p.period = config().getInt(key+".period", 3600);
			p.group_id = group_id;
			p.repeat = config().getInt(key+".repeat", 0);
			p.prm.code = config().getString(key+".http_code","");
			p.prm.redirect_url = config().getString(key+".redirect_url","");
			p.prm.send_rst_to_server = config().getBool(key+".rst_to_server", false);
			p.prm.mtu = config().getInt(key+".out_mtu", 1500);
			_notify_groups.insert(std::make_pair(group_id, p));
		}
	}
	if(n_ports >= RTE_MAX_ETHPORTS)
	{
		logger().fatal("Number of ports %d bigger then maximum supported %d", (int) n_ports, (int) RTE_MAX_ETHPORTS);
		throw Poco::Exception("Too big number of ports");
	}

	_nb_lcore_params=0;
	int cnt_sender = 0;
	for(uint32_t i=0; i < n_ports; i++)
	{
		std::string key("port "+std::to_string(i));
		_enabled_port_mask |= (1 << i);
		std::string type = config().getString(key+".type", "");
		uint8_t port_type = P_TYPE_SUBSCRIBER;
		if(!type.empty())
		{
			if(type == "network")
			{
				port_type = P_TYPE_NETWORK;
			} else if (type == "subscriber")
			{
			} else if (type == "sender")
			{
				if(cnt_sender > 0)
				{
					logger().fatal("Too many sender ports");
					throw Poco::Exception("Congfiguration error");
				}
				++cnt_sender;
				port_type = P_TYPE_SENDER;
				_dpdk_send_port = i;
			} else {
				logger().fatal("Unknown port type %s", type);
				throw Poco::Exception("Congfiguration error");
			}
		}
		port_types[i] = port_type;
		if(port_type == P_TYPE_SENDER)
		{
			std::string mac = config().getString(key+".mac","");
			if(mac.empty())
			{
				logger().fatal("Destination mac address not found for port %d", (int)i);
				throw Poco::Exception("Congfiguration error");
				
			}
			int last = 0;
			int rc = sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n", sender_mac + 0, sender_mac + 1, sender_mac + 2, sender_mac + 3, sender_mac + 4, sender_mac + 5, &last);
			if(rc != 6 || mac.size() != last)
			{
				logger().fatal("Invalid mac address '%s' for port %d", mac, (int)i);
				throw Poco::Exception("Congfiguration error");
			}
			continue;
		}
		std::string p=config().getString(key+".queues", "");
		if(p.empty())
		{
			logger().fatal("Port IDs are not sequential (port %d missing)", (int) i);
			throw Poco::Exception("Congfiguration error");
		}
		Poco::StringTokenizer restTokenizer(p, ";");
		std::vector<int> lcores;
		int nb_lcores_per_port = 0;
		for(auto itr=restTokenizer.begin(); itr!=restTokenizer.end(); ++itr)
		{
			Poco::StringTokenizer params(*itr, ",");
			uint8_t queue_id=Poco::NumberParser::parse(params[0]);
			uint8_t lcore_id=Poco::NumberParser::parse(params[1]);
			if (_nb_lcore_params >= MAX_LCORE_PARAMS)
			{
				logger().fatal("Exceeded max number of lcore params: %d", (int) _nb_lcore_params);
				throw Poco::Exception("Configuration error");
			}
			lcores.push_back(lcore_id);
			_lcore_params_array[_nb_lcore_params].port_id = i;
			_lcore_params_array[_nb_lcore_params].port_type = port_type;
			_lcore_params_array[_nb_lcore_params].queue_id = queue_id;
			_lcore_params_array[_nb_lcore_params].lcore_id = lcore_id;
			_nb_lcore_params++;
			nb_lcores_per_port++;
		}
	}
	_lcore_params = _lcore_params_array;
	if(!_nb_lcore_params)
	{
		logger().fatal("No cores defined in the configuration file");
		throw Poco::Exception("Configuration error");
	}

//	_flowhash_size_per_worker=rte_align32pow2((_flowhash_size/_nb_lcore_params) * n_ports);


	_nb_ports = rte_eth_dev_count();
	if(_nb_ports == 0)
	{
		logger().fatal("No ethernet ports detected");
		throw Poco::Exception("Configuration error");
	}

	if (_nb_ports > RTE_MAX_ETHPORTS)
		_nb_ports = RTE_MAX_ETHPORTS;

	if (_check_lcore_params() < 0)
		throw Poco::Exception("Configuration error");

	if(_init_lcore_rx_queues() < 0)
		throw Poco::Exception("Configuration error");

	if (_check_port_config(_nb_ports) < 0)
		throw Poco::Exception("Configuration error");

	// init acl

	_acl = new ACL();
	
	if(loadACL())
		throw Poco::Exception("Can't init ACL");

	// init value...
	_tsc_hz = rte_get_tsc_hz();

}

void extFilter::uninitialize()
{
	logger().debug("Shutting down");
	ServerApplication::uninitialize();
}

void extFilter::defineOptions(Poco::Util::OptionSet& options)
{
	ServerApplication::defineOptions(options);
	options.addOption(
		Poco::Util::Option("help","h","Display help on command line arguments.")
			.required(false)
			.repeatable(false)
			.callback(Poco::Util::OptionCallback<extFilter>(this,&extFilter::handleHelp)));
	options.addOption(
		Poco::Util::Option("list","l","Print the list of DPDK ports and exit.")
			.required(false)
			.repeatable(false)
			.callback(Poco::Util::OptionCallback<extFilter>(this,&extFilter::printDPDKPorts)));
	options.addOption(
		Poco::Util::Option("config-file","f","Specify config file to read.")
			.required(true)
			.repeatable(false)
			.argument("FILE"));
	options.addOption(
			Poco::Util::Option("version","v","Display version and exit.")
			.required(false)
			.repeatable(false)
			.callback(Poco::Util::OptionCallback<extFilter>(this, &extFilter::handleVersion)));
}

void extFilter::handleOption(const std::string& name,const std::string& value)
{
	ServerApplication::handleOption(name, value);
	if(name == "config-file")
	{
		loadConfiguration(value);
	}
}

void extFilter::handleHelp(const std::string& name,const std::string& value)
{
	_helpRequested=true;
	displayHelp();
	stopOptionsProcessing();
	exit(0);
}

void extFilter::handleVersion(const std::string& name,const std::string& value)
{
	_helpRequested = true;
	std::cout << "extFilter version " << VERSION << std::endl;
	stopOptionsProcessing();
	exit(0);
}

void extFilter::displayHelp()
{
	Poco::Util::HelpFormatter helpFormatter(options());
	helpFormatter.setCommand(commandName());
	helpFormatter.setUsage("<-c config file> [options]");
	helpFormatter.setHeader("extFilter");
	helpFormatter.format(std::cout);
}

void extFilter::printDPDKPorts(const std::string& name,const std::string& value)
{
	_listDPDKPorts=true;
	stopOptionsProcessing();
	// initialize DPDK
/*	if (!pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, DEFAULT_MBUF_POOL_SIZE))
	{
		logger().fatal("Couldn't initialize DPDK!");
		return;
	}

	std::cout << "DPDK port list:" << std::endl;

	// go over all available DPDK devices and print info for each one
	std::vector<pcpp::DpdkDevice*> deviceList = pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList();
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
	{
		pcpp::DpdkDevice* dev = *iter;
		printf("\tPort #%d: MAC address='%s'; PCI address='%s'; PMD='%s'\n",
				dev->getDeviceId(),
				dev->getMacAddress().toString().c_str(),
				dev->getPciAddress().toString().c_str(),
				dev->getPMDName().c_str());
	}
*/

}

namespace
{
	static void handleSignal(int sig)
	{
		Poco::Util::Application& app = Poco::Util::Application::instance();
		app.logger().information("Got HUP signal - reload data");
		ReloadTask::_event.set();
	}
}


int extFilter::main(const ArgVec& args)
{
	if(!_helpRequested && !_listDPDKPorts)
	{
		unsigned lcore_id;
		struct lcore_conf* qconf;


		struct sigaction handler;
		handler.sa_handler = handleSignal;
		handler.sa_flags   = 0;
		sigemptyset(&handler.sa_mask);
		sigaction(SIGHUP, &handler, NULL);

		// core dumps maybe disallowed by parent of this process; change that
		struct rlimit core_limits;
		core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
		setrlimit(RLIMIT_CORE, &core_limits);

		if(initMemory(_nb_ports) < 0)
		{
			logger().fatal("Memory initialization error");
			return Poco::Util::Application::EXIT_CONFIG;
		}

		struct rte_mempool *_mp = nullptr;

		std::vector<uint8_t> ports;
		for (uint8_t portid = 0; portid < _nb_ports; portid++)
		{
			if ((_enabled_port_mask & (1 << portid)) == 0)
				continue;
			if(port_types[portid] == P_TYPE_SENDER)
			{
				if(initSenderPort(portid, &ports_eth_addr[portid], _nb_lcore_params) != 0)
				{
					logger().fatal("Cannot initialize port %d", (int) portid);
					return Poco::Util::Application::EXIT_CONFIG;
				}
				_mp = rte_pktmbuf_pool_create("SenderBuffer", 8192, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
				if(_mp == nullptr)
				{
					logger().fatal("Unable to allocate mempool for sender");
					return Poco::Util::Application::EXIT_CONFIG;
				}
			} else {
				if(initPort(portid, &ports_eth_addr[portid]) != 0)
				{
					logger().fatal("Cannot initialize port %d", (int) portid);
					return Poco::Util::Application::EXIT_CONFIG;
				}
			}
			ports.push_back(portid);
		}

		WorkerConfig workerConfigArr[RTE_MAX_LCORE];

		Poco::TaskManager tm;
		if(_mp == nullptr)
		{
			for(int i=1; i <= _num_of_senders; i++)
			{
				tm.start(new SenderTask(new CSender(_sender_params), i));
			}
		}

		NotifyManager *nm = new NotifyManager(20000, _notify_groups);
		tm.start(nm);


		int max_ipv4_flows_per_core = ceil((float)_dpi_max_active_flows_ipv4/(float)(_nb_lcore_params));
		int max_ipv6_flows_per_core = ceil((float)_dpi_max_active_flows_ipv6/(float)(_nb_lcore_params));


		uint16_t tx_queue_id = 0;
		/* launch per-lcore init on every lcore */
		RTE_LCORE_FOREACH(lcore_id)
		{
			qconf = &_lcore_conf[lcore_id];
			if (qconf->n_rx_queue != 0)
			{
				if(!_domainsFile.empty() && !_urlsFile.empty())
				{
					workerConfigArr[lcore_id].atm_new = new AhoCorasickPlus();
					loadDomainsURLs(_domainsFile, _urlsFile, workerConfigArr[lcore_id].atm_new);
					workerConfigArr[lcore_id].atm_new->finalize();
				}
				workerConfigArr[lcore_id].block_ssl_no_sni = _block_ssl_no_sni;
				if(!_sslFile.empty())
				{
					workerConfigArr[lcore_id].atmSSLDomains_new = new AhoCorasickPlus();
					loadDomains(_sslFile, workerConfigArr[lcore_id].atmSSLDomains_new);
					workerConfigArr[lcore_id].atmSSLDomains_new->finalize();
				}
				workerConfigArr[lcore_id].match_url_exactly = _match_url_exactly;
				workerConfigArr[lcore_id].lower_host = _lower_host;
				workerConfigArr[lcore_id].http_redirect = _http_redirect;
				workerConfigArr[lcore_id].url_normalization = _url_normalization;
				workerConfigArr[lcore_id].remove_dot = _remove_dot;
				workerConfigArr[lcore_id].add_p_type = _add_p_type;
				workerConfigArr[lcore_id].notify_enabled = _notify_enabled;
				workerConfigArr[lcore_id].nm = nm;
				workerConfigArr[lcore_id].sender_port = _dpdk_send_port;
				workerConfigArr[lcore_id].tx_queue_id = tx_queue_id;
				workerConfigArr[lcore_id].maximum_url_size = _dpi_maximum_url_size;

				logger().information("Initializing dpi flow hash with ipv4 max flows %d, ipv6  max flows %d.", max_ipv4_flows_per_core, max_ipv6_flows_per_core);
				flowHash *mFlowHash = new flowHash(rte_lcore_to_socket_id(lcore_id), lcore_id, max_ipv4_flows_per_core, max_ipv6_flows_per_core);

//				dpi_library_state_t* dpi_state = dpi_init_stateful(ipv4_buckets, ipv6_buckets, _dpi_max_active_flows_ipv4, _dpi_max_active_flows_ipv6);
				dpi_library_state_t* dpi_state = dpi_init_stateless();
				dpi_set_max_trials(dpi_state, 1);
				dpi_inspect_nothing(dpi_state);

				dpi_protocol_t protocol;
				protocol.l4prot = IPPROTO_TCP;
				protocol.l7prot = DPI_PROTOCOL_TCP_HTTP;
				dpi_set_protocol(dpi_state, protocol);

				protocol.l7prot = DPI_PROTOCOL_TCP_SSL;
				dpi_set_protocol(dpi_state, protocol);


				dpi_set_flow_cleaner_callback(dpi_state, &flow_delete_cb);

				if(!_dpi_tcp_reordering)
					dpi_tcp_reordering_disable(dpi_state);
				else
					dpi_tcp_reordering_enable(dpi_state);

				if(_dpi_fragmentation_ipv4_state)
					dpi_ipv4_fragmentation_enable(dpi_state, _dpi_fragmentation_ipv4_table_size);
				else
					dpi_ipv4_fragmentation_disable(dpi_state);

				if(_dpi_fragmentation_ipv6_state)
					dpi_ipv6_fragmentation_enable(dpi_state, _dpi_fragmentation_ipv6_table_size);
				else
					dpi_ipv6_fragmentation_disable(dpi_state);




				std::string workerName("WorkerThread-" + std::to_string(lcore_id));
				logger().debug("Preparing thread '%s'", workerName);
				ESender::nparams prms;
				if(_mp != nullptr)
				{
					prms.params = _sender_params;
					prms.mac = (uint8_t *)&ports_eth_addr[1];
					prms.to_mac = &sender_mac[0];
				}

				struct rte_mempool *url_mempool = nullptr;
				unsigned url_entries = (max_ipv4_flows_per_core+max_ipv6_flows_per_core)*PERCENT_URL_ENTRIES;
				std::string pool_name("URLPool-" + std::to_string(lcore_id));
				logger().information("Create pool '%s' for urls with number of entries: %d, size: %d bytes", pool_name, (int) url_entries, (int)(url_entries * (_dpi_maximum_url_size+1)));
				url_mempool = rte_mempool_create(pool_name.c_str(), url_entries, _dpi_maximum_url_size+1, 0, 0, NULL, NULL, NULL, NULL, rte_lcore_to_socket_id(lcore_id), 0);
				if(url_mempool == nullptr)
					logger().warning("Unable to create mempool for url. Will be use malloc. This may affect performance.");
				struct rte_mempool *dpi_mempool = nullptr;
				pool_name.assign("DPIPool-" + std::to_string(lcore_id));
				logger().information("Create pool '%s' for http dissector with number of entries: %d, size: %d bytes", pool_name, (int) url_entries, (int)(url_entries * sizeof(dpi_flow_info)));
				dpi_mempool = rte_mempool_create(pool_name.c_str(), url_entries, sizeof(dpi_flow_info), 0, 0, NULL, NULL, NULL, NULL, rte_lcore_to_socket_id(lcore_id), 0);
				if(dpi_mempool == nullptr)
					logger().warning("Unable to create mempool for http dissector. Will be use malloc. This may affect performance.");

				WorkerThread* newWorker = new WorkerThread(workerName, workerConfigArr[lcore_id], dpi_state, rte_lcore_to_socket_id(lcore_id), mFlowHash, prms, _mp, url_mempool, dpi_mempool);

				int err = rte_eal_remote_launch(dpdkWorkerThreadStart, newWorker, lcore_id);
				if (err != 0)
				{
					logger().fatal("Unable to launch thread on core %d, error: %d", lcore_id, err);
					return Poco::Util::Application::EXIT_CONFIG;
				}
				_workerThreadVec.push_back(newWorker);
				pthread_setname_np(lcore_config[lcore_id].thread_id, workerName.c_str());
				tx_queue_id++;
			}
		}


		tm.start(new StatisticTask(_statistic_interval, _workerThreadVec, _statisticsFile, ports));
		tm.start(new ReloadTask(this, _workerThreadVec));
		if(_cmdline_port)
		{
			tm.start(new CmdLineTask(_cmdline_port, _cmdline_ip));
		}
		for(const auto &port_id : ports)
		{
			rte_eth_stats_reset(port_id);
		}
		waitForTerminationRequest();

		for (auto iter = _workerThreadVec.begin(); iter != _workerThreadVec.end(); iter++)
		{
			(*iter)->stop();
			rte_eal_wait_lcore((*iter)->getCoreId());
		}

		tm.cancelAll();
		SenderTask::queue.wakeUpAll();
		tm.joinAll();

		for (uint8_t portid = 0; portid < _nb_ports; portid++)
		{
			if ((_enabled_port_mask & (1 << portid)) == 0)
			{
				continue;
			}
			rte_eth_dev_stop(portid);
		}

	}
	return Poco::Util::Application::EXIT_OK;
}

void extFilter::loadDomainsURLs(std::string &domains, std::string &urls, AhoCorasickPlus *dm_atm)
{
	logger().debug("Loading domains from file %s",domains);
	Poco::FileInputStream df(domains);
	int entry_id=0;
	if(df.good())
	{
		int lineno=0;
		while(!df.eof())
		{
			lineno++;
			std::string str;
			getline(df,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = lineno;
				std::size_t pos = str.find("*.");
				bool exact_match=true;
				std::string insert=str;
				patId <<= 2;
				if(pos != std::string::npos)
				{
					exact_match=false;
					insert=str.substr(pos+2,str.length()-2);
				}
				patId |= exact_match;
				patId |= E_TYPE_DOMAIN << 1;
				status = dm_atm->addPattern(insert, patId);
				if (status != AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern '%s' already present in the database from file %s",insert,domains);
						continue;
					} else {
						logger().error("Failed to add '%s' from line %d from file %s",insert,lineno,domains);
					}
				}
			}
			entry_id++;
		}
	} else
		throw Poco::OpenFileException(domains);
	df.close();
	logger().debug("Finish loading domains");
	logger().debug("Loading URLS from file %s",urls);
	Poco::FileInputStream uf(urls);
	if(uf.good())
	{
		int lineno=0;
		while(!uf.eof())
		{
			lineno++;
			std::string str;
			getline(uf,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = lineno;
				if(_url_normalization)
				{
					std::string url = "http://" + str;
					try
					{
						Poco::URI url_p(url);
						url_p.normalize();
						url.assign(url_p.toString());
					} catch (Poco::SyntaxException &ex)
					{
						logger().error("An SyntaxException occured: '%s' on URI: '%s'", ex.displayText(), url);
					}
					str.assign(url.c_str()+7, url.length()-7);
				}
/*				std::string url = str;
				std::size_t http_pos = url.find("http://");
				if(http_pos == std::string::npos || http_pos > 0)
				{
					url.insert(0,"http://");
				}*/
				patId <<= 2;
				patId |= 0;
				patId |= E_TYPE_URL << 1;

				status = dm_atm->addPattern(str, patId);
				if (status != AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern '%s' already present in the URL database from file %s",str,urls);
						continue;
					} else {
						logger().error("Failed to add '%s' from line %d from file %s",str,lineno,urls);
					}
				}
			}
			entry_id++;
		}
	} else
		throw Poco::OpenFileException(urls);
	uf.close();
	logger().debug("Finish loading URLS");
}

void extFilter::loadDomains(std::string &fn, AhoCorasickPlus *dm_atm)
{
	logger().debug("Loading domains from file %s",fn);
	Poco::FileInputStream df(fn);
	if(df.good())
	{
		int lineno=1;
		while(!df.eof())
		{
			std::string str;
			getline(df,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = lineno;
				std::size_t pos = str.find("*.");
				bool exact_match=true;
				std::string insert=str;
				if(pos != std::string::npos)
				{
					exact_match=false;
					insert=str.substr(pos+2,str.length()-2);
				}
				patId <<= 2;
				patId |= exact_match;
				patId |= E_TYPE_DOMAIN << 1;
				status = dm_atm->addPattern(insert, patId);
				if (status!=AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern '%s' already present in the database from file %s",insert,fn);
					} else {
						logger().error("Failed to add '%s' from line %d from file %s",insert,lineno,fn);
					}
				}
			}
			lineno++;
		}
	} else
		throw Poco::OpenFileException(fn);
	df.close();
	logger().debug("Finish loading domains");
}

bool extFilter::loadACL(std::set<struct rte_acl_ctx *> *to_del)
{
	std::map<std::string,int> fns;
	if(!_hostsFile.empty())
		fns[_hostsFile] = ACL::ACL_DROP;
	if(!_sslIpsFile.empty())
		fns[_sslIpsFile] = ACL::ACL_SSL;
	if(_notify_enabled && !_notify_acl_file.empty())
		fns[_notify_acl_file] = ACL::ACL_NOTIFY;
	if(_acl->initACL(fns, _numa_on, to_del))
	{
		logger().error("Unable to init ACL");
		return true;
	}
	return false;
}

POCO_SERVER_MAIN(extFilter)
