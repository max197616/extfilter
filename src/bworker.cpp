
#include "bworker.h"
#include "main.h"
#include <rte_cycles.h>
#include "acl.h"

BWorkerThread::BWorkerThread(uint8_t worker_id, const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, struct ESender::nparams &sp, struct rte_mempool *mp) :
	WorkerThread(worker_id, name, workerConfig, state, sp, mp)
{
}


bool BWorkerThread::run(uint32_t coreId)
{
	setCoreId(coreId);
	uint8_t portid = 0, queueid, port_type;
	uint32_t lcore_id;
	struct lcore_conf* qconf;
	uint16_t nb_rx;
	struct rte_mbuf *bufs[EXTFILTER_CAPTURE_BURST_SIZE];

	lcore_id = rte_lcore_id();
	qconf = extFilter::getLcoreConf(lcore_id);

	if (qconf->n_rx_queue == 0)
	{
		_logger.information("Lcore %d has nothing to do", (int) lcore_id);
		return true;
	}

	m_Stop = false;
	struct rte_mbuf *buf;

	const uint64_t timer_interval = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * (1000*1000);
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	uint64_t last_sec = 0;

	uint64_t cur_tsc, diff_timer_tsc, diff_tsc;
	uint64_t prev_timer_tsc = 0, prev_tsc = 0;

	uint8_t sender_port = qconf->sender_port;
	uint16_t tx_queue_id = qconf->tx_queue_id[sender_port];
	_logger.information("Output port for the worker %d is %d (tx_queue_id %d) n_tx_port %d", (int)_worker_id, (int)sender_port, (int)tx_queue_id, (int) qconf->n_tx_port);

	_logger.debug("Starting bridge working thread on core %u", coreId);

	for (int i = 0; i < qconf->n_rx_queue; i++)
	{
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		_logger.information("-- lcoreid=%d portid=%d rxqueueid=%d", (int)lcore_id, (int)portid, (int)queueid);
	}

	// main loop, runs until be told to stop
	while (!m_Stop)
	{
		if(m_Stop)
			break;

		cur_tsc = rte_rdtsc();
//#define ATOMIC_ACL
#ifdef ATOMIC_ACL
#define SWAP_ACX(cur_acx, new_acx)                                            \
	rte_atomic64_cmpswap((uintptr_t*)&new_acx, (uintptr_t*)&cur_acx, \
				  (uintptr_t)new_acx))
#else
#define SWAP_ACX(cur_acx, new_acx)          \
	if (unlikely(cur_acx != new_acx)) { \
		cur_acx = new_acx;          \
	}
#endif
		SWAP_ACX(qconf->cur_acx_ipv4, qconf->new_acx_ipv4);
		SWAP_ACX(qconf->cur_acx_ipv6, qconf->new_acx_ipv6);
#undef SWAP_ACX

		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
		{
			for (uint16_t i = 0; i < qconf->n_tx_port; ++i)
			{
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
				qconf->tx_mbufs[portid].len = 0;
			}
			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (int i = 0; i < qconf->n_rx_queue; i++)
		{
			portid = qconf->rx_queue_list[i].port_id;
			port_type = qconf->rx_queue_list[i].port_type;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, bufs, EXTFILTER_CAPTURE_BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;

			m_ThreadStats.total_packets += nb_rx;

			switch (port_type)
			{
				case P_TYPE_NETWORK:
						for (uint16_t z = 0; z < nb_rx; z++)
						{
							send_single_packet(qconf, bufs[z], sender_port);
						}
						break;

				case P_TYPE_SUBSCRIBER:
						struct ACL::acl_search_t acl_search;
						prepare_acl_parameter(bufs, &acl_search, nb_rx, &_pkt_infos[0]);
						if(likely(qconf->cur_acx_ipv4 && acl_search.num_ipv4))
						{
							rte_acl_classify(qconf->cur_acx_ipv4, acl_search.data_ipv4, acl_search.res_ipv4, acl_search.num_ipv4, DEFAULT_MAX_CATEGORIES);
							for(int acli=0; acli < acl_search.num_ipv4; acli++)
							{
								if(unlikely(acl_search.res_ipv4[acli] != 0))
								{
									((struct packet_info *)acl_search.m_ipv4[acli]->userdata)->acl_res=acl_search.res_ipv4[acli];
								}
							}
						}
						if(qconf->cur_acx_ipv6 && acl_search.num_ipv6)
						{
							rte_acl_classify(qconf->cur_acx_ipv6, acl_search.data_ipv6, acl_search.res_ipv6, acl_search.num_ipv6, DEFAULT_MAX_CATEGORIES);
							for(int acli=0; acli < acl_search.num_ipv6; acli++)
							{
								if(unlikely(acl_search.res_ipv6[acli] != 0))
								{
									((struct packet_info *)acl_search.m_ipv6[acli]->userdata)->acl_res=acl_search.res_ipv6[acli];
								}
							}
						}
						uint64_t cycles = 0;
						uint64_t blocked_cycles = 0;
						uint64_t unblocked_cycles = 0;
						for(uint16_t i = 0; i < nb_rx; i++)
						{
							buf = bufs[i];
							rte_prefetch0(rte_pktmbuf_mtod(buf, void *));
							if(likely(buf->userdata != nullptr))
							{
								bool need_block = analyzePacket(buf, last_sec);
								uint64_t now = rte_rdtsc();
								if(need_block)
								{
									blocked_cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
									m_ThreadStats.latency_counters.blocked_pkts++;
									rte_pktmbuf_free(buf);
								} else {
									unblocked_cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
									m_ThreadStats.latency_counters.unblocked_pkts++;
									send_single_packet(qconf, buf, sender_port);
								}
								cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
							}
						}
						m_ThreadStats.latency_counters.total_cycles += cycles;
						m_ThreadStats.latency_counters.blocked_cycles += blocked_cycles;
						m_ThreadStats.latency_counters.unblocked_cycles += unblocked_cycles;
						m_ThreadStats.latency_counters.total_pkts += nb_rx;
						if(unlikely(_n_send_pkts != 0))
						{
							for(int z = 0; z < _n_send_pkts; z++)
							{
								send_single_packet(qconf, _sender_buf[z], _sender_buf_flags[z] ? sender_port : portid);
							}
							_n_send_pkts = 0;
						}
					break;
			}
		}

		diff_timer_tsc = cur_tsc - prev_timer_tsc;
		if (unlikely(diff_timer_tsc >= timer_interval))
		{
			last_sec++;
			prev_timer_tsc = cur_tsc;
		}
	}
	_logger.debug("Worker thread on core %u terminated", coreId);
	return true;
}
