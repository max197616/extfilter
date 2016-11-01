
#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ring.h>


#include "worker.h"
#include "main.h"

ReaderThread::ReaderThread(const std::string& name, WorkerConfig &workerConfig, struct rte_ring *iring) :
		m_WorkerConfig(workerConfig), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1),
		_logger(Poco::Logger::get(name)),
		ring(iring),
		m_CanRun(false)
{
}

ReaderThread::~ReaderThread()
{
}

bool ReaderThread::run(uint32_t coreId)
{
	m_CoreId = coreId;
	m_Stop = false;
	uint16_t nb_rx;
	uint16_t nb_rx_enqueued;
	struct rte_mbuf *bufs[EXTFILTER_CAPTURE_BURST_SIZE];

	if (m_WorkerConfig.InDataCfg.size() == 0)
	{
		return true;
	}
	_logger.debug("Starting reading thread on core %u", coreId);

	while (!m_Stop)
	{
		if(!m_CanRun)
		{
			sched_yield();
			continue;
		}
		// go over all DPDK devices configured for this worker/core
		for (InputDataConfig::iterator iter = m_WorkerConfig.InDataCfg.begin(); iter != m_WorkerConfig.InDataCfg.end(); iter++)
		{
			// for each DPDK device go over all RX queues configured for this worker/core
			for (std::vector<int>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++)
			{
				pcpp::DpdkDevice* dev = iter->first;
				nb_rx = rte_eth_rx_burst(dev->getDeviceId(), *iter2, bufs, EXTFILTER_CAPTURE_BURST_SIZE);
				if (likely(nb_rx > 0))
				{
					nb_rx_enqueued = rte_ring_enqueue_burst(ring,(void* const*) bufs, nb_rx);
					/* Update stats */
					m_ThreadStats.total_packets += nb_rx;
					m_ThreadStats.enqueued_packets += nb_rx_enqueued;
					m_ThreadStats.missed_packets += nb_rx-nb_rx_enqueued;
//					if(rte_ring_count(ring)/4096*100 > 50)
//						_logger.warning("Queue filled more than 50%");
					if(nb_rx_enqueued < nb_rx)
						_logger.information("Missed %d packets, total %d packets, packets in ring %d", (int) (nb_rx-nb_rx_enqueued), (int)m_ThreadStats.missed_packets, (int) rte_ring_count(ring));
					/* Free whatever we can't put in the write ring */
					while(nb_rx_enqueued < nb_rx)
					{
						rte_pktmbuf_free(bufs[nb_rx_enqueued++]);
				        }
				}
			}
		}
	}
	_logger.debug("Reader thread on core %u terminated", coreId);
	return true;
}
