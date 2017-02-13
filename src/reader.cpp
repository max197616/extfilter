
#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>


#include "worker.h"
#include "main.h"
#include "distributor.h"

ReaderThread::ReaderThread(const std::string& name, WorkerConfig &workerConfig, Distributor *distr) :
		m_WorkerConfig(workerConfig), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1),
		_logger(Poco::Logger::get(name)),
		m_CanRun(false),
		_distr(distr)
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
					rte_distributor_process(_distr->getDistributor(), bufs, nb_rx);
					m_ThreadStats.total_packets += nb_rx;
					m_ThreadStats.enqueued_packets += nb_rx;
				}
			}
		}
	}
	rte_distributor_process(_distr->getDistributor(), NULL, 0);
	/* flush distributor to bring to known state */
	_distr->flush();
	_logger.debug("Reader thread on core %u terminated", coreId);
	return true;
}
