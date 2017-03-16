#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>


#include "worker.h"
#include "main.h"
#include "distributor.h"

ReaderThread::ReaderThread(const std::string& name, WorkerConfig &workerConfig, Distributor *distr) :
		m_WorkerConfig(workerConfig), m_Stop(true),
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
	setCoreId(coreId);
//	m_CoreId = coreId;
	m_Stop = false;
	uint16_t nb_rx;
	struct rte_mbuf *bufs[EXTFILTER_CAPTURE_BURST_SIZE];

	_logger.debug("Starting reading thread on core %u", coreId);

	while (!m_Stop)
	{
		if(!m_CanRun)
		{
			sched_yield();
			continue;
		}
		nb_rx = rte_eth_rx_burst(m_WorkerConfig.port, 0, bufs, EXTFILTER_CAPTURE_BURST_SIZE);
		if (likely(nb_rx > 0))
		{
			int processed_pkts=rte_distributor_process(_distr->getDistributor(), bufs, nb_rx);
			m_ThreadStats.total_packets += nb_rx;
			m_ThreadStats.enqueued_packets += processed_pkts;
			m_ThreadStats.missed_packets += nb_rx-processed_pkts;
			while(processed_pkts < nb_rx)
			{
				rte_pktmbuf_free(bufs[processed_pkts++]);
			}
		}
	}
	rte_distributor_process(_distr->getDistributor(), NULL, 0);
	/* flush distributor to bring to known state */
	_distr->flush();
	_logger.debug("Reader thread on core %u terminated", coreId);
	return true;
}
