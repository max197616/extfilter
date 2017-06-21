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
#include "dtypes.h"
#include "AhoCorasickPlus.h"
#include "flow.h"
#include "stats.h"
#include "dpdk.h"


#define EXTF_GC_INTERVAL	1000 // us
#define EXTF_GC_BUDGET		128 // entries per EXTF_GC_INTERVAL
#define EXTF_ALL_GC_INTERVAL 1 // seconds


#define MAX_IDLE_TIME           30000 // msec

#define EXTFILTER_CAPTURE_BURST_SIZE 32
#define EXTFILTER_WORKER_BURST_SIZE 32

#define URI_RESERVATION_SIZE 4096

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

class NotifyManager;

struct WorkerConfig
{
	uint32_t CoreId;
	int port;
	AhoCorasickPlus *atm;
	Poco::FastMutex atmLock; // для загрузки url
	AhoCorasickPlus *atmSSLDomains;
	DomainsMatchType *SSLdomainsMatchType;
	Poco::FastMutex atmSSLDomainsLock; // для загрузки domains

	bool match_url_exactly;
	bool lower_host;
	bool block_undetected_ssl;
	bool http_redirect;
	enum ADD_P_TYPES add_p_type;

	EntriesData *entriesData;

	bool url_normalization;
	bool remove_dot;

	bool notify_enabled;
	NotifyManager *nm;

	WorkerConfig()
	{
		CoreId = RTE_MAX_LCORE+1;
		atm = NULL;
		atmSSLDomains = NULL;
		SSLdomainsMatchType = NULL;
		match_url_exactly = false;
		lower_host = false;
		block_undetected_ssl = false;
		http_redirect = true;
		add_p_type = A_TYPE_NONE;
		url_normalization = true;
		remove_dot = true;
		notify_enabled = false;
		nm = nullptr;
	}
};

class WorkerThread : public DpdkWorkerThread
{
private:
	WorkerConfig &m_WorkerConfig;
	bool m_Stop;
	Poco::Logger& _logger;
	ThreadStats m_ThreadStats;


	uint64_t last_time;

	flowHash *m_FlowHash;

	struct ndpi_flow_info **ipv4_flows;
	struct ndpi_flow_info **ipv6_flows;

	struct rte_mempool *flows_pool;

	std::string uri;

	bool analyzePacket(struct rte_mbuf* mBuf);
	bool analyzePacketFlow(struct rte_mbuf *m, uint64_t timestamp);
	std::string _name;
public:
	WorkerThread(const std::string& name, WorkerConfig &workerConfig, flowHash *fh, int socketid);

	~WorkerThread();

	bool run(uint32_t coreId);

	void stop()
	{
		// assign the stop flag which will cause the main loop to end
		m_Stop = true;
	}

	const ThreadStats& getStats()
	{
		return m_ThreadStats;
	}

	WorkerConfig& getConfig()
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

	ndpi_flow_info *getFlow(uint8_t *ip_header, int ip_version, uint64_t timestamp, int32_t *idx, uint32_t sig);
};

