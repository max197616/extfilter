#pragma once

#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <iostream>
#include <Poco/Mutex.h>
#include <Poco/HashMap.h>
#include <Poco/Logger.h>
#include <ndpi_api.h>
#include <rte_hash.h>
#include "dtypes.h"
#include "AhoCorasickPlus.h"
#include "patr.h"
#include "flow.h"
#include "stats.h"
#include "dpdk.h"


#define EXTF_GC_INTERVAL	1000 // us
#define EXTF_GC_BUDGET		128 // entries per EXTF_GC_INTERVAL
#define EXTF_ALL_GC_INTERVAL 1 // seconds


#define MAX_IDLE_TIME           30000 // msec

#define EXTFILTER_CAPTURE_BURST_SIZE 32
#define EXTFILTER_WORKER_BURST_SIZE 32

#define URI_RESERVATION_SIZE 2048

/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK ports and which RX queues to receive packet from
 * - Whether to send matched packets to TX DPDK port and/or save them to a pcap file
 */
struct WorkerConfig
{
	uint32_t CoreId;
	int port;
	AhoCorasickPlus *atm;
	Poco::FastMutex atmLock; // для загрузки url
	AhoCorasickPlus *atmSSLDomains;
	DomainsMatchType *SSLdomainsMatchType;
	Poco::FastMutex atmSSLDomainsLock; // для загрузки domains
	Patricia *sslIPs; // ip addresses for blocking
	Poco::FastMutex sslIPsLock;
	IPPortMap *ipportMap;
	Patricia *ipPortMap;
	Poco::FastMutex ipportMapLock;

	bool match_url_exactly;
	bool lower_host;
	bool block_undetected_ssl;
	bool http_redirect;
	std::string PathToWritePackets;
	enum ADD_P_TYPES add_p_type;
	struct ndpi_detection_module_struct *ndpi_struct;
	uint32_t max_ndpi_flows;
	uint32_t num_roots;

	EntriesData *entriesData;

	bool url_normalization;
	bool remove_dot;

	WorkerConfig()
	{
		CoreId = RTE_MAX_LCORE+1;
		atm = NULL;
		atmSSLDomains = NULL;
		SSLdomainsMatchType = NULL;
		sslIPs = NULL;
		ipportMap = NULL;
		match_url_exactly = false;
		lower_host = false;
		block_undetected_ssl = false;
		http_redirect = true;
		add_p_type = A_TYPE_NONE;
		ndpi_struct = NULL;
//		max_ndpi_flows = MAX_NDPI_FLOWS;
//		num_roots = NUM_ROOTS;

		url_normalization = true;
		remove_dot = true;
	}
/*	
	WorkerConfig(const WorkerConfig& cf)
	{
		memcpy(&this->CoreId,&cf.CoreId,sizeof(WorkerConfig));
	}*/
};

class Distributor;

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

	Distributor *_distr;

	int _worker_id;

	std::string uri;

	bool analyzePacket(struct rte_mbuf* mBuf, uint64_t timestamp);
	bool analyzePacketFlow(struct rte_mbuf *m, uint64_t timestamp);
//	Flow *getFlow(Poco::Net::IPAddress *src_ip, Poco::Net::IPAddress *dst_ip, uint16_t src_port, uint8_t dst_port, uint8_t protocol, bool *src2dst_direction, time_t first_seen, time_t last_seen, bool *new_flow);
public:
	WorkerThread(const std::string& name, WorkerConfig &workerConfig, flowHash *fh, Distributor *distr, int worker_id);

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

	ndpi_flow_info *getFlow(uint8_t *ip_header, int ip_version, uint64_t timestamp);
//	ndpi_flow_info *getFlow(Poco::Net::IPAddress *src_ip, Poco::Net::IPAddress *dst_ip, uint16_t src_port, uint8_t dst_port, uint8_t protocol, uint64_t timestamp);
};

class ReaderThread : public DpdkWorkerThread
{
private:
	WorkerConfig &m_WorkerConfig;
	bool m_Stop;
	Poco::Logger& _logger;
	ThreadStats m_ThreadStats;
	bool m_CanRun;
	Distributor *_distr;
public:

	ReaderThread(const std::string& name, WorkerConfig &workerConfig, Distributor *distr);
	~ReaderThread();

	bool run(uint32_t coreId);

	void stop()
	{
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

	void canRun(bool run)
	{
		m_CanRun=run;
	}

};

