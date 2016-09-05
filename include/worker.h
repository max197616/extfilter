#pragma once

#include <DpdkDevice.h>
#include <DpdkDeviceList.h>
#include <Packet.h>
#include <PacketUtils.h>
#include <HttpLayer.h>
#include <vector>
#include <map>
#include <set>
#include <iostream>
#include <Poco/Mutex.h>
#include <Poco/HashMap.h>
#include <Poco/Logger.h>
#include "AhoCorasickPlus.h"
#include "patr.h"
#include "stats.h"

typedef Poco::HashMap<unsigned int,bool> DomainsMatchType;

typedef std::map<pcpp::DpdkDevice*, std::vector<int> > InputDataConfig;

typedef std::map<Poco::Net::IPAddress,std::set<unsigned short>> IPPortMap;

enum ADD_P_TYPES { A_TYPE_NONE, A_TYPE_ID, A_TYPE_URL };

/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK ports and which RX queues to receive packet from
 * - Whether to send matched packets to TX DPDK port and/or save them to a pcap file
 */
struct WorkerConfig
{
	uint32_t CoreId;
	InputDataConfig InDataCfg;
	AhoCorasickPlus *atm;
	Poco::FastMutex atmLock; // для загрузки url
	AhoCorasickPlus *atmDomains;
	DomainsMatchType domainsMatchType;
	Poco::FastMutex atmDomainsLock; // для загрузки domains
	AhoCorasickPlus *atmSSLDomains;
	DomainsMatchType SSLdomainsMatchType;
	Poco::FastMutex atmSSLDomainsLock; // для загрузки domains
	Patricia *sslIPs; // ip addresses for blocking
	IPPortMap *ipportMap;
	Poco::FastMutex ipportMapLock;

	bool match_url_exactly;
	bool lower_host;
	bool block_undetected_ssl;
	bool http_redirect;
	std::string PathToWritePackets;
	enum ADD_P_TYPES add_p_type;
	WorkerConfig() : CoreId(MAX_NUM_OF_CORES+1), atm(NULL), atmDomains(NULL), atmSSLDomains(NULL), sslIPs(NULL), ipportMap(NULL), match_url_exactly(false),lower_host(false),block_undetected_ssl(false),http_redirect(true),add_p_type(A_TYPE_NONE) { }
};


class WorkerThread : public pcpp::DpdkWorkerThread
{
private:
	WorkerConfig& m_WorkerConfig;
	bool m_Stop;
	uint32_t m_CoreId;
//	std::map<uint32_t, bool> m_FlowTable;
	Poco::Logger& _logger;
	ThreadStats m_ThreadStats;
	bool analyzePacket(pcpp::Packet &parsedPacket);
public:
	WorkerThread(const std::string& name, WorkerConfig& workerConfig) :
		m_WorkerConfig(workerConfig), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1),
		_logger(Poco::Logger::get(name))
	{
	}

	virtual ~WorkerThread() {}

	bool run(uint32_t coreId);

	void stop()
	{
		// assign the stop flag which will cause the main loop to end
		m_Stop = true;
	}

	uint32_t getCoreId()
	{
		return m_CoreId;
	}

	const ThreadStats& getStats()
	{
		return m_ThreadStats;
	}

};