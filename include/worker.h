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
#include <api.h>
#include "dtypes.h"
#include "AhoCorasickPlus.h"
#include "flow.h"
#include "stats.h"
#include "dpdk.h"
#include "sender.h"

#define EXTF_GC_INTERVAL	1000 // us
#define EXTF_ALL_GC_INTERVAL 1 // seconds

#define EXT_DPI_FLOW_TABLE_MAX_IDLE_TIME 30 /** In seconds. **/

#define EXTFILTER_CAPTURE_BURST_SIZE 32
#define EXTFILTER_WORKER_BURST_SIZE 32

#define URI_RESERVATION_SIZE 4096
#define CERT_RESERVATION_SIZE 1024

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

class NotifyManager;
class ESender;

struct WorkerConfig
{
	uint32_t CoreId;

	uint8_t port;

	AhoCorasickPlus *atm;
	Poco::FastMutex *atmLock; // для загрузки url
	AhoCorasickPlus *atmSSLDomains;
	Poco::FastMutex *atmSSLDomainsLock; // для загрузки domains

	bool match_url_exactly;
	bool lower_host;
	bool block_ssl_no_sni;
	bool http_redirect;
	enum ADD_P_TYPES add_p_type;

	bool url_normalization;
	bool remove_dot;

	bool notify_enabled;
	NotifyManager *nm;

	uint8_t sender_port;
	uint16_t tx_queue_id;

	uint16_t maximum_url_size;

	WorkerConfig()
	{
		CoreId = RTE_MAX_LCORE+1;
		atm = NULL;
		atmSSLDomains = NULL;
		match_url_exactly = false;
		lower_host = false;
		block_ssl_no_sni = false;
		http_redirect = true;
		add_p_type = A_TYPE_NONE;
		url_normalization = true;
		remove_dot = true;
		notify_enabled = false;
		nm = nullptr;
		atmLock = nullptr;
		atmSSLDomainsLock = nullptr;
	}
};

class WorkerThread : public DpdkWorkerThread
{
	friend class ESender;
private:
	WorkerConfig m_WorkerConfig;
	bool m_Stop;
	Poco::Logger& _logger;
	ThreadStats m_ThreadStats;


	uint64_t last_time;

	dpi_library_state_t *dpi_state;

	std::string uri;
	std::string certificate;

	bool analyzePacket(struct rte_mbuf* mBuf, uint64_t timestamp);
	ext_dpi_flow_info *getFlow(uint8_t *host_key, uint64_t timestamp, int32_t *idx, uint32_t sig, dpi_pkt_infos_t *pkt_infos);
	dpi_identification_result_t getAppProtocol(uint8_t *host_key, uint64_t timestamp, uint32_t sig, dpi_pkt_infos_t *pkt_infos);
	dpi_identification_result_t identifyAppProtocol(const unsigned char* pkt, u_int32_t length, u_int32_t current_time, uint8_t *host_key, uint32_t sig);

	bool checkSSL();
	std::string _name;
	bool _need_block;
	uint16_t _partition_id;

	struct ext_dpi_flow_info **ipv4_flows;
	struct ext_dpi_flow_info **ipv6_flows;

	struct rte_mempool *flows_pool;

	flowHash *m_FlowHash;
	/// for sender through dpdk
	int _n_send_pkts;
	struct rte_mbuf* _sender_buf[EXTFILTER_WORKER_BURST_SIZE];
	ESender *_snd;
	struct rte_mempool *_url_mempool;
	struct rte_mempool *_dpi_mempool;
public:
	WorkerThread(const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, int socketid, flowHash *fh, struct ESender::nparams &sp, struct rte_mempool *mp, struct rte_mempool *url_mempool, struct rte_mempool *dpi_mempool);

	~WorkerThread();

	bool checkHTTP(std::string &uri, dpi_pkt_infos_t *pkt);
	bool checkSSL(std::string &certificate, dpi_pkt_infos_t *pkt);

	inline std::string &getUri()
	{
		return uri;
	}

	inline std::string &getCert()
	{
		return certificate;
	}

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

	inline struct rte_mempool *getUrlMempool()
	{
		return _url_mempool;
	}
	inline struct rte_mempool *getDPIMempool()
	{
		return _dpi_mempool;
	}

};

