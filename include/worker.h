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
#include <api.h>
#include "flow.h"
#include "stats.h"
#include "dpdk.h"
#include "sender.h"
#include "http.h"
#include "ssl.h"

#define EXTFILTER_CAPTURE_BURST_SIZE 32
#define EXTFILTER_WORKER_BURST_SIZE 32

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
	dpi_identification_result_t identifyAppProtocol(const unsigned char* pkt, u_int32_t length, u_int32_t current_time, uint8_t *host_key, uint32_t sig);

	bool checkSSL();
	std::string _name;
	bool _need_block;

	/// for sender through dpdk
	int _n_send_pkts;
	struct rte_mbuf* _sender_buf[EXTFILTER_WORKER_BURST_SIZE];
	ESender *_snd;
	struct rte_mempool *_dpi_http_mempool;
	struct rte_mempool *_dpi_ssl_mempool;

	struct rte_mempool *_pkt_info_mempool;
	uint8_t _worker_id;
	uint32_t ipv4_flow_mask;
	uint32_t ipv6_flow_mask;
public:

	WorkerThread(uint8_t worker_id, const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, int socketid, struct ESender::nparams &sp, struct rte_mempool *mp, struct rte_mempool *dpi_http_mempool, struct rte_mempool *dpi_ssl_mempool);
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
};

