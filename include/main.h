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

#include <Poco/Util/ServerApplication.h>
#include <Poco/HashMap.h>
#include <rte_common.h>
#include <rte_memory.h>
#include "sender.h"
#include "worker.h"
#include "notification.h"
#include "tries.h"


class AhoCorasickPlus;
class Patricia;
class ACL;

class extFilter: public Poco::Util::ServerApplication
{

public:
	extFilter();
	~extFilter();

	void initialize(Application& self);
	void uninitialize();
	void defineOptions(Poco::Util::OptionSet& options);
	void handleOption(const std::string& name,const std::string& value);
	void handleVersion(const std::string& name,const std::string& value);
	void handleHelp(const std::string& name,const std::string& value);
	void displayHelp();

	void initParams();
	void initFlowsIPv4();

	/// Print DPDK ports
	void printDPDKPorts(const std::string& name,const std::string& value);
	int main(const ArgVec& args);

	std::string &getSSLFile()
	{
		return _sslFile;
	}

	std::string &getDomainsFile()
	{
		return _domainsFile;
	}

	std::string &getURLsFile()
	{
		return _urlsFile;
	}

	std::string &getHostsFile()
	{
	    return _hostsFile;
	}

	std::string &getSSLIpsFile()
	{
		return _sslIpsFile;
	}

	std::string &getNotifyFile()
	{
		return _notify_acl_file;
	}

	static inline struct lcore_conf *getLcoreConf(uint32_t lcore_id)
	{
		return &_lcore_conf[lcore_id];
	}

	inline ACL * getACL()
	{
		return _acl;
	}

	inline int getNuma()
	{
		return _numa_on;
	}

	inline std::vector<DpdkWorkerThread*> &getThreadsVec()
	{
		return _workerThreadVec;
	}

	static inline extFilter *instance()
	{
		return _instance;
	}

	bool loadACL(std::set<struct rte_acl_ctx *> *to_del = NULL);

	inline bool getNotifyEnabled()
	{
		return _notify_enabled;
	}

	inline bool setNotifyEnabled(bool ne)
	{
		_notify_enabled = ne;
		if(ne)
		{
			for(auto const &thread : _workerThreadVec)
			{
				WorkerThread *w = (WorkerThread *)thread;
				WorkerConfig &c = w->getConfig();
				c.notify_enabled = true;
			}
		} else {
			for(auto const &thread : _workerThreadVec)
			{
				WorkerThread *w = (WorkerThread *)thread;
				WorkerConfig &c = w->getConfig();
				c.notify_enabled = false;
			}
		}
		return ne;
	}

	inline TriesManager *getTriesManager()
	{
		return &_tries;
	}

	inline operation_modes getOperationMode()
	{
		return _operation_mode;
	}

	static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
private:
	int initPort(uint8_t port, struct ether_addr *addr, bool no_promisc = false);
	int initSenderPort(uint8_t port, struct ether_addr *addr, uint8_t nb_tx_queue);
	int initMemory(uint8_t nb_ports);
	int initACL();

	uint8_t _get_ports_n_rx_queues(void);
	uint8_t _get_port_n_rx_queues(uint8_t port);
	int _init_lcore_rx_queues(void);
	int _check_lcore_params(void);
	int _check_port_config(const unsigned nb_ports);
	int initDPIMemPools();

	bool _helpRequested;
	bool _listDPDKPorts;

	std::string _urlsFile;
	std::string _domainsFile;
	std::string _sslIpsFile;
	std::string _sslFile;
	std::string _hostsFile;
	std::string _protocolsFile;
	std::string _statisticsFile;

	bool _block_ssl_no_sni;

	int _statistic_interval;

	struct CSender::params _sender_params;

	int _numa_on;
	uint32_t _enabled_port_mask;

	struct lcore_params _lcore_params_array[MAX_LCORE_PARAMS];
	static struct lcore_conf _lcore_conf[RTE_MAX_LCORE];
	uint16_t _nb_lcore_params;
	struct lcore_params* _lcore_params;
	struct rte_mempool* _pktmbuf_pool[NB_SOCKETS];

	uint16_t _nb_rxd = EXTF_RX_DESC_DEFAULT;
	uint16_t _nb_txd = EXTF_TX_DESC_DEFAULT;
	unsigned _nb_ports;

	ACL *_acl;

	bool _notify_enabled;
	std::map<int, struct NotificationParams> _notify_groups;
	std::vector<DpdkWorkerThread*> _workerThreadVec;

	static extFilter *_instance;
	std::string _notify_acl_file;
	int _cmdline_port;
	Poco::Net::IPAddress _cmdline_ip;
	uint8_t _dpdk_send_port;
	TriesManager _tries;
	operation_modes _operation_mode;
};



