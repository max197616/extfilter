#pragma once

#include <Poco/Util/ServerApplication.h>
#include <Poco/HashMap.h>
#include <DpdkDevice.h>
#include "dtypes.h"
#include "sender.h"

#define DEFAULT_MBUF_POOL_SIZE 8191
#define DEFAULT_RING_SIZE 4096


class AhoCorasickPlus;
class Patricia;

class extFilter: public Poco::Util::ServerApplication
{

public:
	extFilter();
	~extFilter();

	void initialize(Application& self);
	void uninitialize();
	void defineOptions(Poco::Util::OptionSet& options);
	void handleOption(const std::string& name,const std::string& value);
	void handleHelp(const std::string& name,const std::string& value);
	void displayHelp();

	/// Print DPDK ports
	void printDPDKPorts(const std::string& name,const std::string& value);
	int main(const ArgVec& args);

	/**
	    Load domains for blocking.
	**/
	void loadDomains(std::string &fn, AhoCorasickPlus *_dm_atm,DomainsMatchType *_dm_map);

	/**
	    Load URLs for blocking.
	**/
	void loadURLs(std::string &fn, AhoCorasickPlus *dm_atm);

	/**
	    Load IP SSL for blocking.
	**/
	void loadSSLIP(const std::string &fn, Patricia *patricia);

	/**
	    Load IP:port for blocking.
	**/
	void loadHosts(std::string &fn, IPPortMap *ippm, Patricia *patricia);

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

	static inline uint64_t getTscHz()
	{
		return _tsc_hz;
	}
	
	pcpp::CoreMask _coreMaskToUse;
	uint32_t _BufPoolSize = DEFAULT_MBUF_POOL_SIZE;
	std::vector<int> _dpdkPortVec;
	
private:
	bool _helpRequested;
	bool _listDPDKPorts;
	int _nbRxQueues;

	std::string _urlsFile;
	std::string _domainsFile;
	std::string _sslIpsFile;
	std::string _sslFile;
	std::string _hostsFile;
	std::string _protocolsFile;
	std::string _statisticsFile;

	bool _lower_host;
	bool _match_url_exactly;
	bool _block_undetected_ssl;
	bool _http_redirect;

	uint32_t _num_of_readers;
	uint32_t _num_of_workers;
	int _statistic_interval;
	uint32_t _ring_size;
	enum ADD_P_TYPES _add_p_type;
	struct CSender::params _sender_params;
	
	static uint64_t _tsc_hz;
	uint32_t _flowhash_size;
	uint32_t _flowhash_size_per_worker;
};



