#pragma once

#include <Poco/Util/ServerApplication.h>
#include <Poco/HashMap.h>
#include <DpdkDevice.h>
#include "worker.h"
#include "sender.h"

#define DEFAULT_MBUF_POOL_SIZE 4095



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
	void loadHosts(std::string &fn,IPPortMap *ippm);

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

	pcpp::CoreMask _coreMaskToUse;
	uint32_t _BufPoolSize = DEFAULT_MBUF_POOL_SIZE;
	std::vector<int> _dpdkPortVec;
	
	static u_int32_t ndpi_size_flow_struct;
	static u_int32_t ndpi_size_id_struct;
	static u_int32_t current_ndpi_memory;
	static u_int32_t max_ndpi_memory;

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

	bool _lower_host;
	bool _match_url_exactly;
	bool _block_undetected_ssl;
	bool _http_redirect;

	int _statistic_interval;
	enum ADD_P_TYPES _add_p_type;
	struct CSender::params _sender_params;
};



