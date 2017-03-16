#include <cinttypes>
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/NumberParser.h>
#include <Poco/FileStream.h>
#include <Poco/TaskManager.h>
#include <Poco/StringTokenizer.h>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include "worker.h"
#include "main.h"

#include "AhoCorasickPlus.h"
#include "patr.h"
#include "qdpi.h"
#include "sendertask.h"
#include "statistictask.h"
#include "reloadtask.h"
#include "distributor.h"

#define MBUF_CACHE_SIZE 256

#define RX_RING_SIZE 256
#define TX_RING_SIZE 512

#define DPDK_CONFIG_HEADER_SPLIT	0 /**< Header Split disabled */
#define DPDK_CONFIG_SPLIT_HEADER_SIZE	0
#define DPDK_CONFIG_HW_IP_CHECKSUM	0 /**< IP checksum offload disabled */
#define DPDK_CONFIG_HW_VLAN_FILTER	0 /**< VLAN filtering disabled */
#define DPDK_CONFIG_JUMBO_FRAME		0 /**< Jumbo Frame Support disabled */
#define DPDK_CONFIG_HW_STRIP_CRC	0 /**< CRC stripped by hardware disabled */
#define DPDK_CONFIG_MQ_MODE		ETH_MQ_RX_RSS

uint64_t extFilter::_tsc_hz;

extFilter::extFilter(): _helpRequested(false), _listDPDKPorts(false), _nbRxQueues(1)
{
//	Poco::ErrorHandler::set(&_errorHandler);
}


extFilter::~extFilter()
{
}


uint8_t m_RSSKey[40] = {
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

int extFilter::initPort(int port, struct rte_mempool *mbuf_pool, struct ether_addr *addr)
{
	const uint16_t rxRings = 1, txRings = 1;
	uint16_t q;
	struct rte_eth_conf portConf;
	memset(&portConf,0,sizeof(rte_eth_conf));
	portConf.rxmode.split_hdr_size = DPDK_CONFIG_SPLIT_HEADER_SIZE;
	portConf.rxmode.header_split = DPDK_CONFIG_HEADER_SPLIT;
	portConf.rxmode.hw_ip_checksum = DPDK_CONFIG_HW_IP_CHECKSUM;
	portConf.rxmode.hw_vlan_filter = DPDK_CONFIG_HW_VLAN_FILTER;
	portConf.rxmode.jumbo_frame = DPDK_CONFIG_JUMBO_FRAME;
	portConf.rxmode.hw_strip_crc = DPDK_CONFIG_HW_STRIP_CRC;
	portConf.rxmode.mq_mode = DPDK_CONFIG_MQ_MODE;
//<---->portConf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
	portConf.rx_adv_conf.rss_conf.rss_key = m_RSSKey;
	portConf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV6;
	int retval;
	retval = rte_eth_dev_configure(port, rxRings, txRings, &portConf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rxRings; q++)
	{
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < txRings; q++)
	{
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct rte_eth_link link;
	rte_eth_link_get_nowait(port, &link);
	if (!link.link_status)
	{
		sleep(1);
		rte_eth_link_get_nowait(port, &link);
	}

	if (!link.link_status)
	{
		logger().warning("Link down on port %d", port);
		return 0;
	}

	rte_eth_macaddr_get(port, addr);
	char buffer[100];
	sprintf(buffer,"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8, addr->addr_bytes[0], addr->addr_bytes[1], addr->addr_bytes[2], addr->addr_bytes[3],addr->addr_bytes[4], addr->addr_bytes[5]);
	std::string mac_addr(buffer);
	logger().information("Port %d MAC: %s", port, mac_addr);

	rte_eth_promiscuous_enable(port);

	return 0;
}

void extFilter::initialize(Application& self)
{
	loadConfiguration();
	ServerApplication::initialize(self);

	_num_of_readers = 1;
//	_num_of_readers=config().getInt("num_of_readers", 1);
	_num_of_workers=config().getInt("num_of_workers", 1);
	if(!_num_of_readers)
	{
		logger().fatal("Number of readers must be greate zero");
		throw Poco::Exception("Number of readers must be greate zero");
	}
	if(!_num_of_workers)
	{
		logger().fatal("Number of workers must be greate zero");
		throw Poco::Exception("Number of workers must be greate zero");
	}

	_flowhash_size=config().getInt("flowhash_size",1024*1024);
	if(!rte_is_power_of_2(_flowhash_size))
	{
		logger().fatal("Size of the flowhash must be power of 2, got %d must be %d", (int) _flowhash_size, (int) rte_align32pow2(_flowhash_size));
		throw Poco::Exception("Size of the flowhash must be power of 2");
	}

	_flowhash_size_per_worker=rte_align32pow2(_flowhash_size/_num_of_workers);

	_num_of_senders=config().getInt("num_of_senders", 1);
	_lower_host=config().getBool("lower_host", false);
	_match_url_exactly=config().getBool("match_url_exactly", false);
	_block_undetected_ssl=config().getBool("block_undetected_ssl", false);
	_http_redirect=config().getBool("http_redirect", true);
	_url_normalization=config().getBool("url_normalization", true);
	_remove_dot=config().getBool("remove_dot", true);
	_statistic_interval=config().getInt("statistic_interval", 0);
	_nbRxQueues = 1;
//	_nbRxQueues=config().getInt("rx_queues", 1);
	_BufPoolSize=config().getInt("mbuf_pool_size", DEFAULT_MBUF_POOL_SIZE);


	logger().information("Setting mbuf size to %u",_BufPoolSize);

	_urlsFile=config().getString("urllist","");
	_domainsFile=config().getString("domainlist","");
	_sslIpsFile=config().getString("sslips","");
	_sslFile=config().getString("ssllist","");
	_hostsFile=config().getString("hostlist","");
	_statisticsFile=config().getString("statisticsfile","");

	std::string http_code=config().getString("http_code","");
	if(!http_code.empty())
	{
		http_code.erase(std::remove(http_code.begin(), http_code.end(), '"'), http_code.end());
		_sender_params.code=http_code;
		logger().debug("HTTP code set to %s", http_code);
	}
	_sender_params.redirect_url=config().getString("redirect_url","");
	_sender_params.send_rst_to_server=config().getBool("rst_to_server",false);
	_sender_params.mtu=config().getInt("out_mtu",1500);

	std::string add_p_type=config().getString("url_additional_info","none");
	std::transform(add_p_type.begin(), add_p_type.end(), add_p_type.begin(), ::tolower);

	std::map<std::string, ADD_P_TYPES> add_type_s;
	add_type_s["none"]=A_TYPE_NONE;
	add_type_s["line"]=A_TYPE_ID;
	add_type_s["url"]=A_TYPE_URL;

	std::map<std::string, ADD_P_TYPES>::iterator it=add_type_s.find(add_p_type);
	if(it == add_type_s.end())
	{
		throw Poco::Exception("Unknown url_additional_info type '" + add_p_type + "'",404);
	}
	_add_p_type=it->second;
	logger().debug("URL additional info set to %s", add_p_type);

	std::string dpdk_ports=config().getString("dpdk_ports","");
	if(!dpdk_ports.empty())
	{
		Poco::StringTokenizer restTokenizer(dpdk_ports, ",");
		for(Poco::StringTokenizer::Iterator itr=restTokenizer.begin(); itr!=restTokenizer.end(); ++itr)
		{
			_dpdkPortVec.push_back(Poco::NumberParser::parse(*itr));
		}
	}

	int dpdk_port = config().getInt("dpdk_port", -1);
	if(dpdk_port != -1)
		_dpdkPortVec.push_back(dpdk_port);

	if(_dpdkPortVec.empty())
	{
		logger().fatal("DPDK ports not specified!");
		throw Poco::Exception("DPDK ports not specified!");
	}

	_protocolsFile=config().getString("protocols","");

	int coreMaskToUse=config().getInt("core_mask", 0);

	// initialize DPDK
	std::stringstream dpdkParamsStream;
	dpdkParamsStream << commandName().c_str() << " ";
	dpdkParamsStream << "-n ";
	dpdkParamsStream << "2 ";
	dpdkParamsStream << "-c ";
	dpdkParamsStream << "0x" << std::hex << std::setw(2) << std::setfill('0') << coreMaskToUse << " ";
	dpdkParamsStream << "--master-lcore ";
	dpdkParamsStream << "0";


	int initDpdkArgc=7;
	std::string dpdkParamsArray[initDpdkArgc];
	char** initDpdkArgv = new char*[initDpdkArgc];
	int i = 0;
	while (dpdkParamsStream.good() && i < initDpdkArgc)
	{
		dpdkParamsStream >> dpdkParamsArray[i];
		initDpdkArgv[i] = new char[dpdkParamsArray[i].size()+1];
		strcpy(initDpdkArgv[i], dpdkParamsArray[i].c_str());
		i++;
	}

	char* lastParam = initDpdkArgv[i-1];

	for (i = 0; i < initDpdkArgc; i++)
	{
		std::string arg(initDpdkArgv[i]);
		logger().debug("DPDK command line: %s", arg);
	}

	optind = 1;
	// init the EAL
	int ret = rte_eal_init(initDpdkArgc, (char**)initDpdkArgv);
	if (ret < 0)
		throw Poco::Exception("Can't initialize EAL - invalid EAL arguments");

	for (i = 0; i < initDpdkArgc-1; i++)
	{
		delete [] initDpdkArgv[i];
	}
	delete [] lastParam;

	delete [] initDpdkArgv;

	// init value...
	_tsc_hz = rte_get_tsc_hz();

}

void extFilter::uninitialize()
{
	logger().debug("Shutting down");
	ServerApplication::uninitialize();
}

void extFilter::defineOptions(Poco::Util::OptionSet& options)
{
	ServerApplication::defineOptions(options);
	options.addOption(
		Poco::Util::Option("help","h","Display help on command line arguments.")
			.required(false)
			.repeatable(false)
			.callback(Poco::Util::OptionCallback<extFilter>(this,&extFilter::handleHelp)));
	options.addOption(
		Poco::Util::Option("list","l","Print the list of DPDK ports and exit.")
			.required(false)
			.repeatable(false)
			.callback(Poco::Util::OptionCallback<extFilter>(this,&extFilter::printDPDKPorts)));
	options.addOption(
		Poco::Util::Option("config-file","f","Specify config file to read.")
			.required(true)
			.repeatable(false)
			.argument("FILE"));
	options.addOption(
		Poco::Util::Option("dpdk-ports","d","A comma-separated list of the DPDK port numbers to receive packets from.")
			.required(false)
			.repeatable(false)
			.argument("PORT_1..."));
	options.addOption(
		Poco::Util::Option("mbuf-pool-size","m","DPDK mBuf pool size to initialize DPDK with. Default value is 4095.")
			.required(false)
			.repeatable(false)
			.argument("POOL_SIZE"));
}

void extFilter::handleOption(const std::string& name,const std::string& value)
{
	ServerApplication::handleOption(name, value);
	if(name == "config-file")
	{
		loadConfiguration(value);
	}
	if(name == "mbuf-pool-size")
	{
		_BufPoolSize =  Poco::NumberParser::parse(value);
	}
	if(name == "dpdk-ports")
	{
		Poco::StringTokenizer restTokenizer(value, ",");
		for(Poco::StringTokenizer::Iterator itr=restTokenizer.begin(); itr!=restTokenizer.end(); ++itr)
		{
			_dpdkPortVec.push_back(Poco::NumberParser::parse(*itr));
		}
	}
}

void extFilter::handleHelp(const std::string& name,const std::string& value)
{
	_helpRequested=true;
	displayHelp();
	stopOptionsProcessing();
}

void extFilter::displayHelp()
{
	Poco::Util::HelpFormatter helpFormatter(options());
	helpFormatter.setCommand(commandName());
	helpFormatter.setUsage("<-c config file> [options]");
	helpFormatter.setHeader("extFilter");
	helpFormatter.format(std::cout);
}

void extFilter::printDPDKPorts(const std::string& name,const std::string& value)
{
	_listDPDKPorts=true;
	stopOptionsProcessing();
	// initialize DPDK
/*	if (!pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, DEFAULT_MBUF_POOL_SIZE))
	{
		logger().fatal("Couldn't initialize DPDK!");
		return;
	}

	std::cout << "DPDK port list:" << std::endl;

	// go over all available DPDK devices and print info for each one
	std::vector<pcpp::DpdkDevice*> deviceList = pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList();
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
	{
		pcpp::DpdkDevice* dev = *iter;
		printf("\tPort #%d: MAC address='%s'; PCI address='%s'; PMD='%s'\n",
				dev->getDeviceId(),
				dev->getMacAddress().toString().c_str(),
				dev->getPciAddress().toString().c_str(),
				dev->getPMDName().c_str());
	}
*/

}

namespace
{
	static void handleSignal(int sig)
	{
		Poco::Util::Application& app = Poco::Util::Application::instance();
		app.logger().information("Got HUP signal - reload data");
		ReloadTask::_event.set();
	}
}


int extFilter::main(const ArgVec& args)
{
	if(!_helpRequested && !_listDPDKPorts)
	{
//		int i;
		int nb_lcores = rte_lcore_count();
		int master_core_id = rte_get_master_lcore();

		logger().information("Master core is %d", master_core_id);
/*		RTE_LCORE_FOREACH_SLAVE(i) {
	    continue;
	prf_lcore_conf[i].core_role = WORKER_CORE;
	prf_lcore_conf[i].queue_id = ++j;
	prf_nb_worker_cores++;
		}
*/
		if(nb_lcores < 3)
		{
			logger().fatal("Minimum number of required cores is 3");
			return Poco::Util::Application::EXIT_CONFIG;
		}

		if(_num_of_readers + _num_of_workers > nb_lcores-1)
		{
			logger().fatal("Number of cores (%d) is not enought for starting reader and worker threads (%d). Check the configuration.", (int) nb_lcores, int (_num_of_readers + _num_of_workers));
			return Poco::Util::Application::EXIT_CONFIG;
		}

		bool isPoolSizePowerOfTwoMinusOne = !(_BufPoolSize == 0) && !((_BufPoolSize+1) & (_BufPoolSize));
		if (!isPoolSizePowerOfTwoMinusOne)
		{
			logger().fatal("mBuf pool size must be a power of two minus one: n = (2^q - 1). It's currently: %d", (int)_BufPoolSize);
			return Poco::Util::Application::EXIT_CONFIG;
		}

		if(_dpdkPortVec.size() != 1)
		{
			logger().fatal("Number of input ethernet ports not equal to 1");
			return Poco::Util::Application::EXIT_CONFIG;
		}

		struct sigaction handler;
		handler.sa_handler = handleSignal;
		handler.sa_flags   = 0;
		sigemptyset(&handler.sa_mask);
		sigaction(SIGHUP, &handler, NULL);


		int nb_ports = rte_eth_dev_count();
		if(nb_ports == 0)
		{
			logger().fatal("No ethernet ports detected");
			return Poco::Util::Application::EXIT_CONFIG;
		}

		struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
			_BufPoolSize*_dpdkPortVec.size(),
			MBUF_CACHE_SIZE, // cache size
			0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

		for (std::vector<int>::iterator iter = _dpdkPortVec.begin(); iter != _dpdkPortVec.end(); iter++)
		{
			struct ether_addr addr;
			if(initPort(*iter, mbuf_pool, &addr) != 0)
			{
				logger().fatal("Cannot initialize port %d", *iter);
				return Poco::Util::Application::EXIT_CONFIG;
			}
		}


		WorkerConfig workerConfigArr[nb_lcores-1];
//		prepareCoreConfiguration(dpdkDevicesToUse, coresToUse, workerConfigArr, coresToUse.size(), _num_of_readers, _nbRxQueues);

		// create worker thread for every core
		std::vector<DpdkWorkerThread*> workerThreadVec;

		Distributor *distributor=new Distributor(_num_of_workers);

//		std::vector<pcpp::SystemCore>::iterator iter = coresToUse.begin();
		// подгототавливаем readerы
		int i = 0;
		for(i=0; i < _num_of_readers; i++)
		{
			std::string workerName("ReaderThread " + std::to_string(i));
			logger().debug("Preparing thread '%s'", workerName);
			workerConfigArr[i].port = _dpdkPortVec[0];
			ReaderThread* newWorker = new ReaderThread(workerName, workerConfigArr[i], distributor);
			workerThreadVec.push_back(newWorker);
		}
		int num_of_workers=_num_of_workers;
		int worker_id=0;
		while(num_of_workers)
		{
			if(!_domainsFile.empty() && !_urlsFile.empty())
			{
				workerConfigArr[i].atm = new AhoCorasickPlus();
				workerConfigArr[i].entriesData = new EntriesData();
				loadDomainsURLs(_domainsFile, _urlsFile, workerConfigArr[i].atm, workerConfigArr[i].entriesData);
				workerConfigArr[i].atm->finalize();
			}
			if(!_sslIpsFile.empty() && _block_undetected_ssl)
			{
				workerConfigArr[i].block_undetected_ssl = true;
				workerConfigArr[i].sslIPs = new Patricia();
				loadSSLIP(_sslIpsFile, workerConfigArr[i].sslIPs);
			}
			if(!_sslFile.empty())
			{
				workerConfigArr[i].atmSSLDomains = new AhoCorasickPlus();
				workerConfigArr[i].SSLdomainsMatchType = new DomainsMatchType;
				loadDomains(_sslFile, workerConfigArr[i].atmSSLDomains, workerConfigArr[i].SSLdomainsMatchType);
				workerConfigArr[i].atmSSLDomains->finalize();
			}
			if(!_hostsFile.empty())
			{
				workerConfigArr[i].ipportMap = new IPPortMap;
				workerConfigArr[i].ipPortMap = new Patricia();
				loadHosts(_hostsFile, workerConfigArr[i].ipportMap, workerConfigArr[i].ipPortMap);
			}
//			workerConfigArr[i].PathToWritePackets = "thread"+std::to_string(i)+".pcap";
			workerConfigArr[i].match_url_exactly = _match_url_exactly;
			workerConfigArr[i].lower_host = _lower_host;
			workerConfigArr[i].http_redirect = _http_redirect;
			workerConfigArr[i].url_normalization = _url_normalization;
			workerConfigArr[i].remove_dot = _remove_dot;
			workerConfigArr[i].add_p_type = _add_p_type;
			workerConfigArr[i].ndpi_struct = init_ndpi();
			if (!workerConfigArr[i].ndpi_struct)
			{
				logger().fatal("Can't initialize nDPI!");
				return Poco::Util::Application::EXIT_CONFIG;
			}
			if(!_protocolsFile.empty())
			{
				logger().debug("Loading nDPI protocols from file %s", _protocolsFile);
				ndpi_load_protocols_file(workerConfigArr[i].ndpi_struct, (char *)_protocolsFile.c_str());
			}
			logger().debug("Creating flowHash for the worker with %d entries", (int)_flowhash_size_per_worker);
			flowHash *mFlowHash = new flowHash(rte_socket_id(), i, _flowhash_size_per_worker); // update socket id

			std::string workerName("WorkerThread " + std::to_string(i));
			logger().debug("Preparing thread '%s'", workerName);
			WorkerThread* newWorker = new WorkerThread(workerName, workerConfigArr[i], mFlowHash, distributor, worker_id);
			workerThreadVec.push_back(newWorker);
			i++;
			num_of_workers--;
			worker_id++;
		}

		Poco::TaskManager tm;
		for(int i=1; i <= _num_of_senders; i++)
			tm.start(new SenderTask(_sender_params,i));

		logger().debug("Starting worker threads...");

		int cur_lcore = rte_get_next_lcore(-1, 1, 0);
		for (auto iter = workerThreadVec.begin(); iter != workerThreadVec.end(); iter++)
		{
			logger().debug("Starting thread on core %d" ,cur_lcore);
			if(cur_lcore == RTE_MAX_LCORE)
			{
				logger().fatal("There is no free core for launch thread");
				return Poco::Util::Application::EXIT_CONFIG;
			}
			int err = rte_eal_remote_launch(dpdkWorkerThreadStart, *iter, cur_lcore);
			if (err != 0)
			{
				logger().fatal("Unable to launch thread on core %d, error: %d", cur_lcore, err);
				return Poco::Util::Application::EXIT_CONFIG;
			}
			logger().debug("Started thread on core %d" ,cur_lcore);
			cur_lcore = rte_get_next_lcore(cur_lcore, 1, 0);
		}

//		sleep(4);
		// start readers...
		for(auto it=workerThreadVec.begin(); it != workerThreadVec.end(); it++)
		{
			if(dynamic_cast<ReaderThread*>(*it) != nullptr)
			{
				dynamic_cast<ReaderThread*>(*it)->canRun(true);
			}
		}

		tm.start(new StatisticTask(_statistic_interval, workerThreadVec, _statisticsFile));
		tm.start(new ReloadTask(this, workerThreadVec));
		waitForTerminationRequest();

		for (auto iter = workerThreadVec.begin(); iter != workerThreadVec.end(); iter++)
		{
			(*iter)->stop();
			rte_eal_wait_lcore((*iter)->getCoreId());
		}

//		pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

		tm.cancelAll();
		SenderTask::queue.wakeUpAll();
		tm.joinAll();
		// stop worker threads

/*		for (std::vector<pcpp::DpdkWorkerThread*>::iterator iter = workerThreadVec.begin(); iter != workerThreadVec.end(); iter++)
		{
			WorkerThread* thread = (WorkerThread*)(*iter);
			delete thread;
			
		}*/
	}
	return Poco::Util::Application::EXIT_OK;
}

void extFilter::loadDomainsURLs(std::string &domains, std::string &urls, AhoCorasickPlus *dm_atm, EntriesData *ed)
{
	logger().debug("Loading domains from file %s",domains);
	Poco::FileInputStream df(domains);
	int entry_id=0;
	if(df.good())
	{
		int lineno=0;
		while(!df.eof())
		{
			lineno++;
			std::string str;
			getline(df,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = entry_id;
				std::size_t pos = str.find("*.");
				bool exact_match=true;
				std::string insert=str;
				if(pos != std::string::npos)
				{
					exact_match=false;
					insert=str.substr(pos+2,str.length()-2);
				}
				status = dm_atm->addPattern(insert, patId);
				if (status != AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern '%s' already present in the database from file %s",insert,domains);
						continue;
					} else {
						logger().error("Failed to add '%s' from line %d from file %s",insert,lineno,domains);
					}
				} else {
					entry_data e;
					e.type = E_TYPE_DOMAIN;
					e.match_exactly = exact_match;
					e.lineno = lineno;
					std::pair<EntriesData::Iterator,bool> res=ed->insert(EntriesData::ValueType(entry_id,e));
					if(!res.second)
					{
						logger().fatal("Logic error: found duplicate in the EntriesData. Domain '%s' line %d from file '%s'", str, lineno, domains);
						throw Poco::Exception("Logic error: found duplicate in the EntriesData.");
					}
				}
			}
			entry_id++;
		}
	} else
		throw Poco::OpenFileException(domains);
	df.close();
	logger().debug("Finish loading domains");
	logger().debug("Loading URLS from file %s",urls);
	Poco::FileInputStream uf(urls);
	if(uf.good())
	{
		int lineno=0;
		while(!uf.eof())
		{
			lineno++;
			std::string str;
			getline(uf,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = entry_id;
/*				std::string url = str;
				std::size_t http_pos = url.find("http://");
				if(http_pos == std::string::npos || http_pos > 0)
				{
					url.insert(0,"http://");
				}*/
				status = dm_atm->addPattern(str, patId);
				if (status != AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern '%s' already present in the URL database from file %s",str,urls);
						continue;
					} else {
						logger().error("Failed to add '%s' from line %d from file %s",str,lineno,urls);
					}
				} else {
					entry_data e;
					e.type = E_TYPE_URL;
					e.match_exactly = false;
					e.lineno = lineno;
					std::pair<EntriesData::Iterator,bool> res=ed->insert(EntriesData::ValueType(entry_id,e));
					if(!res.second)
					{
						logger().fatal("Logic error: found duplicate in the EntriesData. URL '%s' line %d from file '%s'", str, lineno, urls);
						throw Poco::Exception("Logic error: found duplicate in the EntriesData.");
					}
				}
			}
			entry_id++;
		}
	} else
		throw Poco::OpenFileException(urls);
	uf.close();
	logger().debug("Finish loading URLS");
}

void extFilter::loadURLs(std::string &fn, AhoCorasickPlus *dm_atm)
{
	logger().debug("Loading URLS from file %s",fn);
	Poco::FileInputStream uf(fn);
	if(uf.good())
	{
		int lineno=1;
		while(!uf.eof())
		{
			std::string str;
			getline(uf,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = lineno;
				std::string url = str;
				std::size_t http_pos = url.find("http://");
				if(http_pos == std::string::npos || http_pos > 0)
				{
					url.insert(0,"http://");
				}
				status = dm_atm->addPattern(url, patId);
				if (status!=AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern '%s' already present in the URL database from file %s",str,fn);
					} else {
						logger().error("Failed to add '%s' from line %d from file %s",str,lineno,fn);
					}
				}
			}
			lineno++;
		}
	} else
		throw Poco::OpenFileException(fn);
	uf.close();
	logger().debug("Finish loading URLS");
}

void extFilter::loadDomains(std::string &fn, AhoCorasickPlus *dm_atm,DomainsMatchType *dm_map)
{
	logger().debug("Loading domains from file %s",fn);
	Poco::FileInputStream df(fn);
	if(df.good())
	{
		int lineno=1;
		while(!df.eof())
		{
			std::string str;
			getline(df,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = lineno;
				std::size_t pos = str.find("*.");
				bool exact_match=true;
				std::string insert=str;
				if(pos != std::string::npos)
				{
					exact_match=false;
					insert=str.substr(pos+2,str.length()-2);
				}
				status = dm_atm->addPattern(insert, patId);
				if (status!=AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern '%s' already present in the database from file %s",insert,fn);
					} else {
						logger().error("Failed to add '%s' from line %d from file %s",insert,lineno,fn);
					}
				} else {
					std::pair<DomainsMatchType::Iterator,bool> res=dm_map->insert(DomainsMatchType::ValueType(lineno,exact_match));
					if(res.second)
					{
//						logger().debug("Inserted domain: '%s' from line %d from file %s",str,lineno,fn);
					} else {
						logger().debug("Updated domain: '%s' from line %d from file %s",str,lineno,fn);
					}
				}
			}
			lineno++;
		}
	} else
		throw Poco::OpenFileException(fn);
	df.close();
	logger().debug("Finish loading domains");
}

void extFilter::loadSSLIP(const std::string &fn, Patricia *patricia)
{
	logger().debug("Loading SSL ips from file %s",fn);
	Poco::FileInputStream hf(fn);
	if(hf.good())
	{
		int lineno=1;
		while(!hf.eof())
		{
			std::string str;
			getline(hf,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				if(!patricia->make_and_lookup(str))
				{
					logger().information("Unable to add IP address %s from line %d to the SSL IPs list", str, lineno);
				}
			}
			lineno++;
		}
	} else
		throw Poco::OpenFileException(fn);
	hf.close();
	logger().debug("Finish loading SSL ips");
}

void extFilter::loadHosts(std::string &fn, IPPortMap *ippm, Patricia *patricia)
{
	logger().debug("Loading ip:port from file %s",fn);
	Poco::FileInputStream hf(fn);
	if(hf.good())
	{
		int lineno=1;
		while(!hf.eof())
		{
			std::string str;
			getline(hf,str);
			if(!str.empty())
			{
				if(str[0] == '#' || str[0] == ';')
					continue;
				std::size_t found=str.find(":");
				std::string ip=str.substr(0, found);
				std::string port;
				unsigned short porti=0;
				if(found != std::string::npos)
				{
					port=str.substr(found+1,str.length());
					logger().debug("IP is %s port %s",ip,port);
					porti=atoi(port.c_str());
				} else {
					logger().debug("IP %s without port", ip);
				}
				Poco::Net::IPAddress ip_addr(ip);
				IPPortMap::iterator it=ippm->find(ip_addr);
				if(it == ippm->end())
				{
					std::set<unsigned short> ports;
					if(porti)
					{
						logger().debug("Adding port %s to ip %s", port, ip);
						ports.insert(porti);
					}
					ippm->insert(std::make_pair(ip_addr,ports));
					logger().debug("Inserted ip: %s from line %d", ip, lineno);
					if(!patricia->make_and_lookup(ip))
					{
						logger().information("Unable to add IP address %s from line %d to the IP:port list", ip, lineno);
					}
				} else {
					logger().debug("Adding port %s from line %d to ip %s", port,lineno,ip);
					it->second.insert(porti);
				}
				
			}
			lineno++;
		}
	} else
		throw Poco::OpenFileException(fn);
	hf.close();
	logger().debug("Finish ip:port");
}

POCO_SERVER_MAIN(extFilter)
