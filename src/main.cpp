#include "main.h"
#include "worker.h"
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/NumberParser.h>
#include <Poco/FileStream.h>
#include <Poco/TaskManager.h>
#include <Poco/StringTokenizer.h>
#include <DpdkDevice.h>
#include <DpdkDeviceList.h>
#include <DnsLayer.h>
#include <SSLLayer.h>

#include <iostream>
#include <vector>

#include "AhoCorasickPlus.h"
#include "patr.h"
#include "qdpi.h"
#include "sendertask.h"
#include "statistictask.h"
#include "reloadtask.h"

struct ndpi_detection_module_struct* extFilter::my_ndpi_struct = NULL;
u_int32_t extFilter::ndpi_size_flow_struct = 0;
u_int32_t extFilter::ndpi_size_id_struct = 0;
u_int32_t extFilter::current_ndpi_memory = 0;
u_int32_t extFilter::max_ndpi_memory = 0;

extFilter::extFilter(): _helpRequested(false), _listDPDKPorts(false), _nbRxQueues(1)
{
	_coreMaskToUse = pcpp::getCoreMaskForAllMachineCores();
//	Poco::ErrorHandler::set(&_errorHandler);
}


extFilter::~extFilter()
{
}

/**
 * Prepare the configuration for each core. Configuration includes: which DpdkDevices and which RX queues to receive packets from, where to send the matched
 * packets, etc.
 */
void prepareCoreConfiguration(std::vector<pcpp::DpdkDevice*>& dpdkDevicesToUse, std::vector<pcpp::SystemCore>& coresToUse, WorkerConfig workerConfigArr[], int workerConfigArrLen, int nbRxQueues)
{
	// create a list of pairs of DpdkDevice and RX queues for all RX queues in all requested devices
	int totalNumOfRxQueues = 0;
	std::vector<std::pair<pcpp::DpdkDevice*, int> > deviceAndRxQVec;
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
	{
		if(nbRxQueues > (*iter)->getTotalNumOfRxQueues())
			nbRxQueues=(*iter)->getTotalNumOfRxQueues();
		for (int rxQueueIndex = 0; rxQueueIndex < nbRxQueues; rxQueueIndex++)
		{
			std::pair<pcpp::DpdkDevice*, int> curPair(*iter, rxQueueIndex);
			deviceAndRxQVec.push_back(curPair);
		}
		totalNumOfRxQueues += nbRxQueues;
	}

	// calculate how many RX queues each core will read packets from. We divide the total number of RX queues with total number of core
	int numOfRxQueuesPerCore = totalNumOfRxQueues / coresToUse.size();
	int rxQueuesRemainder = totalNumOfRxQueues % coresToUse.size();

	// prepare the configuration for every core: divide the devices and RX queue for each device with the various cores
	int i = 0;
	std::vector<std::pair<pcpp::DpdkDevice*, int> >::iterator pairVecIter = deviceAndRxQVec.begin();
	for (std::vector<pcpp::SystemCore>::iterator iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
	{
		printf("Using core %d\n", iter->Id);
		workerConfigArr[i].CoreId = iter->Id;

		for (int rxQIndex = 0; rxQIndex < numOfRxQueuesPerCore; rxQIndex++)
		{
			if (pairVecIter == deviceAndRxQVec.end())
				break;
			workerConfigArr[i].InDataCfg[pairVecIter->first].push_back(pairVecIter->second);
			pairVecIter++;
		}
		if (rxQueuesRemainder > 0 && (pairVecIter != deviceAndRxQVec.end()))
		{
			workerConfigArr[i].InDataCfg[pairVecIter->first].push_back(pairVecIter->second);
			pairVecIter++;
			rxQueuesRemainder--;
		}

		// print configuration for core
		printf("   Core configuration:\n");
		for (InputDataConfig::iterator iter = workerConfigArr[i].InDataCfg.begin(); iter != workerConfigArr[i].InDataCfg.end(); iter++)
		{
			printf("      DPDK device#%d: ", iter->first->getDeviceId());
			for (std::vector<int>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++)
			{
				printf("RX-Queue#%d;  ", *iter2);

			}
			printf("\n");
		}
		if (workerConfigArr[i].InDataCfg.size() == 0)
		{
			printf("      None\n");
		}
		i++;
	}

}

void extFilter::initialize(Application& self)
{
	loadConfiguration();
	ServerApplication::initialize(self);

	// initialize DPDK
	if (!pcpp::DpdkDeviceList::initDpdk(_coreMaskToUse, _BufPoolSize))
	{
		logger().fatal("Couldn't initialize DPDK!");
		throw Poco::Exception("Couldn't initialize DPDK");
	}


	_lower_host=config().getBool("lower_host", false);
	_match_url_exactly=config().getBool("match_url_exactly", false);
	_block_undetected_ssl=config().getBool("block_undetected_ssl", false);
	_http_redirect=config().getBool("http_redirect", true);
	_statistic_interval=config().getInt("statistic_interval", 0);
	_nbRxQueues=config().getInt("rx_queues", 1);
	_BufPoolSize=config().getInt("mbuf_pool_size", DEFAULT_MBUF_POOL_SIZE);
	_coreMaskToUse=config().getInt("core_mask", pcpp::getCoreMaskForAllMachineCores());

	_urlsFile=config().getString("urllist","");
	_domainsFile=config().getString("domainlist","");
	_sslIpsFile=config().getString("sslips","");
	_sslFile=config().getString("ssllist","");
	_hostsFile=config().getString("hostlist","");

	std::string http_code=config().getString("http_code","");
	if(!http_code.empty())
	{
		http_code.erase(std::remove(http_code.begin(), http_code.end(), '"'), http_code.end());
		_sender_params.code=http_code;
		logger().debug("HTTP code set to %s", http_code);
	}
	_sender_params.redirect_url=config().getString("redirect_url","");
	_sender_params.send_rst_to_server=config().getBool("rst_to_server",false);

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

	if(_dpdkPortVec.empty())
	{
		logger().fatal("DPDK ports not specified!");
		throw Poco::Exception("DPDK ports not specified!");
	}
	// todo... ????
	
	my_ndpi_struct = init_ndpi();

	if (my_ndpi_struct == NULL)
	{
		logger().fatal("Can't initialize nDPI!");
		throw Poco::Exception("Can't initialize nDPI!");
	}

	std::string _protocolsFile=config().getString("protocols","");
	if(!_protocolsFile.empty())
		ndpi_load_protocols_file(my_ndpi_struct, (char *)_protocolsFile.c_str());

	// Load sizes of main parsing structures
	ndpi_size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
	ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

	// removing DPDK master core from core mask because DPDK worker threads cannot run on master core
	_coreMaskToUse = _coreMaskToUse & ~(pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);
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
		Poco::Util::Option("core-mask","c","Core mask of cores to use. For example: use 7 (binary 0111) to use cores 0,1,2. Default is using all cores except management core.")
			.required(false)
			.repeatable(false)
			.argument("CORE_MASK"));
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
	if(name == "core-mask")
	{
		_coreMaskToUse = Poco::NumberParser::parse(value);
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
/*	if(name == "threads")
	{
		_cmd_threadsNum = Poco::NumberParser::parse(value);
	}*/
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
	pcpp::CoreMask coreMaskToUse = pcpp::getCoreMaskForAllMachineCores();
	// initialize DPDK
	if (!pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, DEFAULT_MBUF_POOL_SIZE))
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
		std::map<uint16_t, bool> *ptr=(std::map<uint16_t, bool> *)pcpp::DnsLayer::getDNSPortMap();
		ptr->clear();

		ptr=(std::map<uint16_t, bool> *)pcpp::SSLLayer::getSSLPortMap();
		ptr->clear();

		ptr=(std::map<uint16_t, bool> *)pcpp::HttpMessage::getHTTPPortMap();
		ptr->clear();


		struct sigaction handler;
		handler.sa_handler = handleSignal;
		handler.sa_flags   = 0;
		sigemptyset(&handler.sa_mask);
		sigaction(SIGHUP, &handler, NULL);

		// extract core vector from core mask
		std::vector<pcpp::SystemCore> coresToUse;
		pcpp::createCoreVectorFromCoreMask(_coreMaskToUse, coresToUse);
    
		// collect the list of DPDK devices
		std::vector<pcpp::DpdkDevice*> dpdkDevicesToUse;

		for (std::vector<int>::iterator iter = _dpdkPortVec.begin(); iter != _dpdkPortVec.end(); iter++)
		{
			pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(*iter);
			if (dev == NULL)
			{
				logger().fatal("DPDK device for port %d doesn't exist", *iter); // XXX check it!!!
				return Poco::Util::Application::EXIT_OK;
			}
			std::cout << "pushing device with port " << *iter << std::endl;
			dpdkDevicesToUse.push_back(dev);
		}

		// go over all devices and open them
		for (std::vector<pcpp::DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
		{
			std::cout << "total num of rx queue: " << (*iter)->getTotalNumOfRxQueues() << " total num of tx queues: " << (*iter)->getTotalNumOfTxQueues() << std::endl;
			if (!(*iter)->openMultiQueues(_nbRxQueues, 1))
			{
				logger().fatal("Couldn't open DPDK device #%d, PMD '%s'", (*iter)->getDeviceId(), (*iter)->getPMDName());
				return Poco::Util::Application::EXIT_OK;
			}
		}


		WorkerConfig workerConfigArr[coresToUse.size()];
		prepareCoreConfiguration(dpdkDevicesToUse, coresToUse, workerConfigArr, coresToUse.size(),_nbRxQueues);

		// create worker thread for every core
		std::vector<pcpp::DpdkWorkerThread*> workerThreadVec;
		int i = 0;
		for (std::vector<pcpp::SystemCore>::iterator iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
		{
			if(!_urlsFile.empty())
			{
				workerConfigArr[i].atm = new AhoCorasickPlus();
				loadURLs(_urlsFile, workerConfigArr[i].atm);
				workerConfigArr[i].atm->finalize();
			}
			if(!_domainsFile.empty())
			{
				workerConfigArr[i].atmDomains = new AhoCorasickPlus();
				workerConfigArr[i].domainsMatchType = new DomainsMatchType;
				loadDomains(_domainsFile,workerConfigArr[i].atmDomains, workerConfigArr[i].domainsMatchType);
				workerConfigArr[i].atmDomains->finalize();
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
				loadHosts(_hostsFile,workerConfigArr[i].ipportMap);
			}
//			workerConfigArr[i].PathToWritePackets = "thread"+std::to_string(i)+".pcap";
			workerConfigArr[i].match_url_exactly = _match_url_exactly;
			workerConfigArr[i].lower_host = _lower_host;
			workerConfigArr[i].http_redirect = _http_redirect;
			workerConfigArr[i].add_p_type = _add_p_type;
			std::string workerName("WorkerThread " + std::to_string(i));
			WorkerThread* newWorker = new WorkerThread(workerName, workerConfigArr[i]);
			workerThreadVec.push_back(newWorker);
			i++;
		}


		Poco::TaskManager tm;
		tm.start(new SenderTask(_sender_params));

		logger().debug("Starting worker threads...");
		// start all worker threads
		if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(_coreMaskToUse, workerThreadVec))
		{
			logger().fatal("Couldn't start worker threads");
			return Poco::Util::Application::EXIT_OK;
		}
		tm.start(new StatisticTask(_statistic_interval, workerThreadVec));
		tm.start(new ReloadTask(this, workerThreadVec));
		waitForTerminationRequest();
		pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
		tm.cancelAll();
		SenderTask::queue.wakeUpAll();
		tm.joinAll();
		// stop worker threads

		for (std::vector<pcpp::DpdkWorkerThread*>::iterator iter = workerThreadVec.begin(); iter != workerThreadVec.end(); iter++)
		{
			WorkerThread* thread = (WorkerThread*)(*iter);
			delete thread;
		}

	}
	return Poco::Util::Application::EXIT_OK;
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

void extFilter::loadHosts(std::string &fn,IPPortMap *ippm)
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
