#include <TcpLayer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PcapFileDevice.h>
#include <netinet/in.h>
#include <Poco/Stopwatch.h>
#include <Poco/URI.h>
#include <Poco/Net/IPAddress.h>
#include <sstream>
#include <iomanip>
#include "worker.h"
#include "main.h"
#include "ndpiwrapper.h"
#include "sendertask.h"

//#define DEBUG_TIME

#define COUNT_ONLY

static pcpp::PcapFileWriterDevice* pcapWriter = NULL;

bool WorkerThread::analyzePacket(pcpp::Packet &parsedPacket)
{
#ifdef DEBUG_TIME
	Poco::Stopwatch sw;
#endif
	m_ThreadStats.total_packets++;

	int ip_version=0;
	if(parsedPacket.isPacketOfType(pcpp::IPv4))
		ip_version=4;
	else if (parsedPacket.isPacketOfType(pcpp::IPv6))
		ip_version=6;

	if(!ip_version)
	{
		//_logger.error("Unsupported IP protocol for packet:\n %s", parsedPacket.printToString());
		return false;
	}

	m_ThreadStats.ip_packets++;
	if(ip_version == 4)
		m_ThreadStats.ipv4_packets++;
	else
		m_ThreadStats.ipv6_packets++;

	pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	if(!tcpLayer)
	{
//		_logger.debug("Analyzing only TCP protocol, got packet:\n %s", parsedPacket.printToString());
		return false;
	}


	if((tcpLayer->getDataLen()-tcpLayer->getHeaderLen()) == 0)
	{
//		_logger.debug("Skip packet without data:\n %s", parsedPacket.printToString());
		return false;
	}
	
	m_ThreadStats.analyzed_packets++;
	m_ThreadStats.total_bytes += parsedPacket.getRawPacket()->getRawDataLen();

	int tcp_src_port=ntohs(tcpLayer->getTcpHeader()->portSrc);
	int tcp_dst_port=ntohs(tcpLayer->getTcpHeader()->portDst);

	std::unique_ptr<Poco::Net::IPAddress> src_ip;
	std::unique_ptr<Poco::Net::IPAddress> dst_ip;
	if(ip_version == 4)
	{
		src_ip.reset(new Poco::Net::IPAddress((parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress().toInAddr()),sizeof(in_addr)));
		dst_ip.reset(new Poco::Net::IPAddress((parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress().toInAddr()),sizeof(in_addr)));
	} else {
		src_ip.reset(new Poco::Net::IPAddress((parsedPacket.getLayerOfType<pcpp::IPv6Layer>()->getSrcIpAddress().toIn6Addr()),sizeof(in6_addr)));
		dst_ip.reset(new Poco::Net::IPAddress((parsedPacket.getLayerOfType<pcpp::IPv6Layer>()->getDstIpAddress().toIn6Addr()),sizeof(in6_addr)));
	}

	if(m_WorkerConfig.ipportMap && m_WorkerConfig.ipportMapLock.tryLock())
	{
		IPPortMap::iterator it_ip=m_WorkerConfig.ipportMap->find(*dst_ip.get());
		if(it_ip != m_WorkerConfig.ipportMap->end())
		{
			unsigned short port=tcp_dst_port;
			if (it_ip->second.size() == 0 || it_ip->second.find(port) != it_ip->second.end())
			{
				m_ThreadStats.matched_ip_port++;
				_logger.debug("Found record in ip:port list for the client %s:%d and server %s:%d",src_ip->toString(),dst_ip->toString(),tcp_src_port,tcp_dst_port);
				return true;
			}
		}
		m_WorkerConfig.ipportMapLock.unlock();
	}

	ndpi_protocol protocol;
#ifdef DEBUG_TIME
	sw.reset();
	sw.start();
#endif
	nDPIWrapper nw;
	struct ndpi_flow_struct *flow=nw.get_flow();
	uint32_t current_tickt = 0;
	protocol = ndpi_detection_process_packet(m_WorkerConfig.ndpi_struct, flow, ip_version == 4 ? (parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getData()) : (parsedPacket.getLayerOfType<pcpp::IPv6Layer>()->getData()),ip_version == 4 ? (parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDataLen()) : (parsedPacket.getLayerOfType<pcpp::IPv6Layer>()->getDataLen()), current_tickt, nw.get_src(), nw.get_dst());

	if(protocol.protocol == NDPI_PROTOCOL_UNKNOWN)
	{
//		_logger.debug("Guessing protocol...");
		protocol = ndpi_guess_undetected_protocol(m_WorkerConfig.ndpi_struct,
		   IPPROTO_TCP, // TCP
		   0,//ip
		   tcp_src_port, // sport
		   0,
		   tcp_dst_port); // dport
	}
#ifdef DEBUG_TIME
	sw.stop();
	_logger.debug("nDPI protocol detection occupied %ld us",sw.elapsed());
#endif
//	_logger.debug("Protocol is %hu/%hu src port: %d dst port: %d",protocol.master_protocol,protocol.protocol,tcp_src_port,tcp_dst_port);


	if(protocol.master_protocol == NDPI_PROTOCOL_SSL || protocol.protocol == NDPI_PROTOCOL_SSL || protocol.protocol == NDPI_PROTOCOL_TOR)
	{
		if(m_WorkerConfig.atmSSLDomains && flow->l4.tcp.ssl_seen_client_cert == 1)
		{
			std::string ssl_client;
			if(flow->protos.ssl.client_certificate[0] != '\0')
			{
				ssl_client=flow->protos.ssl.client_certificate;
//				_logger.debug("SSL client is: %s",ssl_client);
			}
			if(!ssl_client.empty())
			{
				// если не можем выставить lock, то нет смысла продолжать...
				if(!m_WorkerConfig.atmSSLDomainsLock.tryLock())
					return false;
#ifdef DEBUG_TIME
				sw.reset();
				sw.start();
#endif
				if(m_WorkerConfig.lower_host)
					std::transform(ssl_client.begin(), ssl_client.end(), ssl_client.begin(), ::tolower);
				AhoCorasickPlus::Match match;
				std::size_t host_len=ssl_client.length();
				bool found=false;
				{
					m_WorkerConfig.atmSSLDomains->search(ssl_client,false);
					while(m_WorkerConfig.atmSSLDomains->findNext(match) && !found)
					{
						if(match.pattern.length != host_len)
						{
							DomainsMatchType::Iterator it=m_WorkerConfig.SSLdomainsMatchType->find(match.id);
							bool exact_match=false;
							if(it != m_WorkerConfig.SSLdomainsMatchType->end())
								exact_match = it->second;
							if(exact_match)
								continue;
							if(ssl_client[host_len-match.pattern.length-1] != '.')
								continue;
						}
						found=true;
					}
				}
				m_WorkerConfig.atmSSLDomainsLock.unlock();
#ifdef DEBUG_TIME
				sw.stop();
				_logger.debug("SSL Host seek occupied %ld us, host: %s",sw.elapsed(),ssl_client);
#endif
				if(found)
				{
					m_ThreadStats.matched_ssl++;
					_logger.debug("SSL host %s present in SSL domain (file line %u) list from ip %s:%d to ip %s:%d", ssl_client, match.id, src_ip->toString(),tcp_src_port,dst_ip->toString(),tcp_dst_port);
					if (pcapWriter)
						pcapWriter->writePacket(*(parsedPacket.getRawPacket()));

					std::string empty_str;
					SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(), dst_ip.get(), tcpLayer->getTcpHeader()->ackNumber, tcpLayer->getTcpHeader()->sequenceNumber, (tcpLayer->getTcpHeader()->pshFlag ? 1 : 0 ),empty_str,true));
					m_ThreadStats.sended_rst++;
					return true;
				} else {
					return false;
				}
			} else {
				if(m_WorkerConfig.block_undetected_ssl)
				{
					if(m_WorkerConfig.sslIPsLock.tryLock())
					{
						if(m_WorkerConfig.sslIPs->try_search_exact_ip(*dst_ip.get()))
						{
							m_WorkerConfig.sslIPsLock.unlock();
							m_ThreadStats.matched_ssl_ip++;
							_logger.debug("Blocking/Marking SSL client hello packet from %s:%d to %s:%d", src_ip->toString(),tcp_src_port,dst_ip->toString(),tcp_dst_port);
							m_ThreadStats.sended_rst++;
							std::string empty_str;
							SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(), dst_ip.get(), tcpLayer->getTcpHeader()->ackNumber, tcpLayer->getTcpHeader()->sequenceNumber, (tcpLayer->getTcpHeader()->pshFlag ? 1 : 0 ),empty_str,true));
							return true;
						}
						m_WorkerConfig.sslIPsLock.unlock();
						return false;
					}
				}
//				_logger.debug("No ssl client certificate found! Accept packet from %s:%d to %s:%d.",src_ip->toString(),tcp_src_port,dst_ip->toString(),tcp_dst_port);
				return false;
			}
		}
		return false;
	}


	if(protocol.master_protocol != NDPI_PROTOCOL_HTTP && protocol.protocol != NDPI_PROTOCOL_HTTP && protocol.protocol != NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK)
	{
		return false;
	}

	std::string host((char *)&flow->host_server_name[0]);
	if((flow->http.method == HTTP_METHOD_GET || flow->http.method == HTTP_METHOD_POST || flow->http.method == HTTP_METHOD_HEAD) && !host.empty())
	{
		int dot_del=0;
//		_logger.debug("Analyzing host %s", host);
		if(m_WorkerConfig.atmDomains && !host.empty())
		{
			if(m_WorkerConfig.atmDomainsLock.tryLock())
			{
				if(host[host.length()-1] == '.')
				{
					dot_del=host.length()-1;
					host.erase(dot_del,1);
				}
				if(m_WorkerConfig.lower_host)
					std::transform(host.begin(), host.end(), host.begin(), ::tolower);
#ifdef DEBUG_TIME
				sw.reset();
				sw.start();
#endif
				AhoCorasickPlus::Match match;
				bool found=false;
				{
					m_WorkerConfig.atmDomains->search(host,false);
					std::size_t host_len=host.length();
					while(m_WorkerConfig.atmDomains->findNext(match) && !found)
					{
						if(match.pattern.length != host_len)
						{
							DomainsMatchType::Iterator it=m_WorkerConfig.domainsMatchType->find(match.id);
							bool exact_match=false;
							if(it != m_WorkerConfig.domainsMatchType->end())
								exact_match = it->second;
							if(exact_match)
								continue;
							if(host[host_len-match.pattern.length-1] != '.')
								continue;
						}
						found=true;
					}
				}
				m_WorkerConfig.atmDomainsLock.unlock();
#ifdef DEBUG_TIME
				sw.stop();
				_logger.debug("Host %s seek occupied %ld us", host, sw.elapsed());
#endif
				if(found)
				{
					m_ThreadStats.matched_domains++;
					_logger.debug("Host %s present in domain (file line %u) list from ip %s to ip %s", host, match.id, src_ip->toString(), dst_ip->toString());
					if (pcapWriter)
						pcapWriter->writePacket(*(parsedPacket.getRawPacket()));
					
					if(m_WorkerConfig.http_redirect)
					{
						std::string add_param;
						switch (m_WorkerConfig.add_p_type)
						{
							case A_TYPE_ID: add_param="id="+std::to_string(match.id);
								break;
							case A_TYPE_URL: add_param="url="+host;
								break;
							default: break;
						}
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port, src_ip.get(), dst_ip.get(), tcpLayer->getTcpHeader()->ackNumber, tcpLayer->getTcpHeader()->sequenceNumber, (tcpLayer->getTcpHeader()->pshFlag ? 1 : 0 ), add_param));
						m_ThreadStats.redirected_domains++;
					} else {
						std::string empty_str;
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(), dst_ip.get(), tcpLayer->getTcpHeader()->ackNumber, tcpLayer->getTcpHeader()->sequenceNumber, (tcpLayer->getTcpHeader()->pshFlag ? 1 : 0 ),empty_str,true));
						m_ThreadStats.sended_rst++;
					}
					return true;
				}
			}
		}
		
		std::string uri_o(flow->http.url ? flow->http.url : "");
		if(m_WorkerConfig.atm && !uri_o.empty())
		{
//			_logger.debug("test url %s", uri_o);
			if(m_WorkerConfig.atmLock.tryLock())
			{
				std::string uri;
				if(dot_del)
					uri_o.erase(dot_del+7,1);
				try
				{
					Poco::URI uri_p(uri_o);
					uri_p.normalize();
					uri.assign(uri_p.toString());
/*					if(_config.url_decode)
					{
#ifdef __USE_POCO_URI_DECODE
						Poco::URI::decode(uri_p.toString(),uri);
#else
						uri=url_decode(uri);
#endif
					}*/
				} catch (Poco::SyntaxException &ex)
				{
					_logger.debug("An SyntaxException occured: '%s' on URI: '%s'", ex.displayText(), uri_o);
					uri.assign(uri_o);
				}
				AhoCorasickPlus::Match match;
				bool found=false;
				m_WorkerConfig.atm->search(uri,false);
				while(m_WorkerConfig.atm->findNext(match) && !found)
				{
					if(m_WorkerConfig.match_url_exactly && uri.length() != match.pattern.length)
						continue;
					found=true;
				}
				m_WorkerConfig.atmLock.unlock();
				if(found)
				{
					m_ThreadStats.matched_urls++;
					_logger.debug("URL %s present in url (file pos %u) list from ip %s to ip %s", uri, match.id, src_ip->toString(), dst_ip->toString());
					if (pcapWriter)
						pcapWriter->writePacket(*(parsedPacket.getRawPacket()));
					if(m_WorkerConfig.http_redirect)
					{
						std::string add_param;
						switch (m_WorkerConfig.add_p_type)
						{
							case A_TYPE_ID: add_param="id="+std::to_string(match.id);
								break;
							case A_TYPE_URL: add_param="url="+host;
								break;
							default: break;
						}
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port, src_ip.get(), dst_ip.get(), tcpLayer->getTcpHeader()->ackNumber, tcpLayer->getTcpHeader()->sequenceNumber, (tcpLayer->getTcpHeader()->pshFlag ? 1 : 0 ), add_param));
						m_ThreadStats.redirected_urls++;
					} else {
						std::string empty_str;
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(), dst_ip.get(), tcpLayer->getTcpHeader()->ackNumber, tcpLayer->getTcpHeader()->sequenceNumber, (tcpLayer->getTcpHeader()->pshFlag ? 1 : 0 ),empty_str,true));
						m_ThreadStats.sended_rst++;
					}
					return true;
				}
			}
		}
	}
	return false;
}


bool WorkerThread::run(uint32_t coreId)
{
	m_CoreId = coreId;
	m_Stop = false;

	// if no DPDK devices were assigned to this worker/core don't enter the main loop and exit
	if (m_WorkerConfig.InDataCfg.size() == 0)
	{
		return true;
	}

	if (!m_WorkerConfig.PathToWritePackets.empty())
	{
		pcapWriter = new pcpp::PcapFileWriterDevice(m_WorkerConfig.PathToWritePackets.c_str());
		if (!pcapWriter->open())
		{
			_logger.error("Couldn't open pcap writer device");
		}
	}

	// main loop, runs until be told to stop
	while (!m_Stop)
	{
		// go over all DPDK devices configured for this worker/core
		for (InputDataConfig::iterator iter = m_WorkerConfig.InDataCfg.begin(); iter != m_WorkerConfig.InDataCfg.end(); iter++)
		{
			// for each DPDK device go over all RX queues configured for this worker/core
			for (std::vector<int>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++)
			{
				pcpp::DpdkDevice* dev = iter->first;
				pcpp::MBufRawPacket* packetArr = NULL;
				int packetArrLen = 0;
				// receive packets from network on the specified DPDK device and RX queue
				if (!dev->receivePackets(&packetArr, packetArrLen, *iter2))
				{
					_logger.error("Couldn't receive packet from DpdkDevice #%d, RX queue #%d", dev->getDeviceId(), *iter2);
				}

				for (int i = 0; i < packetArrLen; i++)
				{
					pcpp::Packet parsedPacket(&packetArr[i]);
					analyzePacket(parsedPacket);
				}
				delete [] packetArr;
			}
		}
	}
	if (pcapWriter != NULL)
		delete pcapWriter;
	_logger.debug("Worker thread on core %u terminated", coreId);
	return true;
}
