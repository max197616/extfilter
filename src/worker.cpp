#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <netinet/in.h>
#include <Poco/Stopwatch.h>
#include <Poco/URI.h>
#include <Poco/Net/IPAddress.h>
#include <sstream>
#include <iomanip>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_cycles.h>
#include <rte_ip_frag.h>
#include <rte_ethdev.h>
#include <memory>

#include "worker.h"
#include "main.h"
#include "sendertask.h"
#include "flow.h"
#include "acl.h"
#include <rte_hash.h>
#include "notification.h"
#include "dpi.h"

#define tcphdr(x)	((struct tcphdr *)(x))

void host_cb(dpi_http_message_informations_t* http_informations, const u_char* app_data, u_int32_t data_length, dpi_pkt_infos_t* pkt, void** flow_specific_user_data, void* user_data)
{
	if(*flow_specific_user_data != NULL && data_length > 0)
	{
		struct dpi_flow_info *u = (struct dpi_flow_info *)*flow_specific_user_data;
		u->host = (char *)calloc(1, data_length+1);
		memcpy(u->host, app_data, data_length);
		u->host_size = data_length;
	}
}

void url_cb(const unsigned char* url, u_int32_t url_length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	if(*flow_specific_user_data == NULL && url_length > 0)
	{
		struct dpi_flow_info *u= (struct dpi_flow_info *)calloc(1, sizeof(dpi_flow_info));
		u->url = (char *)calloc(1, url_length+1);
		memcpy(u->url, url, url_length);
		u->url_size = url_length;
		*flow_specific_user_data = u;
	}
}

void header_cb(dpi_http_message_informations_t* m, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	if(user_data != NULL && *flow_specific_user_data != NULL && (m->method_or_code == DPI_HTTP_GET || m->method_or_code == DPI_HTTP_PUT || m->method_or_code == DPI_HTTP_HEAD))
	{
		struct dpi_flow_info *u = (struct dpi_flow_info *)*flow_specific_user_data;
		if(u->url != NULL && u->host != NULL)
		{
			std::string *uri = (std::string *)user_data;
			uri->assign("http://");
			uri->append(u->host, u->host_size);
			uri->append(u->url, u->url_size);
		}
	}
}

void ssl_cert_cb(char *certificate, int size, void *user_data)
{
	std::string *cert=(std::string *)user_data;
	cert->assign(certificate, size > 255 ? 255 : size);
}

WorkerThread::WorkerThread(const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, int socketid) :
		m_WorkerConfig(workerConfig), m_Stop(true),
		_logger(Poco::Logger::get(name)),
		dpi_state(state),
		_name(name)
{
	uri.reserve(URI_RESERVATION_SIZE);
	certificate.reserve(CERT_RESERVATION_SIZE);
	static dpi_http_header_field_callback* single_cb[1]={&host_cb};
	static const char* headers[1]={"host"};

	static dpi_http_callbacks_t callback={.header_url_callback = url_cb, .header_names = headers, .num_header_types = 1, .header_types_callbacks = single_cb, .header_completion_callback = header_cb, .http_body_callback = 0};
	dpi_http_activate_callbacks(dpi_state, &callback, &uri);
	static dpi_ssl_callbacks_t ssl_callback = {.certificate_callback = ssl_cert_cb };
	dpi_ssl_activate_callbacks(state, &ssl_callback, &certificate);
}

WorkerThread::~WorkerThread()
{
	dpi_terminate(dpi_state);
}

const ThreadStats& WorkerThread::getStats()
{
	struct flow_table_stat stat;
	get_flow_stat_v4(dpi_state->db4, &stat);
	m_ThreadStats.ndpi_flows_count = stat.active_flows;
	m_ThreadStats.ndpi_ipv4_flows_count = stat.active_flows;
	m_ThreadStats.max_ipv4_flows = stat.max_active_flows;
	get_flow_stat_v6(dpi_state->db6, &stat);
	m_ThreadStats.ndpi_ipv6_flows_count = stat.active_flows;
	m_ThreadStats.max_ipv6_flows = stat.max_active_flows;
	m_ThreadStats.ndpi_flows_count += stat.active_flows;
	return m_ThreadStats;
}


bool WorkerThread::analyzePacket(struct rte_mbuf* m, uint64_t timestamp)
{
	uint8_t *l3;
	uint16_t l4_packet_len;
	uint16_t payload_len;
	struct ipv4_hdr *ipv4_header=nullptr;
	struct ipv6_hdr *ipv6_header=nullptr;
	int size=rte_pktmbuf_pkt_len(m);

	int ip_version=0;
	uint32_t ip_len;
	int iphlen=0;

//	uint32_t tcp_or_udp = m->packet_type & (RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP);
	uint32_t l3_ptypes = m->packet_type & RTE_PTYPE_L3_MASK;

	if(!m->userdata)
	{
		_logger.error("Userdata is null");
		return false;
	}


	struct packet_info *pkt_info = (struct packet_info *) m->userdata;
	l3 = pkt_info->l3;

	// определяем версию протокола
	if (l3_ptypes == RTE_PTYPE_L3_IPV4)
	{
		ip_version = 4;
		m_ThreadStats.ipv4_packets++;
		ipv4_header = (struct ipv4_hdr *)l3;
		ip_len=rte_be_to_cpu_16(ipv4_header->total_length);
		iphlen = (ipv4_header->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER; // ipv4
		l4_packet_len = ip_len - iphlen;
		if(ip_len < 20)
		{
			m_ThreadStats.ipv4_short_packets++;
			return false;
		}
		if(rte_ipv4_frag_pkt_is_fragmented(ipv4_header))
		{
			m_ThreadStats.ipv4_fragments++;
//			return false;
		}
	} else if (l3_ptypes == RTE_PTYPE_L3_IPV6)
	{
		ip_version=6;
		m_ThreadStats.ipv6_packets++;
		ipv6_header = (struct ipv6_hdr *)l3;
		ip_len=rte_be_to_cpu_16(ipv6_header->payload_len) + sizeof(ipv6_hdr);
		iphlen = sizeof(struct ipv6_hdr);
		l4_packet_len = rte_be_to_cpu_16(ipv6_header->payload_len);
		if(rte_ipv6_frag_get_ipv6_fragment_header(ipv6_header) != NULL)
		{
			m_ThreadStats.ipv6_fragments++;
//			return false;
		}
	} else {
		//_logger.debug("Unsupported ethernet type %x", (int) ether_type);
		return false;
	}

	m_ThreadStats.ip_packets++;

	uint8_t ip_protocol=(ip_version == 4 ? ipv4_header->next_proto_id : ipv6_header->proto);

	if(ip_protocol != IPPROTO_TCP)
	{
		//_logger.debug("Not TCP protocol");
		return false;
	}

	m_ThreadStats.total_bytes += size;

	uint8_t *pkt_data_ptr = NULL;
	struct tcphdr* tcph;

	pkt_data_ptr = l3 + (ip_version == 4 ? sizeof(struct ipv4_hdr) : sizeof(struct ipv6_hdr));

	tcph = (struct tcphdr *) pkt_data_ptr;

	// длина tcp заголовка
	int tcphlen = tcphdr(l3+iphlen)->doff*4;

	// общая длина всех заголовков
	uint32_t hlen = iphlen + tcphlen;

	payload_len = l4_packet_len - tcphlen;
	uint8_t *payload = pkt_data_ptr + tcphlen;

	m_ThreadStats.analyzed_packets++;

	int tcp_src_port=rte_be_to_cpu_16(tcph->source);
	int tcp_dst_port=rte_be_to_cpu_16(tcph->dest);

	uint32_t acl_action = pkt_info->acl_res & ACL_POLICY_MASK;
	if(acl_action == ACL::ACL_DROP)
	{
		m_ThreadStats.matched_ip_port++;
		SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
		m_ThreadStats.sended_rst++;
		return true;
	}


	dpi_identification_result_t r;
	uri.clear();
	certificate.clear();
//	r = dpi_stateful_identify_application_protocol_new(dpi_state, l3, ip_len, timestamp, m->hash.usr);
	r = dpi_stateful_identify_application_protocol_new(dpi_state, l3, ip_len, timestamp, m->hash.rss);

	if(r.protocol.l7prot == DPI_PROTOCOL_TCP_SSL)
	{
		if(m_WorkerConfig.atmSSLDomains)
		{
			if(!certificate.empty())
			{
				// если не можем выставить lock, то нет смысла продолжать...
				if(!m_WorkerConfig.atmSSLDomainsLock.tryLock())
					return false;
				if(m_WorkerConfig.lower_host)
					std::transform(certificate.begin(), certificate.end(), certificate.begin(), ::tolower);
				AhoCorasickPlus::Match match;
				std::size_t host_len=certificate.length();
				bool found=false;
				{
					m_WorkerConfig.atmSSLDomains->search(certificate,false);
					while(m_WorkerConfig.atmSSLDomains->findNext(match) && !found)
					{
						if(match.pattern.ptext.length != host_len)
						{
							DomainsMatchType::Iterator it=m_WorkerConfig.SSLdomainsMatchType->find(match.id);
							bool exact_match=false;
							if(it != m_WorkerConfig.SSLdomainsMatchType->end())
								exact_match = it->second;
							if(exact_match)
								continue;
							if(certificate[host_len-match.pattern.ptext.length-1] != '.')
								continue;
						}
						found=true;
					}
				}
				m_WorkerConfig.atmSSLDomainsLock.unlock();
#ifdef DEBUG_TIME
				sw.stop();
				_logger.debug("SSL Host seek occupied %ld us, host: %s",sw.elapsed(),certificate);
#endif
				if(found)
				{
					m_ThreadStats.matched_ssl++;
#ifdef _DEBUG_WORKER
					_logger.debug("SSL host %s present in SSL domain (file line %u) list from ip %s:%d to ip %s:%d", certificate, match.id, src_ip->toString(),tcp_src_port,dst_ip->toString(),tcp_dst_port);
#endif
					SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
					m_ThreadStats.sended_rst++;
//					flow_info->block=true;
					return true;
				} else {
					return false;
				}
			} else if(m_WorkerConfig.block_undetected_ssl)
			{
				if(acl_action == ACL::ACL_SSL)
				{
					m_ThreadStats.matched_ssl_ip++;
#ifdef _DEBUG_WORKER
					_logger.debug("Blocking/Marking SSL client hello packet from %s:%d to %s:%d", src_ip->toString(),tcp_src_port,dst_ip->toString(),tcp_dst_port);
#endif
					m_ThreadStats.sended_rst++;
					SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
//					flow_info->block=true;
					return true;
				}
			}
		}
		return false;
	}


	if(r.protocol.l7prot == DPI_PROTOCOL_TCP_HTTP && !uri.empty())
	{
		if(m_WorkerConfig.atm)
		{
			if(m_WorkerConfig.atmLock.tryLock())
			{
				std::string orig_uri(uri);
				if(m_WorkerConfig.url_normalization)
				{
					try
					{
						Poco::URI uri_p(uri);
						uri_p.normalize();
						uri.assign(uri_p.toString());
					} catch (Poco::SyntaxException &ex)
					{
						_logger.debug("An SyntaxException occured: '%s' on URI: '%s'", ex.displayText(), uri);
					}
				}
				if(m_WorkerConfig.remove_dot || (!m_WorkerConfig.url_normalization && m_WorkerConfig.lower_host))
				{
					// remove dot after domain...
					size_t f_slash_pos=uri.find('/',10);
					if(!m_WorkerConfig.url_normalization && m_WorkerConfig.lower_host && f_slash_pos != std::string::npos)
					{
						std::transform(uri.begin()+7, uri.begin()+f_slash_pos, uri.begin()+7, ::tolower);
					}
					if(m_WorkerConfig.remove_dot && f_slash_pos != std::string::npos)
					{
						if(uri[f_slash_pos-1] == '.')
							uri.erase(f_slash_pos-1,1);
					}
				}
				AhoCorasickPlus::Match match;
				bool found=false;
				size_t uri_length=uri.length() - 7;
				char const *uri_ptr=uri.c_str() + 7;
				m_WorkerConfig.atm->search((char *)uri_ptr, uri_length, false); // skip http://
				EntriesData::Iterator it;
				while(m_WorkerConfig.atm->findNext(match) && !found)
				{
					it=m_WorkerConfig.entriesData->find(match.id);
					if(match.pattern.ptext.length != uri_length)
					{
						int r=match.position-match.pattern.ptext.length;
						if(it->second.type == E_TYPE_DOMAIN)
						{
							if(r > 0)
							{
								if(it->second.match_exactly)
									continue;
								if(*(uri_ptr+r-1) != '.')
									continue;
							}
						} else if(it->second.type == E_TYPE_URL)
						{
							if(m_WorkerConfig.match_url_exactly)
								continue;
							if(r > 0)
							{
								if(*(uri_ptr+r-1) != '.')
									continue;
							}
						}
					}
					found=true;
				}
				m_WorkerConfig.atmLock.unlock();
				if(found)
				{
					if(it->second.type == E_TYPE_DOMAIN) // block by domain...
					{
						m_ThreadStats.matched_domains++;
//						_logger.debug("Host %s present in domain (file line %u) list from ip %s to ip %s", host, match.id, src_ip->toString(), dst_ip->toString());
						if(m_WorkerConfig.http_redirect)
						{
							std::string add_param;
							switch (m_WorkerConfig.add_p_type)
							{
								case A_TYPE_ID: add_param="id="+std::to_string(it->second.lineno);
									break;
								case A_TYPE_URL: add_param="url="+uri;
									break;
								default: break;
							}

							SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+payload_len), 1, add_param.empty() ? nullptr : (char *)add_param.c_str()));

//							SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port, src_ip.get(), dst_ip.get(), /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+payload_len),/* flag psh */ 1, add_param));
							m_ThreadStats.redirected_domains++;
						} else {
							SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
							m_ThreadStats.sended_rst++;
						}
						return true;
					} else if(it->second.type == E_TYPE_URL) // block by url...
					{
						m_ThreadStats.matched_urls++;
//						_logger.debug("URL %s present in url (file pos %u) list from ip %s to ip %s", uri, match.id, src_ip->toString(), dst_ip->toString());
						if(m_WorkerConfig.http_redirect)
						{
							std::string add_param;
							switch (m_WorkerConfig.add_p_type)
							{
								case A_TYPE_ID: add_param="id="+std::to_string(it->second.lineno);
									break;
								case A_TYPE_URL: add_param="url="+uri;
									break;
								default: break;
							}
	
							SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+payload_len), 1, add_param.empty() ? nullptr : (char *)add_param.c_str()));

//							SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port, src_ip.get(), dst_ip.get(), /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+payload_len),/* flag psh */ 1, add_param));
							m_ThreadStats.redirected_urls++;
						} else {
							SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
//							SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(), dst_ip.get(), /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, empty_str, true));
							m_ThreadStats.sended_rst++;
						}
//						flow_info->block=true;
						return true;
					}
				}
			}
		}
		if(ip_version == 4 && m_WorkerConfig.nm && m_WorkerConfig.notify_enabled && acl_action == ACL::ACL_NOTIFY)
		{
			uint32_t notify_group = (pkt_info->acl_res & ACL_NOTIFY_GROUP) >> 4;
			if(m_WorkerConfig.nm->needNotify(ipv4_header->src_addr, notify_group))
			{
				std::string add_param("url="+uri);
				NotifyManager::queue.enqueueNotification(new NotifyRedirect(notify_group, tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+payload_len), 1, (char *)add_param.c_str()));
				return true;
			}
		}
	}
	return false;
}

/*
 * Put one packet in acl_search struct according to the packet ol_flags
 */
static inline void prepare_one_packet(struct rte_mbuf** pkts_in, struct ACL::acl_search_t* acl, int index)
{
	struct rte_mbuf* pkt = pkts_in[index];

	uint32_t l3_ptypes = pkt->packet_type & RTE_PTYPE_L3_MASK;

	// XXX we cannot filter non IP packet yet
	if (l3_ptypes == RTE_PTYPE_L3_IPV4)
	{
		/* Fill acl structure */
		acl->data_ipv4[acl->num_ipv4] = ((struct packet_info *)pkt->userdata)->l3 + offsetof(struct ipv4_hdr, next_proto_id);
		acl->m_ipv4[(acl->num_ipv4)++] = pkt;
	} else if (l3_ptypes == RTE_PTYPE_L3_IPV6)
	{
		/* Fill acl structure */
		acl->data_ipv6[acl->num_ipv6] = ((struct packet_info *)pkt->userdata)->l3 + offsetof(struct ipv4_hdr, next_proto_id);
		acl->m_ipv6[(acl->num_ipv6)++] = pkt;
	}
}

/*
 * Loop through all packets and classify them if acl_search if possible.
 */
static inline void prepare_acl_parameter(struct rte_mbuf** pkts_in, struct ACL::acl_search_t* acl, int nb_rx)
{
	int i = 0, j = 0;

	acl->num_ipv4 = 0;
	acl->num_ipv6 = 0;

#define PREFETCH()                                          \
	rte_prefetch0(rte_pktmbuf_mtod(pkts_in[i], void*)); \
	i++;                                                \
	j++;

	// we prefetch0 packets 3 per 3
	switch (nb_rx % PREFETCH_OFFSET) {
		while (nb_rx != i) {
		case 0:
			PREFETCH();
		case 2:
			PREFETCH();
		case 1:
			PREFETCH();

			while (j > 0) {
				prepare_one_packet(pkts_in, acl, i - j);
				--j;
			}
		}
	}
}




bool WorkerThread::run(uint32_t coreId)
{
	setCoreId(coreId);
	uint8_t portid = 0, queueid, port_type;
	uint32_t lcore_id;
	struct lcore_conf* qconf;
	uint16_t nb_rx;
	struct rte_mbuf *bufs[EXTFILTER_CAPTURE_BURST_SIZE];

	lcore_id = rte_lcore_id();
	qconf = extFilter::getLcoreConf(lcore_id);

	if (qconf->n_rx_queue == 0)
	{
		_logger.information("Lcore %d has nothing to do", (int) lcore_id);
		return true;
	}

//	m_CoreId = coreId;
	m_Stop = false;
	struct rte_mbuf *buf;

	const uint64_t timer_interval = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * (1000*1000);

	uint64_t last_sec = 0;

	uint64_t cur_tsc, diff_timer_tsc;
	uint64_t prev_timer_tsc = 0;

	_logger.debug("Starting working thread on core %u", coreId);

	for (int i = 0; i < qconf->n_rx_queue; i++)
	{
		portid = qconf->rx_queue_list[i].port_id;
//		stats[lcore_id].port_id = portid;
		queueid = qconf->rx_queue_list[i].queue_id;
		_logger.information("-- lcoreid=%d portid=%d rxqueueid=%d", (int)lcore_id, (int)portid, (int)queueid);
	}

	// main loop, runs until be told to stop
	while (!m_Stop)
	{
		if(m_Stop)
			break;

		cur_tsc = rte_rdtsc();
		last_time = cur_tsc;

#ifdef ATOMIC_ACL
#define SWAP_ACX(cur_acx, new_acx)                                            \
	acx = cur_acx;                                                        \
	if (!rte_atomic64_cmpswap((uintptr_t*)&new_acx, (uintptr_t*)&cur_acx, \
				  (uintptr_t)new_acx)) {                      \
		rte_acl_free(acx);                                            \
	}
#else
#define SWAP_ACX(cur_acx, new_acx)          \
	if (unlikely(cur_acx != new_acx)) { \
		rte_acl_free(cur_acx);      \
		cur_acx = new_acx;          \
	}
#endif
		SWAP_ACX(qconf->cur_acx_ipv4, qconf->new_acx_ipv4);
		SWAP_ACX(qconf->cur_acx_ipv6, qconf->new_acx_ipv6);
#undef SWAP_ACX

		/*
		 * Read packet from RX queues
		 */
		for (int i = 0; i < qconf->n_rx_queue; i++)
		{
			portid = qconf->rx_queue_list[i].port_id;
			port_type = qconf->rx_queue_list[i].port_type;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, bufs, EXTFILTER_CAPTURE_BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;

			m_ThreadStats.total_packets += nb_rx;
			// prefetch packets...
			for(uint16_t i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++)
			{
				rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
			}

			struct ACL::acl_search_t acl_search;

			prepare_acl_parameter(bufs, &acl_search, nb_rx);

			if(likely(qconf->cur_acx_ipv4 && acl_search.num_ipv4))
			{
				rte_acl_classify(qconf->cur_acx_ipv4, acl_search.data_ipv4, acl_search.res_ipv4, acl_search.num_ipv4, DEFAULT_MAX_CATEGORIES);
				for(int acli=0; acli < acl_search.num_ipv4; acli++)
				{
					if(acl_search.res_ipv4[acli] != 0)
					{
						((struct packet_info *)acl_search.m_ipv4[acli]->userdata)->acl_res=acl_search.res_ipv4[acli];
					}
				}
			}
			if (likely(qconf->cur_acx_ipv6 && acl_search.num_ipv6))
			{
				rte_acl_classify(qconf->cur_acx_ipv6, acl_search.data_ipv6, acl_search.res_ipv6, acl_search.num_ipv6, DEFAULT_MAX_CATEGORIES);
				for(int acli=0; acli < acl_search.num_ipv6; acli++)
				{
					if(acl_search.res_ipv6[acli] != 0)
					{
						((struct packet_info *)acl_search.m_ipv6[acli]->userdata)->acl_res=acl_search.res_ipv6[acli];
					}
				}
			}
			uint64_t cycles = 0;
			uint64_t blocked_cycles = 0;
			for(uint16_t i = 0; i < nb_rx; i++)
			{
				buf = bufs[i];
				if(likely(buf->userdata && port_type == P_TYPE_SUBSCRIBER))
				{
					bool need_block = analyzePacket(buf, last_sec);
					uint64_t now = rte_rdtsc();
					if(need_block)
					{
						blocked_cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
						m_ThreadStats.latency_counters.blocked_pkts++;
					}
					cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
					rte_mempool_put(extFilter::getPktInfoPool(), buf->userdata); // free packet_info
				}
				rte_pktmbuf_free(buf);
			}
			m_ThreadStats.latency_counters.total_cycles += cycles;
			m_ThreadStats.latency_counters.blocked_cycles += blocked_cycles;
			m_ThreadStats.latency_counters.total_pkts += nb_rx;
		}

		diff_timer_tsc = cur_tsc - prev_timer_tsc;
		if (unlikely(diff_timer_tsc >= timer_interval))
		{
			last_sec++;
			prev_timer_tsc = cur_tsc;
		}
	}
	_logger.debug("Worker thread on core %u terminated", coreId);
	return true;
}
