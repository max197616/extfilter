#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <netinet/in.h>
#include <Poco/Stopwatch.h>
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
#include <rte_atomic.h>
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

inline u_int8_t ext_dpi_v6_addresses_equal(uint64_t *x, uint64_t *y)
{
	if(x[0] == y[0] && x[1] == y[1])
		return 1;
	return 0;
}

void host_cb(dpi_http_message_informations_t* http_informations, const u_char* app_data, u_int32_t data_length, dpi_pkt_infos_t* pkt, void** flow_specific_user_data, void* user_data)
{
	if(*flow_specific_user_data != NULL && data_length > 0 && (http_informations->method_or_code == DPI_HTTP_POST || http_informations->method_or_code == DPI_HTTP_GET || http_informations->method_or_code == DPI_HTTP_HEAD))
	{
		struct dpi_flow_info *u = (struct dpi_flow_info *)*flow_specific_user_data;
		WorkerThread *obj = (WorkerThread *) user_data;
		std::string &uri = obj->getUri();
		uri.assign("http://", 7);
		uri.append((char *)app_data, data_length);
		uri.append(u->url, u->url_size);
		obj->setNeedBlock(obj->checkHTTP(uri, pkt));
	}
}

void url_cb_mempool(const unsigned char* url, u_int32_t url_length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	if(url_length == 0)
		return ;
	WorkerThread *obj = (WorkerThread *) user_data;
	struct dpi_flow_info *u = (struct dpi_flow_info *) *flow_specific_user_data;
	if(u == nullptr)
	{
		if(rte_mempool_get(obj->getDPIMempool(), (void **)&u) != 0)
		{
			obj->getStats().dpi_no_mempool_http++;
			return ;
		} else {
			memset(u, 0, sizeof(dpi_flow_info));
			u->dpi_mempool = obj->getDPIMempool();
			*flow_specific_user_data = u;
		}
	}
	struct rte_mempool *mempool = obj->getUrlMempool();
	if(url_length+1 > obj->getConfig().maximum_url_size)
	{
		url_length = obj->getConfig().maximum_url_size;
	}
	u->mempool = mempool;
	if(u->url == nullptr)
	{
		if(mempool != nullptr)
		{
			if(rte_mempool_get(mempool, (void **)&u->url) != 0)
				u->mempool = nullptr;
			else
				u->use_pool = true;
		}
		if(!u->use_pool)
		{
			obj->getStats().dpi_use_url_malloc++;
			u->url = (char *)malloc(url_length+1);
		}
	} else {
		if(!u->use_pool)
		{
			if((url_length+1) > ((u_int32_t)u->url_size+1))
				u->url = (char *)realloc(u->url, url_length+1);
		}
	}
	memcpy(u->url, url, url_length);
	u->url_size = url_length;
}


void url_cb(const unsigned char* url, u_int32_t url_length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	if(url_length == 0)
		return ;
	struct dpi_flow_info *u = (struct dpi_flow_info *) *flow_specific_user_data;
	if(u == nullptr)
	{
		u = (struct dpi_flow_info *)calloc(1, sizeof(dpi_flow_info));
		*flow_specific_user_data = u;
	}
	WorkerThread *obj = (WorkerThread *) user_data;
	struct rte_mempool *mempool = obj->getUrlMempool();
	if(url_length+1 > obj->getConfig().maximum_url_size)
	{
		url_length = obj->getConfig().maximum_url_size;
	}
	u->mempool = mempool;
	if(u->url == nullptr)
	{
		if(mempool != nullptr)
		{
			if(rte_mempool_get(mempool, (void **)&u->url) != 0)
				u->mempool = nullptr;
			else
				u->use_pool = true;
		}
		if(!u->use_pool)
		{
			obj->getStats().dpi_use_url_malloc++;
			u->url = (char *)malloc(url_length+1);
		}
	} else {
		if(!u->use_pool)
		{
			if((url_length+1) > ((u_int32_t)u->url_size+1))
				u->url = (char *)realloc(u->url, url_length+1);
		}
	}
	memcpy(u->url, url, url_length);
	u->url_size = url_length;
}

void ssl_cert_cb(char *certificate, int size, void *user_data, dpi_pkt_infos_t *pkt)
{
	WorkerThread *obj = (WorkerThread *) user_data;
	std::string &cert = obj->getCert();
	cert.assign(certificate, size > 255 ? 255 : size);
	obj->setNeedBlock(obj->checkSSL(cert, pkt));
}

WorkerThread::WorkerThread(const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, int socketid, flowHash *fh, struct ESender::nparams &sp, struct rte_mempool *mp, struct rte_mempool *url_mempool, struct rte_mempool *dpi_mempool) :
		m_WorkerConfig(workerConfig), m_Stop(true),
		_logger(Poco::Logger::get(name)),
		dpi_state(state),
		_name(name),
		m_FlowHash(fh),
		_n_send_pkts(0)
{
	uri.reserve(URI_RESERVATION_SIZE);
	certificate.reserve(CERT_RESERVATION_SIZE);

	// setup peafowl
	static dpi_http_header_field_callback* single_cb[1]={&host_cb};

	static const char* headers[1]={"host"};
	static dpi_http_callbacks_t callback={.header_url_callback = (dpi_mempool == nullptr ? url_cb : url_cb_mempool), .header_names = headers, .num_header_types = 1, .header_types_callbacks = single_cb, .header_completion_callback = 0, .http_body_callback = 0};
	dpi_http_activate_callbacks(dpi_state, &callback, this);
	static dpi_ssl_callbacks_t ssl_callback = {.certificate_callback = ssl_cert_cb };
	dpi_ssl_activate_callbacks(state, &ssl_callback, this);

	// setup hash
	std::string mem_name("IPv4Flows_"+name);
	ipv4_flows = (struct ext_dpi_flow_info **)rte_zmalloc_socket(mem_name.c_str(), fh->getHashSizeIPv4()*sizeof(struct ext_dpi_flow_info *), RTE_CACHE_LINE_SIZE, socketid);
	if(ipv4_flows == nullptr)
	{
		_logger.fatal("Not enough memory for ipv4 flows");
		throw Poco::Exception("Not enough memory for ipv4 flows");
	}
	mem_name.assign("IPv6Flows_"+name);
	ipv6_flows = (struct ext_dpi_flow_info **)rte_zmalloc_socket(mem_name.c_str(), fh->getHashSizeIPv6()*sizeof(struct ext_dpi_flow_info *), RTE_CACHE_LINE_SIZE, socketid);
	if(ipv6_flows == nullptr)
	{
		_logger.fatal("Not enough memory for ipv6 flows");
		throw Poco::Exception("Not enough memory for ipv6 flows");
	}
	_logger.debug("Allocating %d bytes for flow pool", (int) ((fh->getHashSizeIPv4() + fh->getHashSizeIPv6())*sizeof(struct ext_dpi_flow_info)));
	std::string mempool_name("flows_pool_" + name);
	flows_pool = rte_mempool_create(mempool_name.c_str(), (fh->getHashSizeIPv4() + fh->getHashSizeIPv6()), sizeof(struct ext_dpi_flow_info), 0, 0, NULL, NULL, NULL, NULL, socketid, 0);
	if(flows_pool == nullptr)
	{
		_logger.fatal("Not enough memory for flows pool. Tried to allocate %d bytes on socket %d", (int) ((fh->getHashSizeIPv4() + fh->getHashSizeIPv6())*sizeof(struct ext_dpi_flow_info)), socketid);
		throw Poco::Exception("Not enough memory for flows pool");
	}
	if(mp != nullptr)
	{
		// setup sender
		_snd = new ESender(sp, m_WorkerConfig.sender_port, mp, this);
	} else {
		_snd = nullptr;
	}
	_url_mempool = url_mempool;
	_dpi_mempool = dpi_mempool;
	uri_p = new Poco::URI("http://www.longurlmakerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr.com/go?id=83olengthy1195stretchingShortURL2s11Beam.tocYepItShortlinksqstretchxrunning1c3stretched2sy436vxfaraway0096ShredURLFwdURL4n111aLiteURL09f0307whighgreatrangy5erunningEasyURL0b6sh6aprotracted1140elongated120towering3DecentURL1g0remotea14great168lEasyURL4continued70f6runningURLviUlimit20v94prolonged0r07Ne1stretcheddistant6URLCutterhighEasyURLlnk.inextensivedestretched1003bShim1041FhURLa39aURLvirunning590kShrinkURLaa1w7elongated010lofty1312549h6bShim9045ar01drawn%2Bout0g8egj10PiURL2bf113protracted154100flingeringShim7prolongedspread%2Bout10301URL8loftysustainedenduringdeep0SHurlaf043far%2Breachingo1deep17enlargede01drawn%2Bout1d57lnk.inSHurlfar%2Breaching001Smallrk2runningDigBigSimURLEasyURLflengthenedURLPie004301URL0spun%2Boutwt1expandede0910GetShortytowering0distant6ffhigheShim2loftyspun%2Bout1NanoRef1401spread%2Boutcetallexpanded5stretched0RubyURLURLHawkloftyaB654UrlTea0URLcut1prolonged2dx7SHurl74j41c2301URLWapURL60lDoiopMyURLTightURL01Redirx21stringyDoiopURLvi4YepItb0URLcut0620stretchingd180lengthened2171FwdURLc1b5URLHawk35lingeringCanURLdrawn%2Boutlengthened0c0rangySimURLprotracted78440muganglingShrtnds2oa00greatb30hyfar%2Breaching1k7Smallr110o715far%2Bofflingering41elongate9k1running3TraceURL3towering6rangy0lanky1EasyURLURLHawkstretchingstretch076jdeep151far%2BofffShortURL05TinyLink78f32715ufdistantprolongedstretchingwd30lengthened1elongated0c8NanoRefsustained7Metamark3w9301URLIs.gd11URL.co.ukDecentURL5extensive1ShoterLinkShorl00v39lengthyntall8f0041f6d5prolonged111EasyURLcontinuedShortlinks4c4408stringym5d0drawn%2Boutf9dShrinkURLURLCutterURLCutter3agangling3SnipURL0G8L00adiYepIt0Minilien91l1URLPie0SnipURLlofty00Shim5hdeepsa1continuedprotracted15765fSnipURLA2Nfar%2Boff1qfar%2Boffstretchinglengthyfar%2Boffc78drawn%2Bout21outstretchedspun%2Boutz52sremoteremoteprolongedeq0yUlimitb1B651CanURL6sustainedj02h117010URLHawk8high0outstretched8aafvstretch0037runningaextensive9ndeep0U7611yab5URl.ieShortenURLsustainedShredURLx60WapURL8aremote9expanded2tall09601gangling21A2N9d48rangysustained36far%2Breachingstretching2lengthened41NotLong11210Ulimit0814Is.gdPiURL89");
}

WorkerThread::~WorkerThread()
{
	dpi_terminate(dpi_state);
	delete uri_p;
	if(_snd != nullptr)
		delete _snd;
}

bool WorkerThread::checkSSL(std::string &certificate, dpi_pkt_infos_t *pkt)
{
	struct ipv4_hdr *ipv4_header = (struct ipv4_hdr *) pkt->pkt;
	struct ipv6_hdr *ipv6_header = (struct ipv6_hdr *) pkt->pkt;
	struct tcphdr* tcph;
	tcph = (struct tcphdr *)((uint8_t *) pkt->pkt + (pkt->ip_version == 4 ? sizeof(struct ipv4_hdr) : sizeof(struct ipv6_hdr)));

	if(likely(m_WorkerConfig.atmSSLDomains != nullptr))
	{
		if(m_WorkerConfig.lower_host)
			std::transform(certificate.begin(), certificate.end(), certificate.begin(), ::tolower);
		AhoCorasickPlus::Match match;
		std::size_t host_len=certificate.length();
		bool found=false;
		m_WorkerConfig.atmSSLDomains->search(certificate, false);
		while(m_WorkerConfig.atmSSLDomains->findNext(match) && !found)
		{
			if(match.pattern.ptext.length != host_len)
			{
				bool exact_match=match.id & 0x01;
				if(exact_match)
					continue;
				if(certificate[host_len-match.pattern.ptext.length-1] != '.')
					continue;
			}
			found=true;
		}
		if(found)
		{
			m_ThreadStats.matched_ssl++;
			if(likely(_snd != nullptr))
			{
				_snd->SendRST(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0);
			} else {
				SenderTask::queue.enqueueNotification(new RedirectNotificationG(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
			}
			m_ThreadStats.sended_rst++;
			return true;
		}
	}
	return false;
}

bool WorkerThread::checkHTTP(std::string &uri, dpi_pkt_infos_t *pkt)
{
	struct ipv4_hdr *ipv4_header = (struct ipv4_hdr *) pkt->pkt;
	struct ipv6_hdr *ipv6_header = (struct ipv6_hdr *) pkt->pkt;
	struct tcphdr* tcph;
	tcph = (struct tcphdr *)((uint8_t *) pkt->pkt + (pkt->ip_version == 4 ? sizeof(struct ipv4_hdr) : sizeof(struct ipv6_hdr)));
	if(likely(m_WorkerConfig.atm != nullptr))
	{
		if(m_WorkerConfig.url_normalization)
		{
			try
			{
				*uri_p = uri;
				uri_p->normalize();
				uri.assign(uri_p->toString());
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
		m_WorkerConfig.atm->search((char *)uri_ptr, uri_length, false);
		while(m_WorkerConfig.atm->findNext(match) && !found)
		{
			if(match.pattern.ptext.length != uri_length)
			{
				int r=match.position-match.pattern.ptext.length;
				if(((match.id & 0x02) >> 1) == E_TYPE_DOMAIN)
				{
					if(r > 0)
					{
						if(match.id & 0x01)
							continue;
						if(*(uri_ptr+r-1) != '.')
							continue;
					}
				} else if(((match.id & 0x02) >> 1) == E_TYPE_URL)
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
		if(found)
		{
			if(((match.id & 0x02) >> 1) == E_TYPE_DOMAIN) // block by domain...
			{
				m_ThreadStats.matched_domains++;
				if(m_WorkerConfig.http_redirect)
				{
					std::string add_param;
					switch (m_WorkerConfig.add_p_type)
					{
						case A_TYPE_ID: add_param="id="+std::to_string(match.id >> 2);
							break;
						case A_TYPE_URL: add_param="url="+uri;
							break;
						default: break;
					}
					if(likely(_snd != nullptr))
					{
						_snd->Redirect(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), 1, add_param.empty() ? nullptr : (char *)add_param.c_str());
					} else {
						SenderTask::queue.enqueueNotification(new RedirectNotificationG(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), 1, add_param.empty() ? nullptr : (char *)add_param.c_str()));
					}
					m_ThreadStats.redirected_domains++;
				} else {
					if(likely(_snd != nullptr))
					{
						_snd->SendRST(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0);
					} else {
						SenderTask::queue.enqueueNotification(new RedirectNotificationG(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
					}
					m_ThreadStats.sended_rst++;
				}
				return true;
			} else if(((match.id & 0x02) >> 1) == E_TYPE_URL) // block by url...
			{
				m_ThreadStats.matched_urls++;
				if(m_WorkerConfig.http_redirect)
				{
					std::string add_param;
					switch (m_WorkerConfig.add_p_type)
					{
						case A_TYPE_ID: add_param="id="+std::to_string(match.id >> 2);
							break;
						case A_TYPE_URL: add_param="url="+uri;
							break;
						default: break;
					}
					if(likely(_snd != nullptr))
					{
						_snd->Redirect(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), 1, add_param.empty() ? nullptr : (char *)add_param.c_str());
					} else {
						SenderTask::queue.enqueueNotification(new RedirectNotificationG(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), 1, add_param.empty() ? nullptr : (char *)add_param.c_str()));
					}
					m_ThreadStats.redirected_urls++;
				} else {
					if(likely(_snd != nullptr))
					{
						_snd->SendRST(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0);
					} else {
						SenderTask::queue.enqueueNotification(new RedirectNotificationG(pkt->srcport, pkt->dstport, pkt->ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, pkt->ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, pkt->ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
					}
					m_ThreadStats.sended_rst++;
				}
				return true;
			}
		}
	}
	return false;
}



dpi_identification_result_t WorkerThread::identifyAppProtocol(const unsigned char* pkt, u_int32_t length, u_int32_t current_time, uint8_t *host_key, uint32_t sig)
{
	dpi_identification_result_t r;
	r.status = DPI_STATUS_OK;
	dpi_pkt_infos_t infos = { 0 };
	u_int8_t l3_status;

	r.status = dpi_parse_L3_L4_headers(dpi_state, pkt, length, &infos, current_time);

	if(unlikely(r.status==DPI_STATUS_IP_FRAGMENT || r.status<0))
	{
		return r;
	}

	if(infos.l4prot != IPPROTO_TCP && infos.l4prot != IPPROTO_UDP)
	{
		r.status=DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
		return r;
	}

	l3_status = r.status;
	r.status = DPI_STATUS_OK;
	/**
	 * We return the status of dpi_stateful_get_app_protocol call,
	 * without giving informations on status returned
	 * by dpi_parse_L3_L4_headers. Basically we return the status which
	 * provides more informations.
	 */
	r = getAppProtocol(host_key, current_time, sig, &infos);

	if(l3_status == DPI_STATUS_IP_LAST_FRAGMENT)
	{
		free((unsigned char*) infos.pkt);
	}

	return r;
}



dpi_identification_result_t WorkerThread::getAppProtocol(uint8_t *host_key, uint64_t timestamp, uint32_t sig, dpi_pkt_infos_t *pkt_infos)
{
	dpi_identification_result_t r;
	r.status = DPI_STATUS_OK;

	dpi_flow_infos_t* flow_infos=NULL;

	int32_t hash_idx = 0;

	ext_dpi_flow_info *fi = getFlow(host_key, timestamp, &hash_idx, sig, pkt_infos);

	if(unlikely(fi==NULL))
	{
		r.status=DPI_ERROR_MAX_FLOWS;
		return r;
	}

	flow_infos = &(fi->infos);

	r = dpi_stateless_get_app_protocol(dpi_state, flow_infos, pkt_infos);

	if(r.status == DPI_STATUS_TCP_CONNECTION_TERMINATED)
	{
		if(pkt_infos->ip_version == 4)
		{
			int32_t delr=rte_hash_del_key(m_FlowHash->getIPv4Hash(), host_key);
			if(delr < 0)
			{
				_logger.error("Error (%d) occured while delete data from the ipv4 flow hash table", (int)delr);
			} else {
				ipv4_flows[hash_idx]->free_mem(dpi_state->flow_cleaner_callback);
				rte_mempool_put(flows_pool, ipv4_flows[hash_idx]);
				ipv4_flows[hash_idx] = nullptr;
				m_ThreadStats.ndpi_flows_count--;
				m_ThreadStats.ndpi_ipv4_flows_count--;
				m_ThreadStats.ndpi_flows_deleted++;
			}
		} else {
			int32_t delr=rte_hash_del_key(m_FlowHash->getIPv6Hash(), host_key);
			if(delr < 0)
			{
				_logger.error("Error (%d) occured while delete data from the ipv6 flow hash table", (int)delr);
			} else {
				ipv6_flows[hash_idx]->free_mem(dpi_state->flow_cleaner_callback);
				rte_mempool_put(flows_pool,ipv6_flows[hash_idx]);
				ipv6_flows[hash_idx] = nullptr;
				m_ThreadStats.ndpi_flows_count--;
				m_ThreadStats.ndpi_ipv6_flows_count--;
				m_ThreadStats.ndpi_flows_deleted++;
			}
		}
	}
	return r;
}



ext_dpi_flow_info *WorkerThread::getFlow(uint8_t *host_key, uint64_t timestamp, int32_t *idx, uint32_t sig, dpi_pkt_infos_t *pkt_infos)
{
	if(pkt_infos->ip_version == 6)
	{
		int32_t ret = rte_hash_lookup_with_hash(m_FlowHash->getIPv6Hash(), host_key, sig);
		if(ret >= 0)
		{
			if(pkt_infos->l4prot == IPPROTO_TCP && ipv6_flows[ret]->infos.tracking.seen_rst && ((struct tcphdr*) (pkt_infos->pkt + pkt_infos->l4offset))->syn)
			{
				// Delete old flow.
				ipv6_flows[ret]->free_mem(dpi_state->flow_cleaner_callback);
				rte_mempool_put(flows_pool, ipv6_flows[ret]);
				ipv6_flows[ret] = nullptr;
				m_ThreadStats.ndpi_flows_count--;
				m_ThreadStats.ndpi_ipv6_flows_count--;
				m_ThreadStats.ndpi_flows_deleted++;
				// Force the following code to create a new flow.
				ret = -ENOENT;
			} else {
				*idx = ret;
				if(ext_dpi_v6_addresses_equal((uint64_t *)&(ipv6_flows[ret]->src_addr_t.ipv6_srcaddr),(uint64_t *) &pkt_infos->src_addr_t.ipv6_srcaddr) && ipv6_flows[ret]->srcport == pkt_infos->srcport)
					pkt_infos->direction=0;
				else
					pkt_infos->direction=1;
				ipv6_flows[ret]->last_timestamp = timestamp;
				return ipv6_flows[ret];
			}
		}
		if(ret == -EINVAL)
		{
			_logger.error("Bad parameter in ipv6 hash lookup");
			return NULL;
		}
		if(ret == -ENOENT)
		{
			struct ext_dpi_flow_info *newflow;
			if(rte_mempool_get(flows_pool, (void **)&newflow) != 0)
			{
				_logger.fatal("Not enough memory for the flow in the flows_pool");
				return NULL;
			}
			memset(newflow, 0, sizeof(struct ext_dpi_flow_info));
			newflow->last_timestamp = timestamp;
			rte_memcpy(&newflow->src_addr_t.ipv6_srcaddr, &pkt_infos->src_addr_t.ipv6_srcaddr, IPV6_ADDR_LEN * 2);
			newflow->srcport=pkt_infos->srcport;
			newflow->dstport=pkt_infos->dstport;
			newflow->l4prot=pkt_infos->l4prot;

			dpi_init_flow_infos(dpi_state, &(newflow->infos), pkt_infos->l4prot);

			pkt_infos->direction = 0;
			ret = rte_hash_add_key_with_hash(m_FlowHash->getIPv6Hash(), host_key, sig);
			if(ret == -EINVAL)
			{
				rte_mempool_put(flows_pool,newflow);
				_logger.fatal("Bad parameters in hash add");
				return NULL;
			}
			if(ret == -ENOSPC)
			{
				rte_mempool_put(flows_pool,newflow);
				_logger.fatal("There is no space in the ipv6 flow hash");
				return NULL;
			}
			ipv6_flows[ret] = newflow;
			*idx = ret;
			m_ThreadStats.ndpi_ipv6_flows_count++;
			m_ThreadStats.ndpi_flows_count++;
			return newflow;
		}
		return NULL;
	}
	if(pkt_infos->ip_version == 4)
	{
		int32_t ret = rte_hash_lookup_with_hash(m_FlowHash->getIPv4Hash(), host_key, sig);
		if(ret >= 0)
		{
			if(pkt_infos->l4prot == IPPROTO_TCP && ipv4_flows[ret]->infos.tracking.seen_rst && ((struct tcphdr*) (pkt_infos->pkt + pkt_infos->l4offset))->syn)
			{
				// Delete old flow.
				ipv4_flows[ret]->free_mem(dpi_state->flow_cleaner_callback);
				rte_mempool_put(flows_pool, ipv4_flows[ret]);
				ipv4_flows[ret] = nullptr;
				m_ThreadStats.ndpi_flows_count--;
				m_ThreadStats.ndpi_ipv4_flows_count--;
				m_ThreadStats.ndpi_flows_deleted++;
				// Force the following code to create a new flow.
				ret = -ENOENT;
			} else {
				*idx = ret;
				if(ipv4_flows[ret]->src_addr_t.ipv4_srcaddr == pkt_infos->src_addr_t.ipv4_srcaddr && ipv4_flows[ret]->srcport == pkt_infos->srcport)
					pkt_infos->direction=0;
				else
					pkt_infos->direction=1;
				ipv4_flows[ret]->last_timestamp = timestamp;
				return ipv4_flows[ret];
			}
		}
		if(ret == -EINVAL)
		{
			_logger.error("Bad parameter in ipv4 hash lookup");
			return NULL;
		}
		if(ret == -ENOENT)
		{
			struct ext_dpi_flow_info *newflow;
			if(rte_mempool_get(flows_pool, (void **)&newflow) != 0)
			{
				_logger.fatal("Not enough memory for the flow in the flows_pool");
				return NULL;
			}
			memset(newflow, 0, sizeof(struct ext_dpi_flow_info));
			newflow->last_timestamp = timestamp;

			newflow->src_addr_t.ipv4_srcaddr = pkt_infos->src_addr_t.ipv4_srcaddr;
			newflow->dst_addr_t.ipv4_dstaddr = pkt_infos->dst_addr_t.ipv4_dstaddr;
			newflow->srcport=pkt_infos->srcport;
			newflow->dstport=pkt_infos->dstport;
			newflow->l4prot=pkt_infos->l4prot;

			dpi_init_flow_infos(dpi_state, &(newflow->infos), pkt_infos->l4prot);

			pkt_infos->direction = 0;
			ret = rte_hash_add_key_with_hash(m_FlowHash->getIPv4Hash(), host_key, sig);
			if(ret == -EINVAL)
			{
				rte_mempool_put(flows_pool,newflow);
				_logger.fatal("Bad parameters in hash add");
				return NULL;
			}
			if(ret == -ENOSPC)
			{
				rte_mempool_put(flows_pool,newflow);
				_logger.fatal("There is no space in the ipv4 flow hash");
				return NULL;
			}
			ipv4_flows[ret] = newflow;
			*idx = ret;
			m_ThreadStats.ndpi_ipv4_flows_count++;
			m_ThreadStats.ndpi_flows_count++;
			return newflow;
		}
		return NULL;
	}
	return NULL;
}

bool WorkerThread::analyzePacket(struct rte_mbuf* m, uint64_t timestamp)
{
	uint8_t *l3;
	uint16_t l4_packet_len;
	uint16_t payload_len;
	struct ipv4_hdr *ipv4_header=nullptr;
	struct ipv6_hdr *ipv6_header=nullptr;
	int size=rte_pktmbuf_pkt_len(m);

	_need_block = false;
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

	payload_len = l4_packet_len - tcphlen;

	m_ThreadStats.analyzed_packets++;

	uint16_t tcp_src_port = tcph->source;
	uint16_t tcp_dst_port = tcph->dest;

	uint32_t acl_action = pkt_info->acl_res & ACL_POLICY_MASK;
	if(payload_len > 0 && acl_action == ACL::ACL_DROP)
	{
		m_ThreadStats.matched_ip_port++;
		SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
		m_ThreadStats.sended_rst++;
		return true;
	}


	dpi_identification_result_t r;
	uri.clear();

	r = identifyAppProtocol(l3, ip_len, timestamp, (uint8_t *)&((struct packet_info *)m->userdata)->keys, m->hash.usr);

	if(_need_block)
		return true;

	if(payload_len == 0)
		return false;

	if(r.protocol.l7prot == DPI_PROTOCOL_TCP_SSL)
	{
		if(m_WorkerConfig.block_ssl_no_sni)
		{
			if(acl_action == ACL::ACL_SSL && payload_len > 0)
			{
				m_ThreadStats.matched_ssl_ip++;
				m_ThreadStats.sended_rst++;
				SenderTask::queue.enqueueNotification(new RedirectNotificationG(tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq, 0, nullptr, true));
				return true;
			}
		}
	}

	if(r.protocol.l7prot == DPI_PROTOCOL_TCP_HTTP && !uri.empty())
	{
		if(ip_version == 4 && m_WorkerConfig.nm && m_WorkerConfig.notify_enabled && acl_action == ACL::ACL_NOTIFY)
		{
			uint32_t notify_group = (pkt_info->acl_res & ACL_NOTIFY_GROUP) >> 4;
			if(m_WorkerConfig.nm->needNotify(ipv4_header->src_addr, notify_group))
			{
				//std::string add_param("url="+uri);
				std::string add_param;
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
	int tx_ret;

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

	const uint64_t gc_int_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * EXTF_GC_INTERVAL;

	int gc_budget_ipv4 = ((double)m_FlowHash->getHashSizeIPv4()/(EXTF_ALL_GC_INTERVAL*1000*1000))*EXTF_GC_INTERVAL;

	int gc_budget_ipv6 = ((double)m_FlowHash->getHashSizeIPv6()/(EXTF_ALL_GC_INTERVAL*1000*1000))*EXTF_GC_INTERVAL;

	_logger.information("gc_budget_ipv4: %d, gc_budget_ipv6: %d", gc_budget_ipv4, gc_budget_ipv6);

	_logger.information("Running gc clean every %" PRIu64 " cycles. Cycles per second %" PRIu64, gc_int_tsc, rte_get_timer_hz());

	uint64_t last_sec = 0;

	uint64_t cur_tsc, diff_timer_tsc, diff_gc_tsc;
	uint64_t prev_timer_tsc = 0;
	uint64_t prev_gc_tsc=0;

	uint32_t iter_flows_ipv4 = 0;
	uint32_t iter_flows_ipv6 = 0;

	uint8_t sender_port = m_WorkerConfig.sender_port;
	uint16_t tx_queue_id = m_WorkerConfig.tx_queue_id;

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
//#define ATOMIC_ACL
#ifdef ATOMIC_ACL
#define SWAP_ACX(cur_acx, new_acx)                                            \
	rte_atomic64_cmpswap((uintptr_t*)&new_acx, (uintptr_t*)&cur_acx, \
				  (uintptr_t)new_acx))
#else
#define SWAP_ACX(cur_acx, new_acx)          \
	if (unlikely(cur_acx != new_acx)) { \
		cur_acx = new_acx;          \
	}
#endif
		SWAP_ACX(qconf->cur_acx_ipv4, qconf->new_acx_ipv4);
		SWAP_ACX(qconf->cur_acx_ipv6, qconf->new_acx_ipv6);
#undef SWAP_ACX

		if(unlikely(m_WorkerConfig.atm_new != m_WorkerConfig.atm))
			m_WorkerConfig.atm = m_WorkerConfig.atm_new;

		if(unlikely(m_WorkerConfig.atmSSLDomains_new != m_WorkerConfig.atmSSLDomains))
			m_WorkerConfig.atmSSLDomains = m_WorkerConfig.atmSSLDomains_new;

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
			if(_n_send_pkts > 0)
			{
				tx_ret = rte_eth_tx_burst(sender_port, tx_queue_id, _sender_buf, _n_send_pkts);
				if (unlikely(tx_ret < _n_send_pkts))
				{
					do {
						rte_pktmbuf_free(_sender_buf[tx_ret]);
					} while (++tx_ret < _n_send_pkts);
				}
				_n_send_pkts = 0;
			}
		}

		diff_gc_tsc = cur_tsc - prev_gc_tsc;
		if (unlikely(diff_gc_tsc >= gc_int_tsc))
		{
			int z=0;
			while(z < gc_budget_ipv4 && iter_flows_ipv4 < m_FlowHash->getHashSizeIPv4())
			{
				if(ipv4_flows[iter_flows_ipv4] && (last_sec - (ipv4_flows[iter_flows_ipv4]->last_timestamp) > EXT_DPI_FLOW_TABLE_MAX_IDLE_TIME))
				{
					void *key_ptr;
					int fr=rte_hash_get_key_with_position(m_FlowHash->getIPv4Hash(), iter_flows_ipv4, &key_ptr);
					if(fr < 0)
					{
						_logger.error("Key not found in the hash for the position %d", (int) iter_flows_ipv4);
					} else {
						int32_t delr=rte_hash_del_key(m_FlowHash->getIPv4Hash(), key_ptr);
						if(delr < 0)
						{
							_logger.error("Error (%d) occured while delete data from the ipv4 flow hash table", (int)delr);
						} else {
							ipv4_flows[iter_flows_ipv4]->free_mem(dpi_state->flow_cleaner_callback);
							rte_mempool_put(flows_pool, ipv4_flows[iter_flows_ipv4]);
							ipv4_flows[iter_flows_ipv4] = nullptr;
							m_ThreadStats.ndpi_flows_count--;
							m_ThreadStats.ndpi_ipv4_flows_count--;
							m_ThreadStats.ndpi_flows_deleted++;
							m_ThreadStats.ndpi_flows_expired++;
						}
					}
				}
				z++;
				iter_flows_ipv4++;
			}
			if(iter_flows_ipv4 >= m_FlowHash->getHashSizeIPv4())
				iter_flows_ipv4 = 0;
			z=0;
			while(z < gc_budget_ipv6 && iter_flows_ipv6 < m_FlowHash->getHashSizeIPv6())
			{
				if(ipv6_flows[iter_flows_ipv6] && ((last_sec - ipv6_flows[iter_flows_ipv6]->last_timestamp) > EXT_DPI_FLOW_TABLE_MAX_IDLE_TIME))
				{
					void *key_ptr;
					int fr=rte_hash_get_key_with_position(m_FlowHash->getIPv6Hash(), iter_flows_ipv6, &key_ptr);
					if(fr < 0)
					{
						_logger.error("Key not found in the hash for the position %d", (int) iter_flows_ipv6);
					} else {
						int32_t delr=rte_hash_del_key(m_FlowHash->getIPv6Hash(), key_ptr);
						if(delr < 0)
						{
							_logger.error("Error (%d) occured while delete data from the ipv6 flow hash table", (int)delr);
						} else {
							ipv6_flows[iter_flows_ipv6]->free_mem(dpi_state->flow_cleaner_callback);
							rte_mempool_put(flows_pool,ipv6_flows[iter_flows_ipv6]);
							ipv6_flows[iter_flows_ipv6] = nullptr;
							m_ThreadStats.ndpi_flows_count--;
							m_ThreadStats.ndpi_ipv6_flows_count--;
							m_ThreadStats.ndpi_flows_deleted++;
							m_ThreadStats.ndpi_flows_expired++;
						}
					}
				}
				z++;
				iter_flows_ipv6++;
			}
			if(iter_flows_ipv6 >= m_FlowHash->getHashSizeIPv6())
				iter_flows_ipv6 = 0;
			prev_gc_tsc = cur_tsc;
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
