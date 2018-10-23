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
#include <netinet/udp.h>

#include "worker.h"
#include "main.h"
#include "sendertask.h"
#include "flow.h"
#include "acl.h"
#include <rte_hash.h>
#include "notification.h"
#include "utils.h"
#include "http.h"
#include "dtypes.h"
#include "ssli.h"

#define tcphdr(x)	((struct tcphdr *)(x))

inline u_int8_t ext_dpi_v6_addresses_equal(uint64_t *x, uint64_t *y)
{
	if(x[0] == y[0] && x[1] == y[1])
		return 1;
	return 0;
}

int on_header_complete_ext(http_parser* p, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	if(*flow_specific_user_data != NULL)
	{
		WorkerThread *obj = (WorkerThread *) user_data;
		struct http::http_req_buf *d = (struct http::http_req_buf *) *flow_specific_user_data;
		obj->setNeedBlock(obj->checkURLBlocked(d->host_r.buf, d->host_r.length, d->uri.buf, d->uri.length, pkt_informations));
		d->uri.length = 0;
		d->host_r.length = 0;
	}
	return 1; // no need to check body...
}

WorkerThread::WorkerThread(uint8_t worker_id,const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, struct ESender::nparams &sp, struct rte_mempool *mp) :
		m_WorkerConfig(workerConfig), m_Stop(true),
		_logger(Poco::Logger::get(name)),
		dpi_state(state),
		_name(name),
		_n_send_pkts(0),
		_worker_id(worker_id)
{
	static dpi_external_http_callbacks_t ext_callbacks = {
		.on_url = http::on_url_ext,
		.on_header_field = http::on_header_field_ext,
		.on_header_value = http::on_header_value_ext,
		.on_headers_complete = on_header_complete_ext
	};
	dpi_http_activate_ext_callbacks(dpi_state, &ext_callbacks, this);

	dpi_ssl_activate_external_inspector(state, ssl_inspector, this);

	ipv4_flow_mask = global_prm->memory_configs.ipv4.mask_parts_flow;
	ipv6_flow_mask = global_prm->memory_configs.ipv6.mask_parts_flow;

	if(mp != nullptr)
	{
		// setup sender
		_snd = new ESender(sp, m_WorkerConfig.sender_port, mp, this, global_prm->operation_mode == OP_MODE_INLINE ? true : false);
	} else {
		throw Poco::Exception("ESender is null!");
	}
	_dpi_http_mempool = common_data->mempools.http_entries.mempool;
	_dpi_ssl_mempool = common_data->mempools.ssl_entries.mempool;
}

WorkerThread::~WorkerThread()
{
	dpi_terminate(dpi_state);
	if(_snd != nullptr)
		delete _snd;
}

bool WorkerThread::checkSNIBlocked(const char *sni, size_t sni_len, dpi_pkt_infos_t* pkt)
{
	if(extFilter::instance()->getTriesManager()->checkSNIBlocked(getWorkerID(), sni, sni_len))
	{
		struct tcphdr *tcph = (struct tcphdr *)((uint8_t *) pkt->pkt + (pkt->ip_version == 4 ? sizeof(struct ipv4_hdr) : sizeof(struct ipv6_hdr)));
		m_ThreadStats.matched_ssl_sni++;
		if(pkt->ip_version == 4)
		{
			_snd->SendRSTIPv4(pkt, tcph->ack_seq, tcph->seq);
			m_ThreadStats.sended_rst_ipv4++;
		} else {
			_snd->SendRSTIPv6(pkt, tcph->ack_seq, tcph->seq);
			m_ThreadStats.sended_rst_ipv6++;
		}
		return true;
	}
	return false;
}

bool WorkerThread::checkURLBlocked(const char *host, size_t host_len, const char *uri, size_t uri_len, dpi_pkt_infos_t* pkt)
{
	int redir_size = 0;
	char *redir_url = nullptr;
	if((redir_size = extFilter::instance()->getTriesManager()->checkURLBlocked(getWorkerID(), host, host_len, uri, uri_len, &redir_url)) != 0)
	{

		struct tcphdr *tcph = (struct tcphdr *)((uint8_t *) pkt->pkt + (pkt->ip_version == 4 ? sizeof(struct ipv4_hdr) : sizeof(struct ipv6_hdr)));
		if(likely(redir_url != nullptr))
		{
			if(pkt->ip_version == 4)
			{
				_snd->HTTPRedirectIPv4(pkt, tcph->ack_seq, rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), true, redir_url, redir_size);
				m_ThreadStats.matched_http_bl_ipv4++;
				m_ThreadStats.redirected_http_bl_ipv4++;
			} else {
				_snd->HTTPRedirectIPv6(pkt, tcph->ack_seq, rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), true, redir_url, redir_size);
				m_ThreadStats.matched_http_bl_ipv6++;
				m_ThreadStats.redirected_http_bl_ipv6++;
			}
		} else {
			if(pkt->ip_version == 4)
			{
				_snd->HTTPForbiddenIPv4(pkt, tcph->ack_seq, rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), true);
				m_ThreadStats.sended_forbidden_ipv4++;
				m_ThreadStats.matched_http_bl_ipv4++;
			} else {
				_snd->HTTPForbiddenIPv6(pkt, tcph->ack_seq, rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+pkt->data_length), true);
				m_ThreadStats.sended_forbidden_ipv6++;
				m_ThreadStats.matched_http_bl_ipv6++;
			}
		}
		return true;
	}
	return false;
}

dpi_identification_result_t WorkerThread::identifyAppProtocol(const unsigned char* pkt, u_int32_t length, const uint8_t *l2_pkt, u_int32_t current_time, struct packet_info *pkt_info, uint32_t sig)
{
	uint8_t *host_key = (uint8_t *)&pkt_info->keys;
	dpi_identification_result_t r;
	dpi_pkt_infos_t infos = { 0 };
	u_int8_t l3_status;

	r.status = dpi_parse_L3_L4_headers(dpi_state, pkt, length, &infos, current_time);
	infos.l2_pkt = l2_pkt;
	if(unlikely(r.status==DPI_STATUS_IP_FRAGMENT || r.status<0))
	{
		return r;
	}

	if(unlikely(infos.l4prot != IPPROTO_TCP && infos.l4prot != IPPROTO_UDP))
	{
		r.status = DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
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
	r.protocol.l7prot = DPI_PROTOCOL_UNKNOWN;

	dpi_flow_infos_t* flow_infos = nullptr;

	int32_t hash_idx = 0;

	FlowStorageIPV4 *fs_ipv4 = nullptr;
	FlowStorageIPV6 *fs_ipv6 = nullptr;

	tcphdr *tcph = nullptr;

	en_alfs_type_t alfs_type = en_alfs_short;

	if(pkt_infos->l4prot == IPPROTO_TCP)
	{
		tcph = (struct tcphdr*) (pkt_infos->pkt + pkt_infos->l4offset);
		if(tcph->fin == 0 && tcph->syn == 0 && tcph->rst == 0)
			alfs_type = en_alfs_long;
	}
	ext_dpi_flow_info_ipv4 *node = nullptr;
	ext_dpi_flow_info_ipv6 *node_ipv6 = nullptr;
	if(pkt_infos->ip_version == 4)
	{
		fs_ipv4 = (FlowStorageIPV4 *) worker_params[_worker_id].flows_ipv4.flows[ipv4_flow_mask & sig];
		node = fs_ipv4->searchFlow(host_key, sig, pkt_infos, &hash_idx);
		if(node == nullptr)
		{
			if(tcph != nullptr)
			{
				// проверяем флаги tcp. этих flow нет в кэше, поэтому пропускаем ничего не делая
				// rst - нечего завершать, т.к. dpi не знает flow
				// syn+ack - нечего подтверждать, т.к. нет flow
				// fin - нечего завершать, т.к. нет flow
				if(tcph->rst || (tcph->ack && tcph->syn) || tcph->fin)
//				if(tcph->rst || tcph->fin)
				{
					m_ThreadStats.no_create_flow++;
					return r;
				}
			}
			pkt_infos->direction=0;
			if((node = fs_ipv4->short_alfs.getOldestMoveBack(timestamp, &fs_ipv4->long_alfs)) != nullptr || (node = fs_ipv4->long_alfs.getOldestMoveBack(timestamp, &fs_ipv4->short_alfs)) != nullptr)
			{
				// есть просроченная запись...
				// очищаем всю память, занятую ранее...
				node->free_mem(dpi_state->flow_cleaner_callback);
				// надо удалить по ключу из старой записи...
				fs_ipv4->removeFlow(node->cmn.hash_idx);
				node->init(timestamp, node->cmn.owner_worker_id, _worker_id, node->cmn.idx_alfs, node->cmn.hash_idx);

				node->src_addr_t.ipv4_srcaddr = pkt_infos->src_addr_t.ipv4_srcaddr;
				node->dst_addr_t.ipv4_dstaddr = pkt_infos->dst_addr_t.ipv4_dstaddr;
				node->srcport = pkt_infos->srcport;
				node->dstport = pkt_infos->dstport;
				node->l4prot = pkt_infos->l4prot;

				dpi_init_flow_infos(dpi_state, &(node->infos), pkt_infos->l4prot);
				node->cmn.alfs_type = alfs_type;

				fs_ipv4->reuseFlow(host_key, sig, node);
				m_ThreadStats.new_flow++;
				m_ThreadStats.reuse_flow++;
				flow_infos = &node->infos;
			} else {
				// нет просроченных записей, надо создавать новую...
				node = fs_ipv4->newFlow();
				if(likely(node != nullptr))
				{
					node->init(timestamp, _worker_id, _worker_id, 0, 0);
					node->src_addr_t.ipv4_srcaddr = pkt_infos->src_addr_t.ipv4_srcaddr;
					node->dst_addr_t.ipv4_dstaddr = pkt_infos->dst_addr_t.ipv4_dstaddr;
					node->srcport = pkt_infos->srcport;
					node->dstport = pkt_infos->dstport;
					node->l4prot = pkt_infos->l4prot;
					dpi_init_flow_infos(dpi_state, &(node->infos), pkt_infos->l4prot);
					node->cmn.alfs_type = alfs_type;
					if(unlikely(fs_ipv4->addFlow(host_key, sig, node)))
					{
						m_ThreadStats.hash_add_fail_flow++;
						if(m_ThreadStats.hash_add_fail_flow % 100000 == 0)
							_logger.error("Can't add flow to the hash");
					}

					if(likely(fs_ipv4->short_alfs.can_add_rec() && fs_ipv4->long_alfs.can_add_rec()))
					{
						fs_ipv4->short_alfs.add_rec(node);
						uint32_t short_alfs_idx = node->cmn.idx_alfs;
						fs_ipv4->long_alfs.add_rec(node);
						if(short_alfs_idx != node->cmn.idx_alfs)
							_logger.error("idx_alfs not equal: short %d <> long %d", (int)short_alfs_idx, (int) node->cmn.idx_alfs);
						m_ThreadStats.new_flow++;
					} else {
						m_ThreadStats.alfs_fail_flow++;
						if(m_ThreadStats.alfs_fail_flow % 100000 == 0)
							_logger.error("Can't add ipv4 flow to the alfs!");
					}
					flow_infos = &node->infos;
				} else {
					m_ThreadStats.error_alloc_flow++;
					if(m_ThreadStats.error_alloc_flow % 100000 == 0)
					{
						_logger.error("Unable to allocate flow record. Repeat error %" PRIu64, m_ThreadStats.error_alloc_flow);
					}
				}
			}
		} else {
			if(unlikely(pkt_infos->l4prot == IPPROTO_TCP && node->infos.tracking.seen_rst && ((struct tcphdr*) (pkt_infos->pkt + pkt_infos->l4offset))->syn))
			{
				// recycling flow, reset all data for dpi.
				m_ThreadStats.recycling_flow++;
				node->free_mem(dpi_state->flow_cleaner_callback);
				node->init(timestamp, node->cmn.owner_worker_id, _worker_id, node->cmn.idx_alfs, node->cmn.hash_idx);
				node->src_addr_t.ipv4_srcaddr = pkt_infos->src_addr_t.ipv4_srcaddr;
				node->dst_addr_t.ipv4_dstaddr = pkt_infos->dst_addr_t.ipv4_dstaddr;
				node->srcport = pkt_infos->srcport;
				node->dstport = pkt_infos->dstport;
				node->l4prot = pkt_infos->l4prot;
				dpi_init_flow_infos(dpi_state, &(node->infos), pkt_infos->l4prot);
			} else {
				if(node->src_addr_t.ipv4_srcaddr == pkt_infos->src_addr_t.ipv4_srcaddr && node->srcport == pkt_infos->srcport)
					pkt_infos->direction=0;
				else
					pkt_infos->direction=1;
			}
			node->cmn.alfs_type = alfs_type;
			fs_ipv4->short_alfs.moveBack(node, timestamp, &fs_ipv4->long_alfs);
			flow_infos = &node->infos;
		}
	} else if(pkt_infos->ip_version == 6)
	{
		fs_ipv6 = (FlowStorageIPV6 *) worker_params[_worker_id].flows_ipv6.flows[ipv6_flow_mask & sig];
		node_ipv6 = fs_ipv6->searchFlow(host_key, sig, pkt_infos, &hash_idx);
		if(node_ipv6 == nullptr)
		{
			if(tcph != nullptr)
			{
				// проверяем флаги tcp. этих flow нет в кэше, поэтому пропускаем ничего не делая
				// rst - нечего завершать, т.к. dpi не знает flow
				// syn+ack - нечего подтверждать, т.к. нет flow
				//if(tcph->rst || (tcph->ack && tcph->syn))
				if(tcph->rst || (tcph->ack && tcph->syn) || tcph->fin)
//				if(tcph->rst || tcph->fin)
				{
					m_ThreadStats.no_create_flow_ipv6++;
					return r;
				}
			}
			pkt_infos->direction=0;
			if((node_ipv6 = fs_ipv6->short_alfs.getOldestMoveBack(timestamp, &fs_ipv6->long_alfs)) != nullptr || (node_ipv6 = fs_ipv6->long_alfs.getOldestMoveBack(timestamp, &fs_ipv6->short_alfs)) != nullptr)
			{
				// есть просроченная запись...
				// очищаем всю память, занятую ранее...
				node_ipv6->free_mem(dpi_state->flow_cleaner_callback);
				// надо удалить по ключу из старой записи...
				fs_ipv6->removeFlow(node_ipv6->cmn.hash_idx);
				node_ipv6->init(timestamp, node_ipv6->cmn.owner_worker_id, _worker_id, node_ipv6->cmn.idx_alfs, node_ipv6->cmn.hash_idx);
				rte_memcpy(&node_ipv6->src_addr_t.ipv6_srcaddr, &pkt_infos->src_addr_t.ipv6_srcaddr, IPV6_ADDR_LEN * 2);
				node_ipv6->srcport = pkt_infos->srcport;
				node_ipv6->dstport = pkt_infos->dstport;
				node_ipv6->l4prot = pkt_infos->l4prot;
				dpi_init_flow_infos(dpi_state, &(node_ipv6->infos), pkt_infos->l4prot);
				node_ipv6->cmn.alfs_type = alfs_type;

				fs_ipv6->reuseFlow(host_key, sig, node_ipv6);
				m_ThreadStats.new_flow_ipv6++;
				m_ThreadStats.reuse_flow_ipv6++;
				flow_infos = &node_ipv6->infos;
			} else {
				// нет просроченных записей, надо создавать новую...
				node_ipv6 = fs_ipv6->newFlow();
				if(likely(node_ipv6 != nullptr))
				{
					node_ipv6->init(timestamp, _worker_id, _worker_id, 0, 0);
					rte_memcpy(&node_ipv6->src_addr_t.ipv6_srcaddr, &pkt_infos->src_addr_t.ipv6_srcaddr, IPV6_ADDR_LEN * 2);
					node_ipv6->srcport = pkt_infos->srcport;
					node_ipv6->dstport = pkt_infos->dstport;
					node_ipv6->l4prot = pkt_infos->l4prot;
					dpi_init_flow_infos(dpi_state, &(node_ipv6->infos), pkt_infos->l4prot);
					node_ipv6->cmn.alfs_type = alfs_type;

					if(unlikely(fs_ipv6->addFlow(host_key, sig, node_ipv6)))
					{
						m_ThreadStats.hash_add_fail_flow_ipv6++;
						if(m_ThreadStats.hash_add_fail_flow_ipv6 % 100000 == 0)
							_logger.error("Can't add ipv6 flow to the hash");
					}

					if(unlikely(fs_ipv6->short_alfs.can_add_rec() && fs_ipv6->long_alfs.can_add_rec()))
					{
						fs_ipv6->short_alfs.add_rec(node_ipv6);
						uint32_t short_alfs_idx = node_ipv6->cmn.idx_alfs;
						fs_ipv6->long_alfs.add_rec(node_ipv6);
						if(short_alfs_idx != node_ipv6->cmn.idx_alfs)
							_logger.error("idx_alfs not equal: short %d <> long %d", (int)short_alfs_idx, (int) node_ipv6->cmn.idx_alfs);
						m_ThreadStats.new_flow_ipv6++;
					} else {
						m_ThreadStats.alfs_fail_flow_ipv6++;
						if(m_ThreadStats.alfs_fail_flow_ipv6 % 100000 == 0)
							_logger.error("Can't add ipv6 flow to the alfs!");
					}
					flow_infos = &node_ipv6->infos;
				} else {
					m_ThreadStats.error_alloc_flow_ipv6++;
					if(m_ThreadStats.error_alloc_flow_ipv6 % 100000 == 0)
					{
						_logger.error("Unable to allocate flow ipv6 record. Repeat error %" PRIu64, m_ThreadStats.error_alloc_flow_ipv6);
					}
				}
			}
		} else {
			if(pkt_infos->l4prot == IPPROTO_TCP && node_ipv6->infos.tracking.seen_rst && ((struct tcphdr*) (pkt_infos->pkt + pkt_infos->l4offset))->syn)
			{
				// recycling flow, reset all data for dpi.
				m_ThreadStats.recycling_flow_ipv6++;
				node_ipv6->free_mem(dpi_state->flow_cleaner_callback);
				node_ipv6->init(timestamp, node_ipv6->cmn.owner_worker_id, _worker_id, node_ipv6->cmn.idx_alfs, node_ipv6->cmn.hash_idx);
				rte_memcpy(&node_ipv6->src_addr_t.ipv6_srcaddr, &pkt_infos->src_addr_t.ipv6_srcaddr, IPV6_ADDR_LEN * 2);
				node_ipv6->srcport = pkt_infos->srcport;
				node_ipv6->dstport = pkt_infos->dstport;
				node_ipv6->l4prot = pkt_infos->l4prot;
				dpi_init_flow_infos(dpi_state, &(node_ipv6->infos), pkt_infos->l4prot);
			} else {
				if(ext_dpi_v6_addresses_equal((uint64_t *)&(node_ipv6->src_addr_t.ipv6_srcaddr),(uint64_t *) &pkt_infos->src_addr_t.ipv6_srcaddr) && node_ipv6->srcport == pkt_infos->srcport)
					pkt_infos->direction=0;
				else
					pkt_infos->direction=1;
			}
			node_ipv6->cmn.alfs_type = alfs_type;
			fs_ipv6->short_alfs.moveBack(node_ipv6, timestamp, &fs_ipv6->long_alfs);
			flow_infos = &node_ipv6->infos;
		}
	}
	if(unlikely(flow_infos == nullptr))
	{
		_logger.error("Unable to extract flow_infos");
		r.status = DPI_ERROR_MAX_FLOWS;
		return r;
	}

	r = dpi_stateless_get_app_protocol(dpi_state, flow_infos, pkt_infos);

	if(pkt_infos->ip_version == 4)
	{
		if(unlikely(_need_block))
		{
			node->cmn.blocked = true;
		} else {
			if(unlikely(node->cmn.blocked && pkt_infos->data_length > 0))
			{
				switch (r.protocol.l7prot)
				{
					case DPI_PROTOCOL_TCP_SSL:
						_snd->SendRSTIPv4(pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
						m_ThreadStats.seen_already_blocked_ssl_ipv4++;
						m_ThreadStats.sended_rst_ipv4++;
						break;
					case DPI_PROTOCOL_TCP_HTTP:
						_snd->SendRSTIPv4(pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
						m_ThreadStats.seen_already_blocked_http_ipv4++;
						m_ThreadStats.sended_rst_ipv4++;
						break;
					default:
						break;
				}
				
			}
		}
	} else if (pkt_infos->ip_version == 6)
	{
		if(unlikely(_need_block))
		{
			node_ipv6->cmn.blocked = true;
		} else {
			if(unlikely(node_ipv6->cmn.blocked && pkt_infos->data_length > 0))
			{
				switch (r.protocol.l7prot)
				{
					case DPI_PROTOCOL_TCP_SSL:
						_snd->SendRSTIPv6(pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
						m_ThreadStats.seen_already_blocked_ssl_ipv6++;
						m_ThreadStats.sended_rst_ipv6++;
						break;
					case DPI_PROTOCOL_TCP_HTTP:
						_snd->SendRSTIPv6(pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
						m_ThreadStats.seen_already_blocked_http_ipv6++;
						m_ThreadStats.sended_rst_ipv6++;
						break;
					default:
						break;
				}
			}
		}
	}

	if(r.status == DPI_STATUS_TCP_CONNECTION_TERMINATED)
	{
		if(pkt_infos->ip_version == 4)
		{
			m_ThreadStats.close_flow++;
			node->free_mem(dpi_state->flow_cleaner_callback);
			node->init(timestamp, node->cmn.owner_worker_id, _worker_id, node->cmn.idx_alfs, node->cmn.hash_idx);
			node->cmn.alfs_type = alfs_type;
			fs_ipv4->short_alfs.moveBack(node, timestamp, &fs_ipv4->long_alfs);
		} else {
			m_ThreadStats.close_flow_ipv6++;
			node_ipv6->free_mem(dpi_state->flow_cleaner_callback);
			node_ipv6->init(timestamp, node_ipv6->cmn.owner_worker_id, _worker_id, node_ipv6->cmn.idx_alfs, node_ipv6->cmn.hash_idx);
			node_ipv6->cmn.alfs_type = alfs_type;
			fs_ipv6->short_alfs.moveBack(node_ipv6, timestamp, &fs_ipv6->long_alfs);
		}
	}
	return r;
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
		}
	} else {
		return false;
	}

	m_ThreadStats.ip_packets++;

	uint32_t acl_action = pkt_info->acl_res & ACL_POLICY_MASK;

	uint8_t ip_protocol=(ip_version == 4 ? ipv4_header->next_proto_id : ipv6_header->proto);

	if(unlikely(acl_action == ACL::ACL_DROP && ip_protocol != IPPROTO_TCP && global_prm->operation_mode == OP_MODE_INLINE))
	{
		return true;
	}
	if(ip_protocol != IPPROTO_TCP)
	{
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


	if(unlikely(payload_len > 0 && acl_action == ACL::ACL_DROP))
	{
		m_ThreadStats.matched_ip_port++;
		dpi_pkt_infos_t pkt_infos;
		pkt_infos.pkt = l3;
		pkt_infos.l2_pkt = rte_pktmbuf_mtod(m, const uint8_t *);
		if(ip_version == 4)
		{
			_snd->SendRSTIPv4(&pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
			m_ThreadStats.sended_rst_ipv4++;
		}
		else
		{
			_snd->SendRSTIPv6(&pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
			m_ThreadStats.sended_rst_ipv6++;
		}
		return true;
	}

	dpi_identification_result_t r;

	r = identifyAppProtocol(l3, ip_len, rte_pktmbuf_mtod(m, const uint8_t *), timestamp, (struct packet_info *)m->userdata, m->hash.usr);

	switch (r.protocol.l7prot)
	{
		case DPI_PROTOCOL_TCP_SSL:
				m_ThreadStats.ssl_packets++;
				break;
		case DPI_PROTOCOL_TCP_HTTP:
				m_ThreadStats.http_packets++;
				break;
		default:
			break;
	}

	if(unlikely(_need_block))
		return true;

	if(payload_len == 0)
		return false;

	if(unlikely(r.protocol.l7prot == DPI_PROTOCOL_TCP_SSL && m_WorkerConfig.block_ssl_no_sni && acl_action == ACL::ACL_SSL))
	{
		m_ThreadStats.matched_ssl_ip++;
		dpi_pkt_infos_t pkt_infos;
		pkt_infos.pkt = l3;
		pkt_infos.l2_pkt = rte_pktmbuf_mtod(m, const uint8_t *);
		if(ip_version == 4)
		{
			_snd->SendRSTIPv4(&pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
			m_ThreadStats.sended_rst_ipv4++;
		}
		else
		{
			_snd->SendRSTIPv6(&pkt_infos, /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq);
			m_ThreadStats.sended_rst_ipv6++;
		}
		return true;
	}

//	if(r.protocol.l7prot == DPI_PROTOCOL_TCP_HTTP && !uri.empty())
//	{
//		if(m_WorkerConfig.notify_enabled && m_WorkerConfig.nm && ip_version == 4 && acl_action == ACL::ACL_NOTIFY)
//		{
//			uint32_t notify_group = (pkt_info->acl_res & ACL_NOTIFY_GROUP) >> 4;
//			if(m_WorkerConfig.nm->needNotify(ipv4_header->src_addr, notify_group))
//			{
//				std::string add_param;
//				NotifyManager::queue.enqueueNotification(new NotifyRedirect(notify_group, tcp_src_port, tcp_dst_port, ip_version == 4 ? (void *)&ipv4_header->src_addr : (void *)&ipv6_header->src_addr, ip_version == 4 ? (void *)&ipv4_header->dst_addr : (void *)&ipv6_header->dst_addr, ip_version, /*acknum*/ tcph->ack_seq, /*seqnum*/ rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->seq)+payload_len), 1, (char *)add_param.c_str()));
//				return true;
//			}
//		}
//	}

	return false;
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

	m_Stop = false;
	struct rte_mbuf *buf;

	const uint64_t timer_interval = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * (1000*1000);

	uint64_t last_sec = 0;

	uint64_t cur_tsc, diff_timer_tsc;
	uint64_t prev_timer_tsc = 0;

	uint8_t sender_port = m_WorkerConfig.sender_port;
	uint16_t tx_queue_id = m_WorkerConfig.tx_queue_id;

	_logger.debug("Starting working thread on core %u", coreId);

	for (int i = 0; i < qconf->n_rx_queue; i++)
	{
		portid = qconf->rx_queue_list[i].port_id;
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

			struct ACL::acl_search_t acl_search;

			prepare_acl_parameter(bufs, &acl_search, nb_rx, &_pkt_infos[0]);

			if(likely(qconf->cur_acx_ipv4 && acl_search.num_ipv4))
			{
				rte_acl_classify(qconf->cur_acx_ipv4, acl_search.data_ipv4, acl_search.res_ipv4, acl_search.num_ipv4, DEFAULT_MAX_CATEGORIES);
				for(int acli=0; acli < acl_search.num_ipv4; acli++)
				{
					if(unlikely(acl_search.res_ipv4[acli] != 0))
					{
						((struct packet_info *)acl_search.m_ipv4[acli]->userdata)->acl_res=acl_search.res_ipv4[acli];
					}
				}
			}

			if(qconf->cur_acx_ipv6 && acl_search.num_ipv6)
			{
				rte_acl_classify(qconf->cur_acx_ipv6, acl_search.data_ipv6, acl_search.res_ipv6, acl_search.num_ipv6, DEFAULT_MAX_CATEGORIES);
				for(int acli=0; acli < acl_search.num_ipv6; acli++)
				{
					if(unlikely(acl_search.res_ipv6[acli] != 0))
					{
						((struct packet_info *)acl_search.m_ipv6[acli]->userdata)->acl_res=acl_search.res_ipv6[acli];
					}
				}
			}

			uint64_t cycles = 0;
			uint64_t blocked_cycles = 0;
			uint64_t unblocked_cycles = 0;
			for(uint16_t i = 0; i < nb_rx; i++)
			{
				buf = bufs[i];
				rte_prefetch0(rte_pktmbuf_mtod(buf, void *));
				if(likely(buf->userdata && port_type == P_TYPE_SUBSCRIBER))
				{
					bool need_block = analyzePacket(buf, last_sec);
					uint64_t now = rte_rdtsc();
					if(need_block)
					{
						blocked_cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
						m_ThreadStats.latency_counters.blocked_pkts++;
					} else {
						unblocked_cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
						m_ThreadStats.latency_counters.unblocked_pkts++;
					}
					cycles += now - ((struct packet_info *)buf->userdata)->timestamp;
				}
				rte_pktmbuf_free(buf);
			}
			m_ThreadStats.latency_counters.total_cycles += cycles;
			m_ThreadStats.latency_counters.blocked_cycles += blocked_cycles;
			m_ThreadStats.latency_counters.unblocked_cycles += unblocked_cycles;
			m_ThreadStats.latency_counters.total_pkts += nb_rx;
			if(unlikely(_n_send_pkts != 0))
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
