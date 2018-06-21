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

#include "sender.h"
#include <unistd.h>
#include <Poco/FileStream.h>
#include <memory>
#include <iostream>
#include "worker.h"

BSender::BSender(const char *cn, struct params &prm) : _logger(Poco::Logger::get(cn)), _parameters(prm)
{
	pkt_id = 1;
}

BSender::~BSender()
{

}


void BSender::sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, int f_reset, int f_psh)
{
	uint8_t datagram[4096];

	int pkt_len = makePacket(ip_from, ip_to, ip_ver, port_from, port_to, acknum, seqnum, dt_buf, dt_len, f_reset, f_psh, &datagram[0]);

	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	if(ip_ver == 4)
	{
		sin.sin_family = AF_INET;
		sin.sin_port = port_to;
		sin.sin_addr.s_addr = ((in_addr *)ip_to)->s_addr;
	} else {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = 0; // not filled in ipv6
		rte_mov16((uint8_t *)&sin6.sin6_addr, (uint8_t *)ip_to);
	}

	if(ip_ver == 4)
	{
		// Send the packet
		if(Send((uint8_t *)&datagram, pkt_len,(struct sockaddr *)&sin, sizeof(sin)) < 0 )
		{
			Poco::Net::IPAddress ipa(ip_to, sizeof(in_addr));
			_logger.error("sendto() failed to %s:%d errno: %d",ipa.toString(), port_to, errno);
		}
	} else {
		// Send the packet
		if(Send((uint8_t *)&datagram, pkt_len, (struct sockaddr *)&sin6, sizeof(sin6)) < 0 )
		{
			Poco::Net::IPAddress ipa(ip_to, sizeof(in6_addr));
			Poco::Net::IPAddress ipb(ip_from, sizeof(in6_addr));
			_logger.error("sendto() failed to [%s]:%d from [%s]:%d errno: %d", ipa.toString(), ntohs(port_to), ipb.toString(), ntohs(port_from), errno);
		}
	}

	return;
}


void BSender::HTTPRedirect(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh, const char *redir_url, size_t r_len)
{
	char payload[OUR_PAYLOAD_SIZE];
	size_t payload_size = sizeof(f_lines) - 1;
	const char *payload_ptr = f_lines;
	if(redir_url != nullptr && r_len + OUR_REDIR_SIZE < OUR_PAYLOAD_SIZE)
	{
		rte_memcpy(payload, r_line1, sizeof(r_line1)-1);
		rte_memcpy(payload + sizeof(r_line1) - 1, r_line2, sizeof(r_line2) -1);
		rte_memcpy(payload + sizeof(r_line1) - 1 + sizeof(r_line2) - 1 , redir_url, r_len);
		rte_memcpy(payload + sizeof(r_line1) - 1 + sizeof(r_line2) - 1 + r_len, r_line3, sizeof(r_line3) - 1);
		payload_size = sizeof(r_line1) - 1 + sizeof(r_line2) - 1 + sizeof(r_line3) - 1 + r_len;
		payload_ptr = payload;
	}
	this->sendPacket(dst_ip, user_ip, ip_ver, dst_port, user_port, acknum, seqnum, payload_ptr, payload_size, 0, f_psh);
//	sendPacket(dst_ip, user_ip, ip_ver, dst_port, user_port, rte_cpu_to_be_32(rte_be_to_cpu_32(acknum) + payload_size), 0,  nullptr, 0, 1, 0); // send rst...
	// And reset session with server, if needed
	if(_parameters.send_rst_to_server)
		this->sendPacket(user_ip, dst_ip, ip_ver, user_port, dst_port, seqnum, acknum, nullptr, 0, 1, 0);
}

void BSender::HTTPForbidden(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh)
{
	this->sendPacket(dst_ip, user_ip, ip_ver, dst_port, user_port, acknum, seqnum, f_lines, sizeof(f_lines) - 1, 0, f_psh);
	// And reset session with server, if needed
	if(_parameters.send_rst_to_server)
	{
		this->sendPacket(user_ip, dst_ip, ip_ver, user_port, dst_port, seqnum, acknum, nullptr, 0, 1, 0);
	}
}

void BSender::SendRST(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh)
{
	// send rst to the client
	this->sendPacket(dst_ip, user_ip, ip_ver, dst_port, user_port, acknum, seqnum, nullptr, 0, 1, 0);
	// send rst to the server
	if(_parameters.send_rst_to_server)
		this->sendPacket(user_ip, dst_ip, ip_ver, user_port, dst_port, seqnum, acknum, nullptr, 0, 1, 0);
}

CSender::CSender(struct params &prm) : BSender("CSender", prm)
{
	this->s = ::socket( PF_INET, SOCK_RAW, IPPROTO_RAW );
	if( s == -1 ) {
		_logger.error("Failed to create IPv4 socket!");
		return;
	}
	this->s6 = ::socket( PF_INET6, SOCK_RAW, IPPROTO_RAW );
	if( s6 == -1 ) {
		_logger.error("Failed to create IPv6 socket!");
		return;
	}

	int one = 1;
	const int *val = &one;
	if( ::setsockopt(this->s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
	{
		_logger.error("Error setting IP_HDRINCL for IPv4 socket");
		return;
	}

}

CSender::~CSender()
{
	::close(s);
	::close(s6);
}


int CSender::Send(uint8_t *buffer, int size, void *addr, int addr_size)
{
	if(addr_size == sizeof(sockaddr_in))
	{
		return ::sendto(this->s, buffer, size, 0, (struct sockaddr *)addr, addr_size);
	} else {
		return ::sendto(this->s6, buffer, size, 0, (struct sockaddr *)&addr, addr_size);
	}
}


DSender::DSender(struct BSender::params &prm, uint8_t port, uint8_t *mac, uint8_t *to_mac, struct rte_mempool *mp) : BSender("DSender", prm),
	_port(port),
	_mp(mp)
{
	rte_memcpy(&_eth_hdr.s_addr, mac, 6);
	rte_memcpy(&_eth_hdr.d_addr, to_mac, 6);
}

DSender::~DSender()
{
	
}

int DSender::Send(uint8_t *buffer, int size, void *addr, int addr_size)
{
	struct rte_mbuf *pkt;
	pkt = rte_pktmbuf_alloc(_mp);
	if(pkt == nullptr)
	{
		_logger.error("Unable to allocate buffer for the packet");
		return -1;
	}
	int pkt_size = size + sizeof(struct ether_hdr);
	pkt->data_len = pkt_size;
	pkt->pkt_len = pkt_size;
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	rte_memcpy(eth_hdr, &_eth_hdr, sizeof(struct ether_hdr));
	if(addr_size == sizeof(sockaddr_in))
	{
		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
		struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) buffer;
		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	} else {
		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
	}
	char *data = ((char *)eth_hdr + sizeof(struct ether_hdr));
	rte_memcpy(data, buffer, size);
	if(rte_eth_tx_burst(_port, 0, &pkt, 1) != 1)
	{
		_logger.error("Unable to send packet with size %d to port %d", pkt_size, (int) _port);
		rte_pktmbuf_free(pkt);
		return -1;
	}
	return pkt_size;
}

ESender::ESender(struct nparams &prm, uint8_t port, struct rte_mempool *mp, WorkerThread *wt, bool keep_l2_hdr) : BSender("ESender", prm.params),
	_port(port),
	_mp(mp),
	_clone_pool(prm.clone_pool),
	_wt(wt),
	_answer_duplication(prm.answer_duplication),
	_keep_l2_hdr(keep_l2_hdr)
{
	rte_memcpy(&_eth_hdr.s_addr, prm.mac, 6);
	rte_memcpy(&_eth_hdr.d_addr, prm.to_mac, 6);
	_eth_hdr.ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	rte_memcpy(&_eth_hdr_ipv6.s_addr, prm.mac, 6);
	rte_memcpy(&_eth_hdr_ipv6.d_addr, prm.to_mac, 6);
	_eth_hdr_ipv6.ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
}

ESender::~ESender()
{
	
}

void ESender::sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, int f_reset, int f_psh)
{
	pkt_id++;
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(_mp);
	if(unlikely(pkt == nullptr))
	{
		_logger.error("Unable to allocate buffer for the packet");
		return;
	}
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	uint8_t *pkt_buf = ((uint8_t *)eth_hdr + sizeof(struct ether_hdr));

	int pkt_len = makePacket(ip_from, ip_to, ip_ver, port_from, port_to, acknum, seqnum, dt_buf, dt_len, f_reset, f_psh, pkt_buf) + sizeof(struct ether_hdr);
	pkt->data_len = pkt_len;
	pkt->pkt_len = pkt_len;
	ether_addr_copy(&_eth_hdr.s_addr, &eth_hdr->s_addr);
	ether_addr_copy(&_eth_hdr.d_addr, &eth_hdr->d_addr);
	if(ip_ver == 4)
	{
		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
		struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) pkt_buf;
		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	} else {
		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
	}

	if(likely(_wt->_n_send_pkts < EXTFILTER_WORKER_BURST_SIZE))
	{
		_wt->_sender_buf[_wt->_n_send_pkts] = pkt;
		_wt->_n_send_pkts++;
	} else {
		_logger.error("Can't send packet. Buffer is full.");
		rte_pktmbuf_free(pkt);
		return;
	}
	return;
}


void ESender::sendPacketIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, bool f_reset, bool f_psh, bool to_server)
{
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(_mp);
	if(unlikely(pkt == nullptr))
	{
		_logger.error("Unable to allocate buffer for the packet");
		return;
	}
	makeSwapPacketIPv4(pkt_infos, acknum, seqnum, dt_buf, dt_len, f_reset, f_psh, pkt, to_server);

	if(likely(_wt->_n_send_pkts < EXTFILTER_WORKER_BURST_SIZE))
	{
		if(!_keep_l2_hdr && !to_server && _answer_duplication > 0 && _wt->_n_send_pkts+_answer_duplication < EXTFILTER_WORKER_BURST_SIZE)
		{
			for(uint8_t z = 0; z < _answer_duplication; z++)
			{
				struct rte_mbuf *clone = rte_pktmbuf_clone(pkt, _clone_pool);
				if(clone != nullptr)
				{
					_wt->_sender_buf[_wt->_n_send_pkts] = clone;
					_wt->_sender_buf_flags[_wt->_n_send_pkts] = false;
					_wt->_n_send_pkts++;
				}
				else {
					_logger.error("Unable to create clone packet.");
					break;
				}
			}
		}
		_wt->_sender_buf[_wt->_n_send_pkts] = pkt;
		_wt->_sender_buf_flags[_wt->_n_send_pkts] = to_server;
		_wt->_n_send_pkts++;
		
	} else {
		_logger.error("Can't send packet. Buffer is full.");
		rte_pktmbuf_free(pkt);
		return;
	}
	return;
}

void ESender::sendPacketIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, bool f_reset, bool f_psh, bool to_server)
{
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(_mp);
	if(unlikely(pkt == nullptr))
	{
		_logger.error("Unable to allocate buffer for the packet");
		return;
	}
	makeSwapPacketIPv6(pkt_infos, acknum, seqnum, dt_buf, dt_len, f_reset, f_psh, pkt, to_server);
	if(likely(_wt->_n_send_pkts < EXTFILTER_WORKER_BURST_SIZE))
	{
		if(!_keep_l2_hdr && !to_server && _answer_duplication > 0 && _wt->_n_send_pkts+_answer_duplication < EXTFILTER_WORKER_BURST_SIZE)
		{
			for(uint8_t z = 0; z < _answer_duplication; z++)
			{
				struct rte_mbuf *clone = rte_pktmbuf_clone(pkt, _clone_pool);
				if(clone != nullptr)
				{
					_wt->_sender_buf[_wt->_n_send_pkts] = clone;
					_wt->_sender_buf_flags[_wt->_n_send_pkts] = false;
					_wt->_n_send_pkts++;
				}
				else {
					_logger.error("Unable to create clone packet.");
					break;
				}
			}
		}
		_wt->_sender_buf[_wt->_n_send_pkts] = pkt;
		_wt->_sender_buf_flags[_wt->_n_send_pkts] = to_server;
		_wt->_n_send_pkts++;
	} else {
		_logger.error("Can't send packet. Buffer is full.");
		rte_pktmbuf_free(pkt);
		return;
	}
	return;
}

void ESender::HTTPRedirectIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh, const char *redir_url, size_t r_len)
{
	char payload[OUR_PAYLOAD_SIZE];
	size_t payload_size = sizeof(f_lines) - 1;
	const char *payload_ptr = f_lines;
	if(redir_url != nullptr && r_len + OUR_REDIR_SIZE < OUR_PAYLOAD_SIZE)
	{
		memcpy(payload, r_line1, sizeof(r_line1)-1);
		memcpy(payload + sizeof(r_line1) - 1, r_line2, sizeof(r_line2) -1);
		rte_memcpy(payload + sizeof(r_line1) - 1 + sizeof(r_line2) - 1 , redir_url, r_len);
		memcpy(payload + sizeof(r_line1) - 1 + sizeof(r_line2) - 1 + r_len, r_line3, sizeof(r_line3) - 1);
		payload_size = sizeof(r_line1) - 1 + sizeof(r_line2) - 1 + sizeof(r_line3) - 1 + r_len;
		payload_ptr = payload;
	}
	sendPacketIPv4(pkt_infos, acknum, seqnum, payload_ptr, payload_size, false, f_psh);
//	sendPacketIPv4(pkt, rte_cpu_to_be_32(rte_be_to_cpu_32(acknum) + payload_size), 0, nullptr, 0, true, false); // send rst...
	// And reset session with server, if needed
	if(_parameters.send_rst_to_server)
		this->sendPacketIPv4(pkt_infos, seqnum, acknum, nullptr, 0, 1, 0, true);
}

void ESender::HTTPForbiddenIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh)
{
	sendPacketIPv4(pkt_infos, acknum, seqnum, f_lines, sizeof(f_lines)-1, 0, f_psh);
	// And reset session with server, if needed
	if(_parameters.send_rst_to_server)
		this->sendPacketIPv4(pkt_infos, seqnum, acknum, nullptr, 0, 1, 0, true);
}

void ESender::HTTPRedirectIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh, const char *redir_url, size_t r_len)
{
	char payload[OUR_PAYLOAD_SIZE];
	size_t payload_size = sizeof(f_lines) - 1;
	const char *payload_ptr = f_lines;
	if(redir_url != nullptr && r_len + OUR_REDIR_SIZE < OUR_PAYLOAD_SIZE)
	{
		memcpy(payload, r_line1, sizeof(r_line1)-1);
		memcpy(payload + sizeof(r_line1) - 1, r_line2, sizeof(r_line2) -1);
		rte_memcpy(payload + sizeof(r_line1) - 1 + sizeof(r_line2) - 1 , redir_url, r_len);
		memcpy(payload + sizeof(r_line1) - 1 + sizeof(r_line2) - 1 + r_len, r_line3, sizeof(r_line3) - 1);
		payload_size = sizeof(r_line1) - 1 + sizeof(r_line2) - 1 + sizeof(r_line3) - 1 + r_len;
		payload_ptr = payload;
	}
	sendPacketIPv6(pkt_infos, acknum, seqnum, payload_ptr, payload_size, false, f_psh);
//	sendPacketIPv6(pkt, rte_cpu_to_be_32(rte_be_to_cpu_32(acknum) + payload_size), 0, nullptr, 0, true, false); // send rst...
	// And reset session with server, if needed
	if(_parameters.send_rst_to_server)
		sendPacketIPv6(pkt_infos, seqnum, acknum, nullptr, 0, 1, 0, true);
}

void ESender::HTTPForbiddenIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh)
{
	sendPacketIPv6(pkt_infos, acknum, seqnum, f_lines, sizeof(f_lines)-1, 0, f_psh);
	// And reset session with server, if needed
	if(_parameters.send_rst_to_server)
		this->sendPacketIPv6(pkt_infos, seqnum, acknum, nullptr, 0, 1, 0, true);
}


void ESender::SendRSTIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum)
{
	// send rst to the client
	sendPacketIPv4(pkt_infos, acknum, seqnum, nullptr, 0, true, false);
	// send rst to the server
	if(_parameters.send_rst_to_server)
		sendPacketIPv4(pkt_infos, seqnum, acknum, nullptr, 0, true, false, true);
}

void ESender::SendRSTIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum)
{
	// send rst to the client
	sendPacketIPv6(pkt_infos, acknum, seqnum, nullptr, 0, true, false);
	// send rst to the server
	if(_parameters.send_rst_to_server)
		sendPacketIPv6(pkt_infos, seqnum, acknum, nullptr, 0, true, false, true);
}
