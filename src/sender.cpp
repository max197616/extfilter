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
#include "sender.h"
#include <unistd.h>
#include <netinet/ip6.h>
#include <Poco/FileStream.h>
#include <rte_config.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <memory>
#include <iostream>
#include "worker.h"

struct pseudo_header
{
	u_int32_t	source_address;
	u_int32_t	dest_address;
	u_int8_t	placeholder;
	u_int8_t	protocol;
	u_int16_t	tcp_length;
};

struct ipv6_pseudo_hdr
{
	struct in6_addr source_address;
	struct in6_addr dest_address;
	u_int32_t tcp_length;
	u_int32_t  zero: 24,
		   nexthdr: 8;
};

BSender::BSender(const char *cn, struct params &prm) : _logger(Poco::Logger::get(cn)), _parameters(prm)
{
	this->rHeader = "HTTP/1.1 "+_parameters.code+"\r\nLocation: " + _parameters.redirect_url + "\r\nConnection: close\r\n\r\n";
	_logger.debug("Default header is %s", rHeader);
	pkt_id = 1;
}

BSender::~BSender()
{

}

int BSender::makePacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh, uint8_t *buffer)
{
	int pkt_len;
	pkt_id++;

	// IP header
	struct iphdr *iph = (struct iphdr *) buffer;
	struct ip6_hdr *iph6 = (struct ip6_hdr *) buffer;

	// TCP header
	struct tcphdr *tcph = (struct tcphdr *) (buffer + (ip_ver == 4 ? sizeof(struct iphdr) : sizeof(struct ip6_hdr)));

	int payloadlen=dt.size();
	// Data part
	uint8_t *data = (uint8_t *)tcph + sizeof(struct tcphdr);

	if(!dt.empty())
		rte_memcpy(data, dt.c_str(), payloadlen);

	if(_logger.getLevel() == Poco::Message::PRIO_DEBUG)
	{
		Poco::Net::IPAddress ipa(ip_to, ip_ver == 4 ? sizeof(in_addr) : sizeof(in6_addr));
		_logger.debug("Trying to send packet to %s port %d", ipa.toString(), port_to);
	}
	if(ip_ver == 4)
	{
		// Fill the IPv4 header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos=0;
		iph->tot_len = rte_cpu_to_be_16(sizeof(struct iphdr) + sizeof(struct tcphdr) + payloadlen);
		iph->id = rte_cpu_to_be_16(pkt_id);
		iph->frag_off = 0;
		iph->ttl = _parameters.ttl;
		iph->protocol = IPPROTO_TCP;
		iph->check = 0;
		iph->saddr = ((in_addr *)ip_from)->s_addr;
		iph->daddr = ((in_addr *)ip_to)->s_addr;;
		pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payloadlen;
	} else {
		// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
		iph6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
		// Payload length (16 bits): TCP header + TCP data
		iph6->ip6_plen = rte_cpu_to_be_16 (sizeof(struct tcphdr) + payloadlen);
		// Next header (8 bits): 6 for TCP
		iph6->ip6_nxt = IPPROTO_TCP;
		 // Hop limit (8 bits): default to maximum value
		iph6->ip6_hops = 250;
		rte_mov16((uint8_t *)&iph6->ip6_src, (uint8_t *)ip_from);
		rte_mov16((uint8_t *)&iph6->ip6_dst, (uint8_t *)ip_to);
		pkt_len = (sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + payloadlen);
	}

	// TCP Header
	tcph->source = port_from;
	tcph->dest = port_to;
	tcph->seq = acknum;
	tcph->doff = 5;
	tcph->syn = 0;
	tcph->res1 = 0;
	tcph->res2 = 0;
	tcph->rst = f_reset;
	tcph->psh = f_psh;
	if(f_reset)
	{
		tcph->ack = 1;
		tcph->ack_seq = seqnum;
		tcph->fin = 0;
		tcph->window = rte_cpu_to_be_16(0xEF);
	} else {
		tcph->ack_seq = seqnum;
		tcph->ack = 1;
		tcph->fin = 1;
		tcph->window = rte_cpu_to_be_16(5885);
	}
	tcph->urg = 0;
	tcph->check = 0;
	tcph->urg_ptr = 0;

	if(ip_ver == 4)
		tcph->check = rte_ipv4_udptcp_cksum((const ipv4_hdr*)iph,tcph);
	else
		tcph->check = rte_ipv6_udptcp_cksum((const ipv6_hdr*)iph6,tcph);
	return pkt_len;
}

void BSender::sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh)
{
	uint8_t datagram[4096];

	int pkt_len = makePacket(ip_from, ip_to, ip_ver, port_from, port_to, acknum, seqnum, dt, f_reset, f_psh, &datagram[0]);

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
			Poco::Net::IPAddress ipa(ip_to, ip_ver == 4 ? sizeof(in_addr) : sizeof(in6_addr));
			_logger.error("sendto() failed to %s:%d errno: %d",ipa.toString(), port_to, errno);
		}
	} else {
		// Send the packet
		if(Send((uint8_t *)&datagram, pkt_len, (struct sockaddr *)&sin6, sizeof(sin6)) < 0 )
		{
			Poco::Net::IPAddress ipa(ip_to, ip_ver == 4 ? sizeof(in_addr) : sizeof(in6_addr));
			Poco::Net::IPAddress ipb(ip_from, ip_ver == 4 ? sizeof(in_addr) : sizeof(in6_addr));
			_logger.error("sendto() failed to [%s]:%d from [%s]:%d errno: %d", ipa.toString(), ntohs(port_to), ipb.toString(), ntohs(port_from), errno);
		}
	}

	return;
}

void BSender::Redirect(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh, const char *additional_param)
{
	// формируем дополнительные параметры
	std::string tstr = rHeader;
	if(additional_param != nullptr && additional_param[0] == '@' && (tstr.length() < (_parameters.mtu - (ip_ver == 4 ? sizeof(struct iphdr) : sizeof(struct ip6_hdr)) + sizeof(struct tcphdr) - sizeof(struct ether_hdr))))
	{
		tstr.assign(additional_param+1);
	} else {
		if(additional_param != nullptr && _parameters.redirect_url[_parameters.redirect_url.length()-1] == '?' && (tstr.length() < (_parameters.mtu - (ip_ver == 4 ? sizeof(struct iphdr) : sizeof(struct ip6_hdr)) + sizeof(struct tcphdr) - sizeof(struct ether_hdr))))
		{
			tstr = "HTTP/1.1 "+_parameters.code+"\r\nLocation: " + _parameters.redirect_url + additional_param + "\r\nConnection: close\r\n\r\n";
		}
	}
	this->sendPacket(dst_ip, user_ip, ip_ver, dst_port, user_port, acknum, seqnum, tstr, 0, f_psh);
	
	// And reset session with server
	if(_parameters.send_rst_to_server)
	{
		std::string empty_str;
		this->sendPacket(user_ip, dst_ip, ip_ver, user_port, dst_port, seqnum, acknum, empty_str, 1, 0);
	}
	return;
}



void BSender::SendRST(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh)
{
	std::string empty_str;
	// send rst to the client
	this->sendPacket(dst_ip, user_ip, ip_ver, dst_port, user_port, acknum, seqnum, empty_str, 1, 0);
	// send rst to the server
	if(_parameters.send_rst_to_server)
		this->sendPacket(user_ip, dst_ip, ip_ver, user_port, dst_port, seqnum, acknum, empty_str, 1, 0);
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
	memcpy(&_eth_hdr.s_addr, mac, 6);
	memcpy(&_eth_hdr.d_addr, to_mac, 6);
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

ESender::ESender(struct nparams &prm, uint8_t port, struct rte_mempool *mp, WorkerThread *wt) : BSender("ESender", prm.params),
	_port(port),
	_mp(mp),
	_wt(wt)
{
	memcpy(&_eth_hdr.s_addr, prm.mac, 6);
	memcpy(&_eth_hdr.d_addr, prm.to_mac, 6);
}

ESender::~ESender()
{
	
}

void ESender::sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh)
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

	int pkt_len = makePacket(ip_from, ip_to, ip_ver, port_from, port_to, acknum, seqnum, dt, f_reset, f_psh, pkt_buf) + sizeof(struct ether_hdr);
	pkt->data_len = pkt_len;
	pkt->pkt_len = pkt_len;
	rte_memcpy(eth_hdr, &_eth_hdr, sizeof(struct ether_hdr));
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
		_wt->_n_send_pkts += 1;
	} else {
		_logger.error("Can't send packet. Buffer is full.");
		rte_pktmbuf_free(pkt);
		return;
	}

	return;
}

