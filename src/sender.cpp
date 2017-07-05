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
#include <netinet/ip6.h>
#include <Poco/FileStream.h>
#include <rte_config.h>
#include <rte_ip.h>
#include <memory>

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

CSender::CSender(struct params &prm) : _logger(Poco::Logger::get("CSender")), _parameters(prm)
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

	this->rHeader = "HTTP/1.1 "+_parameters.code+"\r\nLocation: " + _parameters.redirect_url + "\r\nConnection: close\r\n\r\n";
	_logger.debug("Default header is %s", rHeader);
}

CSender::~CSender()
{
	::close(s);
	::close(s6);
}

void CSender::sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh)
{
	char datagram[4096], *data;
	
	// zero out the packet buffer
	memset(datagram, 0, sizeof(datagram));
	
	// IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	struct ip6_hdr *iph6 = (struct ip6_hdr *) datagram;

	// TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + (ip_ver == 4 ? sizeof(struct iphdr) : sizeof(struct ip6_hdr)));

	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	int payloadlen=dt.size();
	if(payloadlen > (_parameters.mtu - (ip_ver == 4 ? sizeof(struct iphdr) : sizeof(struct ip6_hdr)) + sizeof(struct tcphdr) - 12))
	{
		_logger.warning("Size of the outgoing packet bigger than the MTU. Removing all additional data in the redirect packet. Payload: %s", dt);
		dt = rHeader;
		payloadlen = rHeader.size();
	}
	// Data part
	data = (char *)tcph + sizeof(struct tcphdr);
	rte_memcpy(data, dt.c_str(), payloadlen);

	if(_logger.getLevel() == Poco::Message::PRIO_DEBUG)
	{
		Poco::Net::IPAddress ipa(ip_to, ip_ver == 4 ? sizeof(in_addr) : sizeof(in6_addr));
		_logger.debug("Trying to send packet to %s port %d", ipa.toString(), port_to);
	}

	if(ip_ver == 4)
	{
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port_to);
		sin.sin_addr.s_addr = ((in_addr *)ip_to)->s_addr;
		// Fill the IPv4 header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos=0;
		iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payloadlen;
		iph->id = htons(random());
		iph->frag_off = 0;
		iph->ttl = _parameters.ttl;
		iph->protocol = IPPROTO_TCP;
		iph->check = 0;
		iph->saddr = ((in_addr *)ip_from)->s_addr;
		iph->daddr = sin.sin_addr.s_addr;
	} else {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = 0; // not filled in ipv6
		rte_mov16((uint8_t *)&sin6.sin6_addr, (uint8_t *)ip_to);
		// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
		iph6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
		// Payload length (16 bits): TCP header + TCP data
		iph6->ip6_plen = htons (sizeof(struct tcphdr) + payloadlen);
		// Next header (8 bits): 6 for TCP
		iph6->ip6_nxt = IPPROTO_TCP;
		 // Hop limit (8 bits): default to maximum value
		iph6->ip6_hops = 250;
		rte_mov16((uint8_t *)&iph6->ip6_src, (uint8_t *)ip_from);
		rte_mov16((uint8_t *)&iph6->ip6_dst, (uint8_t *)ip_to);
	}

	// TCP Header
	tcph->source = htons(port_from);
	tcph->dest = htons(port_to);
	tcph->seq = acknum;
	tcph->doff = 5;
	tcph->syn = 0;
	tcph->rst = f_reset;
	tcph->psh = f_psh;
	if(f_reset)
	{
		tcph->ack = 1;
		tcph->ack_seq = seqnum;
		tcph->fin = 0;
		tcph->window = htons(0xEF);
	} else {
		tcph->ack_seq = seqnum;
		tcph->ack = 1;
		tcph->fin = 1;
		tcph->window = htons(5880);
	}
	tcph->urg = 0;
	tcph->check = 0;
	tcph->urg_ptr = 0;



	if(ip_ver == 4)
	{
		iph->tot_len = rte_cpu_to_be_16(iph->tot_len);
		tcph->check = rte_ipv4_udptcp_cksum((const ipv4_hdr*)iph,tcph);
		iph->tot_len = rte_be_to_cpu_16(iph->tot_len);
		// Send the packet
		if( ::sendto( this->s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0 )
		{
			Poco::Net::IPAddress ipa(ip_to, ip_ver == 4 ? sizeof(in_addr) : sizeof(in6_addr));
			_logger.error("sendto() failed to %s:%d errno: %d",ipa.toString(), port_to, errno);
		}
	} else {
		tcph->check = rte_ipv6_udptcp_cksum((const ipv6_hdr*)iph6,tcph);
		// Send the packet
		if( ::sendto( this->s6, datagram, (sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + payloadlen), 0, (struct sockaddr *)&sin6, sizeof(sin6)) < 0 )
		{
			Poco::Net::IPAddress ipa(ip_to, ip_ver == 4 ? sizeof(in_addr) : sizeof(in6_addr));
			_logger.error("sendto() failed to [%s]:%d errno: %d",ipa.toString(), port_to, errno);
		}
	}

	return;
}

void CSender::Redirect(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh, std::string &additional_param)
{
	// формируем дополнительные параметры
	std::string tstr = rHeader;
	if(!additional_param.empty() && additional_param[0] == '@')
	{
		tstr = additional_param.substr(1, additional_param.length());
	} else {
		if(!additional_param.empty() && _parameters.redirect_url[_parameters.redirect_url.length()-1] == '?')
		{
			tstr = "HTTP/1.1 "+_parameters.code+"\r\nLocation: " + _parameters.redirect_url + additional_param + "\r\nConnection: close\r\n";
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

void CSender::SendRST(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh)
{
	std::string empty_str;
	// send rst to the client
	this->sendPacket(dst_ip, user_ip, ip_ver, dst_port, user_port, acknum, seqnum, empty_str, 1, 0);
	// send rst to the server
	if(_parameters.send_rst_to_server)
		this->sendPacket(user_ip, dst_ip, ip_ver, user_port, dst_port, seqnum, acknum, empty_str, 1, 0);
}


