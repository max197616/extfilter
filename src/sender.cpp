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

	this->rHeader = "HTTP/1.1 "+_parameters.code+"\r\nLocation: " + _parameters.redirect_url + "\r\nConnection: close\r\n";
	_logger.debug("Default header is %s", rHeader);
}

CSender::~CSender()
{
	::close(s);
	::close(s6);
}

void CSender::sendPacket(Poco::Net::IPAddress &ip_from, Poco::Net::IPAddress &ip_to, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh)
{
	char datagram[4096], *data, *pseudogram=NULL;
	
	// zero out the packet buffer
	memset(datagram, 0, sizeof(datagram));
	
	// IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	struct ip6_hdr *iph6 = (struct ip6_hdr *) datagram;

	// TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + (ip_from.family() == Poco::Net::IPAddress::IPv4 ? sizeof(struct iphdr) : sizeof(struct ip6_hdr)));

	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	int payloadlen=dt.size();
	
	// Data part
	data = (char *)tcph + sizeof(struct tcphdr);
	memcpy(data,dt.c_str(),payloadlen);

	_logger.debug("Trying to send packet to %s port %d", ip_to.toString(), port_to);

	if(ip_from.family() == Poco::Net::IPAddress::IPv4)
	{
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port_to);
		sin.sin_addr.s_addr=((in_addr *)ip_to.addr())->s_addr;
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
		iph->saddr = ((in_addr *)ip_from.addr())->s_addr;
		iph->daddr = sin.sin_addr.s_addr;
		// IP checksum
		iph->check = 0; // done by kernel  //this->csum((unsigned short *) datagram, iph->tot_len);
	} else {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = 0; // not filled in ipv6
		memcpy(&sin6.sin6_addr,ip_to.addr(),sizeof(sin6.sin6_addr));
		// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
		iph6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
		// Payload length (16 bits): TCP header + TCP data
		iph6->ip6_plen = htons (sizeof(struct tcphdr) + payloadlen);
		// Next header (8 bits): 6 for TCP
		iph6->ip6_nxt = IPPROTO_TCP;
		 // Hop limit (8 bits): default to maximum value
		iph6->ip6_hops = 250;
		memcpy(&iph6->ip6_src,ip_from.addr(),sizeof(in6_addr));
		memcpy(&iph6->ip6_dst,ip_to.addr(),sizeof(in6_addr));
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
		tcph->window = 0;
	} else {
		tcph->ack_seq = seqnum;
		tcph->ack = 1;
		tcph->fin = 1;
		tcph->window = htons(5840);
	}
	tcph->urg = 0;
	tcph->check = 0;
	tcph->urg_ptr = 0;



	if(ip_from.family() == Poco::Net::IPAddress::IPv4)
	{
		struct pseudo_header psh;
		psh.source_address = ((in_addr *)ip_from.addr())->s_addr;
		psh.dest_address = sin.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct tcphdr) + dt.size() );
	
		int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + dt.size();
		pseudogram = (char*)calloc(1,psize);
	
		memcpy( pseudogram, (char*) &psh, sizeof(struct pseudo_header));
		memcpy( pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + dt.size());
	
		tcph->check = csum( (unsigned short*) pseudogram, psize);
	
		// Send the packet
		if( ::sendto( this->s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0 )
		{
			_logger.error("sendto() failed to %s:%d errno: %d",ip_to.toString(), port_to, errno);
		}
	} else {
		struct ipv6_pseudo_hdr psh;
		// filling pseudoheader...
		memcpy(&psh.source_address,&iph6->ip6_src,sizeof(iph6->ip6_src));
		memcpy(&psh.dest_address,&iph6->ip6_dst,sizeof(iph6->ip6_dst));
		psh.tcp_length = htonl(sizeof(tcphdr) + payloadlen);
		psh.zero = 0;
		psh.nexthdr = iph6->ip6_nxt;
		int psize = sizeof(ipv6_pseudo_hdr) + sizeof(struct tcphdr) + payloadlen;

		pseudogram = (char*)calloc(1,psize);
		memcpy( pseudogram, (char*) &psh, sizeof(struct ipv6_pseudo_hdr));
		memcpy( pseudogram + sizeof(struct ipv6_pseudo_hdr), tcph, sizeof(struct tcphdr) + dt.size());
	
		tcph->check = csum( (unsigned short*) pseudogram, psize);

		// Send the packet
		if( ::sendto( this->s6, datagram, (sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + payloadlen), 0, (struct sockaddr *)&sin6, sizeof(sin6)) < 0 )
		{
			_logger.error("sendto() failed to [%s]:%d errno: %d",ip_to.toString(), port_to, errno);
		}
	}
	if(pseudogram)
		free(pseudogram);

	return;
}

//void CSender::sendPacket(char *ip_from, char *ip_to, int port_from, int port_to, uint32_t acknum, uint32_t seqnum)
void CSender::Redirect(int user_port, int dst_port, Poco::Net::IPAddress &user_ip, Poco::Net::IPAddress &dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh, std::string &additional_param )
{
	// формируем дополнительные параметры
	std::string tstr = rHeader;
	if(!additional_param.empty() && _parameters.redirect_url[_parameters.redirect_url.length()-1] == '?')
	{
		tstr = "HTTP/1.1 "+_parameters.code+"\r\nLocation: " + _parameters.redirect_url + additional_param + "\r\nConnection: close\r\n";
	}
	this->sendPacket(dst_ip, user_ip, dst_port, user_port, acknum, seqnum, tstr, 0, 0);
	
	// And reset session with server
	if(_parameters.send_rst_to_server)
	{
		std::string empty_str;
		this->sendPacket(user_ip, dst_ip, user_port, dst_port, seqnum, acknum, empty_str, 1, f_psh);
	}
	return;
}

void CSender::SendRST(int user_port, int dst_port, Poco::Net::IPAddress &user_ip, Poco::Net::IPAddress &dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh)
{
	std::string empty_str;
	// send rst to the client
	this->sendPacket(dst_ip, user_ip, dst_port, user_port, acknum, seqnum, empty_str, 1, 0);
	// send rst to the server
	if(_parameters.send_rst_to_server)
		this->sendPacket(user_ip, dst_ip, user_port, dst_port, seqnum, acknum, empty_str, 1, 0);
}

unsigned short CSender::csum( unsigned short *ptr, int nbytes )
{
	register long sum;
	unsigned short oddbyte;
	register short answer;
	
	sum = 0;
	while( nbytes > 1 ) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if( nbytes==1 ) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum+(sum>>16);
	answer=(short)~sum;
	
	return( answer );
}
