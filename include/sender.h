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
#ifndef __SENDER_H
#define __SENDER_H

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <errno.h>
#include <stdio.h>
#include <string>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <rte_config.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <netinet/ip6.h>
#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>
#include <api.h>
#include "cfg.h"

class BSender
{
public:
	struct params
	{
		std::string redirect_url;
		std::string code;
		bool send_rst_to_server;
		int ttl;
		int ipv6_hops;
		int mtu;
		params() : code("302 Moved Temporarily"), send_rst_to_server(false), ttl(250), ipv6_hops(250), mtu(1500) { }
	};

	BSender(const char *, struct params &prm);
	virtual ~BSender();

	void HTTPRedirect(int user_port, int dst_port, void *ip_from, void *ip_to, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh, const char *redir_url, size_t p_len);
	void HTTPForbidden(int user_port, int dst_port, void *ip_from, void *ip_to, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh);
	virtual void sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, int f_reset, int f_psh);
	void SendRST(int user_port, int dst_port, void *ip_from, void *ip_to, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh);

	inline int makePacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, int f_reset, int f_psh, uint8_t *buffer)
	{
		int pkt_len;
		pkt_id++;

		// IP header
		struct iphdr *iph = (struct iphdr *) buffer;
		struct ip6_hdr *iph6 = (struct ip6_hdr *) buffer;

		// TCP header
		struct tcphdr *tcph = (struct tcphdr *) (buffer + (ip_ver == 4 ? sizeof(struct iphdr) : sizeof(struct ip6_hdr)));

		// Data part
		uint8_t *data = (uint8_t *)tcph + sizeof(struct tcphdr);

		if(dt_buf != nullptr && dt_len != 0)
			rte_memcpy(data, dt_buf, dt_len);

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
			iph->tot_len = rte_cpu_to_be_16(sizeof(struct iphdr) + sizeof(struct tcphdr) + dt_len);
			iph->id = rte_cpu_to_be_16(pkt_id);
			iph->frag_off = 0;
			iph->ttl = _parameters.ttl;
			iph->protocol = IPPROTO_TCP;
			iph->check = 0;
			iph->saddr = ((in_addr *)ip_from)->s_addr;
			iph->daddr = ((in_addr *)ip_to)->s_addr;;
			pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + dt_len;
		} else {
			// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
			iph6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
			// Payload length (16 bits): TCP header + TCP data
			iph6->ip6_plen = rte_cpu_to_be_16 (sizeof(struct tcphdr) + dt_len);
			// Next header (8 bits): 6 for TCP
			iph6->ip6_nxt = IPPROTO_TCP;
			 // Hop limit (8 bits): default to maximum value
			iph6->ip6_hops = 250;
			rte_mov16((uint8_t *)&iph6->ip6_src, (uint8_t *)ip_from);
			rte_mov16((uint8_t *)&iph6->ip6_dst, (uint8_t *)ip_to);
			pkt_len = (sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + dt_len);
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
			tcph->ack = 0;
			tcph->ack_seq = 0;
			tcph->fin = 0;
			tcph->window = rte_cpu_to_be_16(0xEF);
		} else {
			tcph->ack_seq = seqnum;
			tcph->ack = 1;
			tcph->fin = 1;
			tcph->window = rte_cpu_to_be_16(5885); // TODO get from original packet...
		}
		tcph->urg = 0;
		tcph->check = 0;
		tcph->urg_ptr = 0;

		if(ip_ver == 4)
			tcph->check = rte_ipv4_udptcp_cksum((const ipv4_hdr*)iph, tcph);
		else
			tcph->check = rte_ipv6_udptcp_cksum((const ipv6_hdr*)iph6, tcph);
		return pkt_len;
	}


	virtual int Send(uint8_t *buffer, int size, void *addr, int addr_size) = 0;

	Poco::Logger& _logger;
	struct params _parameters;
	uint16_t pkt_id;
};

class CSender : public BSender
{
public:
	CSender(struct BSender::params &prm);
	~CSender();
	int Send(uint8_t *buffer, int size, void *addr, int addr_size);
private:
	int s;
	int s6;
};

class DSender : public BSender
{
public:
	DSender(struct BSender::params &prm, uint8_t port, uint8_t *mac, uint8_t *to_mac, struct rte_mempool *mp);
	~DSender();
	int Send(uint8_t *buffer, int size, void *addr, int addr_size);
private:
	uint8_t _port;
	struct ether_hdr _eth_hdr;
	struct rte_mempool *_mp;
};

class WorkerThread;

class ESender : public BSender
{
public:
	struct nparams
	{
		struct params params;
		uint8_t *mac;
		uint8_t *to_mac;
		int answer_duplication;
		struct rte_mempool *clone_pool;
	};
	ESender(struct nparams &params, uint8_t port, struct rte_mempool *mp, WorkerThread *wt, bool keep_l2_hdr = false);
	~ESender();

	void sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, int f_reset, int f_psh);

	int Send(uint8_t *buffer, int size, void *addr, int addr_size)
	{
		return size;
	}

	inline int makeSwapPacketIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, bool f_reset, bool f_psh, struct rte_mbuf *m, bool to_server = false)
	{
		int pkt_len;
		const uint8_t *pkt = pkt_infos->pkt;
		struct ipv4_hdr *ipv4_header = (struct ipv4_hdr *)pkt;
		struct tcphdr *tcph_orig = (struct tcphdr *)(pkt + sizeof(struct ipv4_hdr));

		// ethernet header
		std::size_t l2_hdr_size = _keep_l2_hdr ? (pkt_infos->pkt - pkt_infos->l2_pkt) : sizeof(struct ether_hdr);
		struct ether_hdr *eth_hdr = (struct ether_hdr *) rte_pktmbuf_append(m, l2_hdr_size);
		if(_keep_l2_hdr)
		{
			rte_memcpy(eth_hdr, pkt_infos->l2_pkt, l2_hdr_size);
			if(!to_server)
			{
				struct ether_addr addr;
				ether_addr_copy(&eth_hdr->d_addr, &addr);
				ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
				ether_addr_copy(&addr, &eth_hdr->s_addr);
			}
		} else {
			*eth_hdr = _eth_hdr;
		}

		// IP header
		struct iphdr *iph = (struct iphdr *) rte_pktmbuf_append(m, sizeof(struct iphdr));

		// TCP header
		struct tcphdr *tcph = (struct tcphdr *) rte_pktmbuf_append(m, sizeof(struct tcphdr));

		// Data part
		if(dt_buf != nullptr && dt_len != 0)
		{
			uint8_t *data = (uint8_t *) rte_pktmbuf_append(m, dt_len);
			rte_memcpy(data, dt_buf, dt_len);
		}

		if(_logger.getLevel() == Poco::Message::PRIO_DEBUG)
		{
			Poco::Net::IPAddress ipa(&ipv4_header->src_addr, sizeof(in_addr) );
			_logger.debug("Trying to send packet to %s port %d", ipa.toString(), (int) rte_be_to_cpu_16(tcph_orig->source));
		}
		// Fill the IPv4 header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = rte_cpu_to_be_16(sizeof(struct iphdr) + sizeof(struct tcphdr) + dt_len);
		iph->id = rte_cpu_to_be_16(pkt_id++);
		iph->frag_off = 0;
		iph->ttl = _parameters.ttl;
		iph->protocol = IPPROTO_TCP;
		iph->check = 0;
		if(to_server)
		{
			iph->saddr = ipv4_header->src_addr;
			iph->daddr = ipv4_header->dst_addr;
		} else {
			iph->saddr = ipv4_header->dst_addr;
			iph->daddr = ipv4_header->src_addr;
		}
		pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + dt_len;

		// TCP Header
		tcph->source = tcph_orig->dest;
		tcph->dest = tcph_orig->source;
		tcph->seq = acknum;
		tcph->doff = 5;
		tcph->syn = 0;
		tcph->res1 = 0;
		tcph->res2 = 0;
		tcph->rst = f_reset;
		tcph->psh = f_psh;
		if(f_reset)
		{
			tcph->ack = 0;
			tcph->ack_seq = 0;
			tcph->fin = 0;
			tcph->window = 0;
		} else {
			tcph->window = tcph_orig->window;
			tcph->ack_seq = seqnum;
			tcph->ack = 1;
			tcph->fin = 0;
		}
		tcph->urg = 0;
		tcph->check = 0;
		tcph->urg_ptr = 0;

		tcph->check = rte_ipv4_udptcp_cksum((const ipv4_hdr*)iph, tcph);
		iph->check = rte_ipv4_cksum((const ipv4_hdr*)iph);

		return pkt_len;
	}

	inline int makeSwapPacketIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, bool f_reset, bool f_psh, struct rte_mbuf *m, bool to_server = false)
	{
		int pkt_len;

		const uint8_t *pkt = pkt_infos->pkt;
		struct ipv6_hdr *ipv6_header = (struct ipv6_hdr *)pkt;
		struct tcphdr *tcph_orig = (struct tcphdr *)(pkt + sizeof(struct ipv6_hdr));

		// ethernet header
		std::size_t l2_hdr_size = _keep_l2_hdr ? (pkt_infos->pkt - pkt_infos->l2_pkt) : sizeof(struct ether_hdr);
		struct ether_hdr *eth_hdr = (struct ether_hdr *) rte_pktmbuf_append(m, l2_hdr_size);
		if(_keep_l2_hdr)
		{
			rte_memcpy(eth_hdr, pkt_infos->l2_pkt, l2_hdr_size);
			if(!to_server)
			{
				struct ether_addr addr;
				ether_addr_copy(&eth_hdr->d_addr, &addr);
				ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
				ether_addr_copy(&addr, &eth_hdr->s_addr);
			}
		} else {
			*eth_hdr = _eth_hdr_ipv6;
		}

		// IP header
		struct ip6_hdr *iph6 = (struct ip6_hdr *) rte_pktmbuf_append(m, sizeof(struct ip6_hdr));

		// TCP header
		struct tcphdr *tcph = (struct tcphdr *) rte_pktmbuf_append(m, sizeof(struct tcphdr));

		// Data part
		if(dt_buf != nullptr && dt_len != 0)
		{
			uint8_t *data = (uint8_t *) rte_pktmbuf_append(m, dt_len);
			rte_memcpy(data, dt_buf, dt_len);
		}

		if(_logger.getLevel() == Poco::Message::PRIO_DEBUG)
		{
			Poco::Net::IPAddress ipa(&ipv6_header->src_addr, sizeof(in6_addr) );
			_logger.debug("Trying to send packet to %s port %d", ipa.toString(), (int) rte_be_to_cpu_16(tcph_orig->source));
		}
		// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
		iph6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
		// Payload length (16 bits): TCP header + TCP data
		iph6->ip6_plen = rte_cpu_to_be_16 (sizeof(struct tcphdr) + dt_len);
		// Next header (8 bits): 6 for TCP
		iph6->ip6_nxt = IPPROTO_TCP;
		 // Hop limit (8 bits): default to maximum value
		iph6->ip6_hops = 250;
		if(to_server)
		{
			rte_mov16((uint8_t *)&iph6->ip6_src, (uint8_t *)&ipv6_header->src_addr);
			rte_mov16((uint8_t *)&iph6->ip6_dst, (uint8_t *)&ipv6_header->dst_addr);
		} else {
			rte_mov16((uint8_t *)&iph6->ip6_src, (uint8_t *)&ipv6_header->dst_addr);
			rte_mov16((uint8_t *)&iph6->ip6_dst, (uint8_t *)&ipv6_header->src_addr);
		}
		pkt_len = (sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + dt_len);
		// TCP Header
		tcph->source = tcph_orig->dest;
		tcph->dest = tcph_orig->source;
		tcph->seq = acknum;
		tcph->doff = 5;
		tcph->syn = 0;
		tcph->res1 = 0;
		tcph->res2 = 0;
		tcph->rst = f_reset;
		tcph->psh = f_psh;
		tcph->window = tcph_orig->window;
		if(f_reset)
		{
			tcph->ack = 0;
			tcph->ack_seq = 0;
			tcph->fin = 0;
		} else {
			tcph->ack_seq = seqnum;
			tcph->ack = 1;
			tcph->fin = 1;
		}
		tcph->urg = 0;
		tcph->check = 0;
		tcph->urg_ptr = 0;
		tcph->check = rte_ipv6_udptcp_cksum((const ipv6_hdr*)iph6, tcph);
		return pkt_len;
	}

	void sendPacketIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, bool f_reset, bool f_psh, bool to_server = false);
	void SendRSTIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum);
	void HTTPRedirectIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh, const char *redir_url, size_t r_len);
	void HTTPForbiddenIPv4(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh);

	void sendPacketIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, const char *dt_buf, size_t dt_len, bool f_reset, bool f_psh, bool to_server = false);
	void HTTPRedirectIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh, const char *redir_url, size_t r_len);
	void SendRSTIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum);
	void HTTPForbiddenIPv6(dpi_pkt_infos_t *pkt_infos, uint32_t acknum, uint32_t seqnum, bool f_psh);
private:
	uint8_t _port;
	struct ether_hdr _eth_hdr;
	struct ether_hdr _eth_hdr_ipv6;
	struct rte_mempool *_mp;
	struct rte_mempool *_clone_pool;
	WorkerThread *_wt;
	int _answer_duplication;
	bool _keep_l2_hdr;
};

#endif
