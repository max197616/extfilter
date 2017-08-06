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
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>

class BSender
{
public:
	struct params
	{
		std::string redirect_url;
		std::string code;
		bool send_rst_to_server;
		int ttl;
		int ip6_hops;
		int mtu;
		params() : code("302 Moved Temporarily"), send_rst_to_server(false), ttl(250), ip6_hops(250), mtu(1500) { }
	};

	BSender(const char *, struct params &prm);
	virtual ~BSender();

	void Redirect(int user_port, int dst_port, void *ip_from, void *ip_to, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh, const char *add_prm);
	virtual void sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh);
	void SendRST(int user_port, int dst_port, void *ip_from, void *ip_to, int ip_ver, uint32_t acknum, uint32_t seqnum, int f_psh);
	int makePacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh, uint8_t *buffer);

	virtual int Send(uint8_t *buffer, int size, void *addr, int addr_size) = 0;

	Poco::Logger& _logger;
	std::string rHeader;
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
	};
	ESender(struct nparams &params, uint8_t port, struct rte_mempool *mp, WorkerThread *wt);
	~ESender();
	void sendPacket(void *ip_from, void *ip_to, int ip_ver, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh);
	int Send(uint8_t *buffer, int size, void *addr, int addr_size)
	{
		return size;
	}
private:
	uint8_t _port;
	struct ether_hdr _eth_hdr;
	struct rte_mempool *_mp;
	WorkerThread *_wt;
};

#endif
