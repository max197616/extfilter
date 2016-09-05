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

#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>


class CSender {
public:
	struct params
	{
		std::string redirect_url;
		std::string code;
		bool send_rst_to_server;
		int ttl;
		int ip6_hops;

		params() : code("302 Moved Temporarily"), send_rst_to_server(false), ttl(250), ip6_hops(250) { }
	};
	CSender( std::string url );
	CSender(struct params &prm);
	~CSender();
	void Redirect(int user_port, int dst_port, Poco::Net::IPAddress &src_ip, Poco::Net::IPAddress &dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh, std::string &additional_param);
	void sendPacket(Poco::Net::IPAddress &ip_from, Poco::Net::IPAddress &ip_to, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh);
	void SendRST(int user_port, int dst_port, Poco::Net::IPAddress &user_ip, Poco::Net::IPAddress &dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh);
private:
	unsigned short csum(unsigned short *ptr, int nbytes);
	int s;
	int s6;
	std::string rHeader;
	Poco::Logger& _logger;
	struct params _parameters;
};


#endif
