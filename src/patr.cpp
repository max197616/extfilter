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

#include "patricia.h"
#include "patr.h"
#include <string.h>
#include <iostream>


Patricia::Patricia()
{
	tree_ipv4 = New_Patricia(32);
	tree_ipv6 = New_Patricia(128);
}

Patricia::~Patricia()
{
	Destroy_Patricia(tree_ipv4, nullptr);
	Destroy_Patricia(tree_ipv6, nullptr);
}


patricia_node_t *Patricia::make_and_lookup(std::string &description)
{
	prefix_t prefix;
	patricia_node_t *node;
	Poco::Net::IPAddress mask;
	Poco::Net::IPAddress address;
	if(description.empty())
		return nullptr;
	std::size_t slash=description.find('/');
	if(slash != std::string::npos)
	{
		std::string addr=description.substr(0,slash);
		std::string msk_t=description.substr(slash+1,description.size());
		if(Poco::Net::IPAddress::tryParse(addr,address))
		{
			int msk = std::stoi(msk_t,nullptr);
			if(address.family() == Poco::Net::IPAddress::IPv4)
			{
				if(msk > 32)
				{
					return nullptr;
				}
				Poco::Net::IPAddress msk1(msk, Poco::Net::IPAddress::IPv4);
				mask=msk1;
			} else {
				if(msk > 128)
				{
					return nullptr;
				}
				mask=Poco::Net::IPAddress(msk,Poco::Net::IPAddress::IPv6);
			}
		} else
			return nullptr;
	} else {
		if(Poco::Net::IPAddress::tryParse(description,address))
		{
			if(address.family() == Poco::Net::IPAddress::IPv4)
				mask=Poco::Net::IPAddress(32,Poco::Net::IPAddress::IPv4);
			else
				mask=Poco::Net::IPAddress(128,Poco::Net::IPAddress::IPv6);
		} else
			return nullptr;
	}
	if(!fill_prefix(address.family() == Poco::Net::IPAddress::IPv4 ? AF_INET : AF_INET6,(void *)address.addr(),mask.prefixLength(),prefix))
		return nullptr;
	node = patricia_lookup (address.family() == Poco::Net::IPAddress::IPv4 ? tree_ipv4 : tree_ipv6, &prefix);
	return (node);
}

patricia_node_t *Patricia::try_search_exact_ip(Poco::Net::IPAddress &address)
{
	prefix_t prefix;
	patricia_node_t *node;
	if(!fill_prefix(address.family() == Poco::Net::IPAddress::IPv4 ? AF_INET : AF_INET6,(void *)address.addr(),address.family() == Poco::Net::IPAddress::IPv4 ? 32 : 128, prefix))
		return nullptr;
	node=patricia_search_exact (address.family() == Poco::Net::IPAddress::IPv4 ? tree_ipv4 : tree_ipv6, &prefix);
	return (node);
}

bool Patricia::fill_prefix(int family, void *dest, int bitlen, prefix_t &prefix)
{
	int default_bitlen = sizeof(struct in_addr) * 8;
	if(family == AF_INET6)
	{
		default_bitlen = sizeof(struct in6_addr) * 8;
		memcpy (&prefix.add.sin6, dest, sizeof(struct in6_addr));
	} else if (family == AF_INET)
	{
		memcpy (&prefix.add.sin, dest, sizeof(struct in_addr));
	} else {
		return false;
	}
	prefix.bitlen = (bitlen >= 0)? bitlen: default_bitlen;
	prefix.family = family;
	prefix.ref_count = 0;
	return true;
}

void Patricia::print_all_nodes()
{
	patricia_node_t *node;
	std::cout << "IPv4 nodes:" << std::endl;
	PATRICIA_WALK(tree_ipv4->head, node) {
		std::cout << "node: " << prefix_toa(node->prefix) << "/" << node->prefix->bitlen << std::endl;
	} PATRICIA_WALK_END;
	std::cout << "IPv6 nodes:" << std::endl;
	PATRICIA_WALK(tree_ipv6->head, node) {
		std::cout << "node: " << prefix_toa(node->prefix) << "/" << node->prefix->bitlen << std::endl;
	} PATRICIA_WALK_END;
}
