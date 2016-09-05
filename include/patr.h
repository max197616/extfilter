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

#ifndef __PATR_H
#define __PATR_H

#include <Poco/Net/IPAddress.h>
#include <string>
#include "patricia.h"

class Patricia
{
public:
	Patricia();
	~Patricia();

	patricia_node_t *make_and_lookup(std::string &addr);
	/// Поиск только по адресу
	patricia_node_t *try_search_exact_ip(Poco::Net::IPAddress &address);
	void print_all_nodes();
private:
	bool fill_prefix(int family, void *dest, int bitlen, prefix_t &prefix);
	patricia_tree_t *tree_ipv4;
	patricia_tree_t *tree_ipv6;
};

#endif
