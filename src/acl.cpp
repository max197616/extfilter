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
#include <Poco/FileStream.h>
#include <Poco/Net/IPAddress.h>
#include "acl.h"
#include "main.h"

struct rte_acl_ctx* ACL::ipv4_acx[NB_SOCKETS];
struct rte_acl_ctx* ACL::ipv6_acx[NB_SOCKETS];


ACL::ACL() :
	_logger(Poco::Logger::get("ACL"))
{
	memset(ipv4_acx, 0, sizeof(ipv4_acx));
	memset(ipv6_acx, 0, sizeof(ipv6_acx));
}

ACL::~ACL()
{

}

rte_acl_ctx* ACL::_setup_acl(struct rte_acl_rule* acl_base, unsigned int acl_num, int ipv6, int socketid)
{
	char name[PATH_MAX];
	struct rte_acl_param acl_param;
	struct rte_acl_config acl_build_param;
	struct rte_acl_ctx* context;
	int dim = ipv6 ? RTE_DIM(ipv6_defs) : RTE_DIM(ipv4_defs);
	static uint32_t ctx_count[NB_SOCKETS] = {0};

	if (!acl_num)
		return NULL;

	/* Create ACL contexts */
	snprintf(name, sizeof(name), "%s%d-%d", ipv6 ? "extFilter-ipv6-acl" : "extFilter-ipv4-acl", socketid, ctx_count[socketid]++);

	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;

	if ((context = rte_acl_create(&acl_param)) == NULL)
	{
		_logger.error("Failed to create ACL context");
		return NULL;
	}

/*	if (acl_parm_config.aclavx2 &&
	    rte_acl_set_ctx_classify(context, RTE_ACL_CLASSIFY_AVX2) != 0) {
		acl_log("Failed to setup classify method for  ACL context\n");
		goto err;
	}
*/
	if (rte_acl_add_rules(context, acl_base, acl_num) < 0)
	{
		_logger.error("Add rules failed");
		rte_acl_free(context);
		return NULL;
	}

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;
	rte_memcpy(&acl_build_param.defs, ipv6 ? ipv6_defs : ipv4_defs,
	       ipv6 ? sizeof(ipv6_defs) : sizeof(ipv4_defs));

	if (rte_acl_build(context, &acl_build_param) != 0)
	{
		_logger.error("Failed to build ACL trie");
		rte_acl_free(context);
		return NULL;
	}

	rte_acl_dump(context);
	return context;
}

static void _parse_ipv6(uint32_t *v, struct rte_acl_field field[4], uint32_t mask)
{
	const uint32_t nbu32 = sizeof(uint32_t) * CHAR_BIT;
	/* put all together. */
	for (int i = 0; i < 4; i++)
	{
		if (mask >= (i + 1) * nbu32)
			field[i].mask_range.u32 = nbu32;
		else
			field[i].mask_range.u32 =  mask > (i * nbu32) ? mask - (i * 32) : 0;
		field[i].value.u32 = v[i];
	}

}

int ACL::initACL(std::map<std::string, int> &fns, int _numa_on, std::set<struct rte_acl_ctx*> *to_del)
{
	char mapped[NB_SOCKETS];

	struct rte_acl_ctx* acl_ctx;

	struct rte_acl_rule* ipv4_rules = NULL;
	struct rte_acl_rule* ipv6_rules = NULL;

	unsigned int total_num = 0;
	unsigned int total_num_ipv6 = 0;
	
	uint32_t def_ipv6[4] = { 0, 0, 0, 0 };

//	unsigned int acl_cnt = 0;

	memset(&mapped[0], 0, sizeof(mapped));
	std::vector<struct ACL::acl4_rule> acl4_rules;
	std::vector<struct ACL::acl6_rule> acl6_rules;

	for(auto const &entry: fns)
	{
		std::string file_name=entry.first;
		if(!file_name.empty())
		{
			_logger.debug("Building ACL from file %s", file_name);
			Poco::FileInputStream hf(file_name);
			if(hf.good())
			{
				int lineno=1;
				while(!hf.eof())
				{
					std::string str;
					getline(hf,str);
					if(!str.empty())
					{
						if(str[0] == '#' || str[0] == ';')
							continue;
						int group_id = 0;
						bool ipv6 = false;
						if(str[0] == '[')
							ipv6 = true;
						std::size_t found;
						int first_pos=0;
						if(ipv6)
						{
							found = str.find("]");
							ipv6=true;
							first_pos = 1;
						} else {
							found = str.find(":");
						}
						uint8_t proto = IPPROTO_TCP;
						uint8_t proto_mask = 0xff;
						std::size_t found_comma = str.find(",");
						if(found_comma != std::string::npos)
						{
							std::string protocol_str = str.substr(found_comma + 1, str.length());
							str.erase(found_comma, str.length() - found_comma);
							std::size_t found_sl = protocol_str.find("/");
							if(found_sl != std::string::npos)
							{
								std::string p_mask = protocol_str.substr(found_sl + 1, protocol_str.length());
								std::string p = protocol_str.substr(0, found_sl);
								long int p_mask_b = std::strtol(p_mask.c_str(),NULL, 0);
								long int p_b = std::strtol(p.c_str(), NULL, 0);
								if(p_mask_b > 255 || p_b > 255)
								{
									_logger.warning("Bad protocol/mask (value > 255) in line %d", lineno);
								} else {
									proto = p_b;
									proto_mask = p_mask_b;
								}
							} else {
								_logger.warning("Bad protocol/mask in line %d", lineno);
							}
						}
						std::string ip=str.substr(first_pos, ipv6 ? found-1 : found);
						std::size_t found_slash=ip.find("/");
						uint32_t def_mask=0;
						if(found_slash != std::string::npos)
						{
							std::string mask_str=ip.substr(found_slash+1,ip.length());
							def_mask = atoi(mask_str.c_str());
							ip = ip.substr(0, found_slash);
						}
						std::string port;
						uint16_t port_s=0;
						uint16_t port_e=65535;
						if(ipv6)
						{
							found = str.find(":", found+1);
						}
						std::size_t end_pos = str.length();
						if(entry.second == ACL::ACL_NOTIFY)
						{
							std::size_t f = str.find("@");
							if(f != std::string::npos)
							{
								end_pos = f;
								std::string group_num = str.substr(f+1, str.length());
								group_id = atoi(group_num.c_str());
							}
						}
						if(found != std::string::npos)
						{
							port=str.substr(ipv6 ? found+2 : found+1, end_pos);
							_logger.debug("IP is %s port %s", ip, port);
							port_s=atoi(port.c_str());
							port_e=port_s;
						} else {
							_logger.debug("IP %s without port", ip);
						}
						Poco::Net::IPAddress ip_addr(ip);
						if(ip_addr.family() == Poco::Net::IPAddress::IPv4)
						{
							struct ACL::acl4_rule rule;
							rule.field[ACL::PROTO_FIELD_IPV4].value.u8 = proto;
							rule.field[ACL::PROTO_FIELD_IPV4].mask_range.u8 = proto_mask;
							if(entry.second == ACL::ACL_NOTIFY)
							{
								rule.field[ACL::DST_FIELD_IPV4].value.u32 = IPv4(0, 0, 0, 0);
								rule.field[ACL::DST_FIELD_IPV4].mask_range.u32 = 0;
								rule.field[ACL::SRC_FIELD_IPV4].value.u32 = rte_be_to_cpu_32(*((uint32_t *)ip_addr.addr()));
								rule.field[ACL::SRC_FIELD_IPV4].mask_range.u32 = def_mask ? def_mask : 32;
								
							} else {
								rule.field[ACL::SRC_FIELD_IPV4].value.u32 = IPv4(0, 0, 0, 0);
								rule.field[ACL::SRC_FIELD_IPV4].mask_range.u32 = 0;
								rule.field[ACL::DST_FIELD_IPV4].value.u32 = rte_be_to_cpu_32(*((uint32_t *)ip_addr.addr()));
								rule.field[ACL::DST_FIELD_IPV4].mask_range.u32 = def_mask ? def_mask : 32;
							}
							rule.field[ACL::SRCP_FIELD_IPV4].value.u16 = 0;
							rule.field[ACL::SRCP_FIELD_IPV4].mask_range.u16 = 65535;
							if(entry.second == ACL::ACL_NOTIFY)
							{
								rule.field[ACL::DSTP_FIELD_IPV4].value.u16 = 80;
								rule.field[ACL::DSTP_FIELD_IPV4].mask_range.u16 = 80;
								
							} else {
								rule.field[ACL::DSTP_FIELD_IPV4].value.u16 = port_s;
								rule.field[ACL::DSTP_FIELD_IPV4].mask_range.u16 = port_e;
							}
							if(entry.second == ACL::ACL_NOTIFY)
							{
								rule.data.userdata = (group_id << 4) | entry.second;
							} else {
								rule.data.userdata = entry.second;
							}
							rule.data.priority = RTE_ACL_MAX_PRIORITY - total_num;
							rule.data.category_mask = 1;

							acl4_rules.push_back(rule);
							total_num++;
						} else if (ip_addr.family() == Poco::Net::IPAddress::IPv6)
						{
							struct ACL::acl6_rule rule;
							rule.field[ACL::PROTO_FIELD_IPV6].value.u8 = proto;
							rule.field[ACL::PROTO_FIELD_IPV6].mask_range.u8 = proto_mask;
							_parse_ipv6((uint32_t *)&def_ipv6, rule.field + SRC1_FIELD_IPV6, 0);
							_parse_ipv6((uint32_t *)ip_addr.addr(), rule.field + DST1_FIELD_IPV6, def_mask ? def_mask : 128);

							rule.field[ACL::SRCP_FIELD_IPV6].value.u16 = 0;
							rule.field[ACL::SRCP_FIELD_IPV6].mask_range.u16 = 65535;
							rule.field[ACL::DSTP_FIELD_IPV6].value.u16 = port_s;
							rule.field[ACL::DSTP_FIELD_IPV6].mask_range.u16 = port_e;

							rule.data.userdata = entry.second;
							rule.data.priority = RTE_ACL_MAX_PRIORITY - total_num;
							rule.data.category_mask = 1;

							acl6_rules.push_back(rule);
							total_num_ipv6++;
						}
					}
					lineno++;
				}
			} else
				throw Poco::OpenFileException(file_name);
			hf.close();
		}
	}
	if(!acl4_rules.empty())
	{
		_logger.information("Preparing %d rules for IPv4 ACL", (int) acl4_rules.size());
		// allocate memory
		ipv4_rules = (rte_acl_rule *)calloc(acl4_rules.size(), sizeof(struct ACL::acl4_rule));
		if(ipv4_rules == nullptr)
		{
			_logger.error("Unable to get memory for ipv4 rules");
			return -1;
		}

		int z = 0;
		for(auto i=acl4_rules.begin(); i != acl4_rules.end(); i++)
		{
			rte_memcpy((uint8_t *)ipv4_rules+z*sizeof(struct ACL::acl4_rule), &(*i), sizeof(struct ACL::acl4_rule));
			z++;
		}
	}

	if(!acl6_rules.empty())
	{
		_logger.information("Preparing %d rules for IPv6 ACL", (int) acl6_rules.size());
		// allocate memory
		ipv6_rules = (rte_acl_rule *)calloc(acl6_rules.size(), sizeof(struct ACL::acl6_rule));
		if(ipv6_rules == nullptr)
		{
			_logger.error("Unable to get memory for ipv6 rules");
			free(ipv4_rules);
			return -1;
		}

		int z = 0;
		for(auto i=acl6_rules.begin(); i != acl6_rules.end(); i++)
		{
			rte_memcpy((uint8_t *)ipv6_rules+z*sizeof(struct ACL::acl6_rule), &(*i), sizeof(struct ACL::acl6_rule));
			z++;
		}
	}



	if(!_numa_on)
	{
		mapped[0] = 1;
	} else {
		for (unsigned lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
		{
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			int socketid = rte_lcore_to_socket_id(lcore_id);
			if (socketid >= NB_SOCKETS)
			{
				_logger.error("Socket %d of core %d is out of range %d", socketid, (int) lcore_id, NB_SOCKETS);
				free(ipv4_rules);
				free(ipv6_rules);
				return -1;
			}
			mapped[socketid] = 1;
		}
	}
	for (int i = 0; i < NB_SOCKETS; i++)
	{
		if(mapped[i])
		{
			if(to_del != nullptr && ipv4_acx[i] != nullptr)
				to_del->insert(ipv4_acx[i]);
			if(acl4_rules.empty())
			{
				ipv4_acx[i] = NULL;
			} else if ((acl_ctx = _setup_acl(ipv4_rules, acl4_rules.size(), 0, i)) != NULL)
			{
				ipv4_acx[i] = acl_ctx;
			} else {
				_logger.error("Setup acl for ipv4 with socketid %d failed, keeping previous rules for that socket", (int) i);
			}

			if(to_del != nullptr && ipv6_acx[i] != nullptr)
				to_del->insert(ipv6_acx[i]);
			if(acl6_rules.empty())
			{
				ipv6_acx[i] = NULL;
			} else if ((acl_ctx = _setup_acl(ipv6_rules, acl6_rules.size(), 1, i)) != NULL)
			{
				ipv6_acx[i] = acl_ctx;
			} else {
				_logger.error("Setup acl for ipv6 with socketid %d failed, keeping previous rules for that socket", (int) i);
			}
		}
	}
	free(ipv4_rules);
	free(ipv6_rules);

	int socketid, lcore_id;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
	{
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		if (_numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;
		rte_atomic64_cmpset((uintptr_t*)&extFilter::getLcoreConf(lcore_id)->new_acx_ipv4, (uintptr_t)extFilter::getLcoreConf(lcore_id)->new_acx_ipv4, (uintptr_t)ipv4_acx[socketid]);
		rte_atomic64_cmpset((uintptr_t*)&extFilter::getLcoreConf(lcore_id)->new_acx_ipv6, (uintptr_t)extFilter::getLcoreConf(lcore_id)->new_acx_ipv6, (uintptr_t)ipv6_acx[socketid]);
	}

	return 0;
}
