#pragma once

#include <Poco/Net/IPAddress.h>
#include <Poco/HashMap.h>
#include <DpdkDevice.h>
#include <map>
#include <set>
#include <vector>

enum entry_types
{
	E_TYPE_DOMAIN,
	E_TYPE_URL
};

struct entry_data
{
	uint32_t lineno;
	entry_types type;
	bool match_exactly;
};


typedef Poco::HashMap<unsigned int, struct entry_data> EntriesData;

typedef Poco::HashMap<unsigned int,bool> DomainsMatchType;

typedef std::map<pcpp::DpdkDevice*, std::vector<int> > InputDataConfig;

typedef std::map<Poco::Net::IPAddress,std::set<unsigned short>> IPPortMap;

enum ADD_P_TYPES { A_TYPE_NONE, A_TYPE_ID, A_TYPE_URL };

