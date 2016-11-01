#pragma once

#include <Poco/Net/IPAddress.h>
#include <Poco/HashMap.h>
#include <DpdkDevice.h>
#include <map>
#include <set>
#include <vector>

typedef Poco::HashMap<unsigned int,bool> DomainsMatchType;

typedef std::map<pcpp::DpdkDevice*, std::vector<int> > InputDataConfig;

typedef std::map<Poco::Net::IPAddress,std::set<unsigned short>> IPPortMap;

enum ADD_P_TYPES { A_TYPE_NONE, A_TYPE_ID, A_TYPE_URL };

