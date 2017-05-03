#pragma once

#include <Poco/Task.h>
#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>
#include <vector>
#include <rte_config.h>
#include <cmdline.h>
#include <cmdline_parse_string.h>

class CmdLineTask: public Poco::Task
{
public:
	CmdLineTask(int port, Poco::Net::IPAddress &ip);
	~CmdLineTask();

	void runTask();

private:
	void build_ctx();
	Poco::Logger& _logger;
	int _sockfd;
	int _port;
	int _max_connections;
	cmdline_parse_ctx_t *_main_ctx;
	std::vector<cmdline_parse_inst_t *> cmds;
};
