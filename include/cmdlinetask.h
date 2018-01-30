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
