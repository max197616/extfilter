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
#include <Poco/Mutex.h>
#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/AutoPtr.h>
#include <rte_config.h>
#include <cmdline.h>
#include <unordered_map>
#include <map>
#include "sender.h"

#define DEFAULT_SUBSCRIBER_TABLE_SIZE 50000

struct subscriber
{
	uint32_t ipv4;
	bool need_redirect;
	uint64_t last_redirect;
	uint64_t next_redirect;
	uint64_t redirects;
	int repeat;
	subscriber()
	{
		last_redirect = 0;
		next_redirect = 0;
		redirects = 0;
		repeat = 0;
	}
};

struct NotificationParams
{
	int group_id;
	struct CSender::params prm;
	int period;
	int repeat;
};

class UpdateNotification: public Poco::Notification
{
public:
	typedef Poco::AutoPtr<UpdateNotification> Ptr;
	
	UpdateNotification(uint32_t ip, uint32_t group_id) : _ip(ip), _group_id(group_id)
	{
	}

	inline uint32_t getIP()
	{
		return _ip;
	}

	inline uint32_t group_id()
	{
		return _group_id;
	}
private:
	uint32_t _ip;
	uint32_t _group_id;
};

class NotifyRedirect: public Poco::Notification
{
public:
	typedef Poco::AutoPtr<NotifyRedirect> Ptr;
	
	NotifyRedirect(uint32_t notify_group, int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_version, uint32_t acknum, uint32_t seqnum, int f_psh, char *additional_param, bool is_rst=false):
		_notify_group(notify_group),
		_user_port(user_port),
		_dst_port(dst_port),
		_ip_version(ip_version),
		_acknum(acknum),
		_seqnum(seqnum),
		_f_psh(f_psh),
		_is_rst(is_rst)
	{
		if(_ip_version == 4)
		{
			_user_ip.ipv4 = *(uint32_t *)user_ip;
			_dst_ip.ipv4 = *(uint32_t *)dst_ip;
		} else if(_ip_version == 6)
		{
			_user_ip.ipv6 = _mm_loadu_si128((__m128i *)user_ip);
			_dst_ip.ipv6 = _mm_loadu_si128((__m128i *)dst_ip);
		}
		if(additional_param)
		{
			_additional_param.assign(additional_param);
		}
	}
	int user_port()
	{
		return _user_port;
	}
	int dst_port()
	{
		return _dst_port;
	}
	u_int32_t acknum()
	{
		return _acknum;
	}
	u_int32_t seqnum()
	{
		return _seqnum;
	}
	int f_psh()
	{
		return _f_psh;
	}
	std::string &additional_param()
	{
		return _additional_param;
	}
	bool is_rst()
	{
		return _is_rst;
	}
	void *user_ip()
	{
		return &_user_ip;
	}
	void *dst_ip()
	{
		return &_dst_ip;
	}
	int ip_version()
	{
		return _ip_version;
	}
	uint32_t notify_group()
	{
		return _notify_group;
	}
private:
	uint32_t _notify_group;
	int _user_port;
	int _dst_port;
	union
	{
		uint32_t ipv4;
		__m128i ipv6;
	} _user_ip;
	union
	{
		uint32_t ipv4;
		__m128i ipv6;
	} _dst_ip;
	int _ip_version;
	uint32_t _acknum;
	uint32_t _seqnum;
	int _f_psh;
	std::string _additional_param;
	bool _is_rst;
};

class extFilter;

class NotifyManager : public Poco::Task
{
public:
	struct redirect_params
	{
		std::string code;
		std::string redirect_url;
	};
	NotifyManager(int size, std::map<int, struct NotificationParams> &prms);
	~NotifyManager();
	
	bool needNotify(uint32_t ip, int group_id);
	void runTask();
	static void printSubscribers(struct cmdline* cl, uint32_t ip);
	static Poco::NotificationQueue queue;
private:
	Poco::Logger& _logger;
	std::unordered_map<uint32_t, struct subscriber> subs;
	Poco::FastMutex subsLock;
	long _timeout; // msec
	static NotifyManager *_instance;
	std::unordered_map<int, CSender *> _senders;
	std::map<int, struct NotificationParams> _params;
};

