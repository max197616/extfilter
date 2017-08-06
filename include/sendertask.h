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
#ifndef __SENDER_TASK_H
#define __SENDER_TASK_H

#include <Poco/Task.h>
#include <Poco/Mutex.h>
#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/AutoPtr.h>
#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>

#include "sender.h"

class RedirectNotification: public Poco::Notification
	// The notification sent to worker threads.
{
public:
	typedef Poco::AutoPtr<RedirectNotification> Ptr;
	
	RedirectNotification(int user_port, int dst_port, Poco::Net::IPAddress *user_ip, Poco::Net::IPAddress *dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh, std::string &additional_param, bool is_rst=false):
		_user_port(user_port),
		_dst_port(dst_port),
		_user_ip(*user_ip),
		_dst_ip(*dst_ip),
		_acknum(acknum),
		_seqnum(seqnum),
		_f_psh(f_psh),
		_additional_param(additional_param),
		_is_rst(is_rst)
	{
	}
	int user_port()
	{
		return _user_port;
	}
	int dst_port()
	{
		return _dst_port;
	}
	Poco::Net::IPAddress &user_ip()
	{
		return _user_ip;
	}
	Poco::Net::IPAddress &dst_ip()
	{
		return _dst_ip;
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
private:
	int _user_port;
	int _dst_port;
	Poco::Net::IPAddress _user_ip;
	Poco::Net::IPAddress _dst_ip;
	uint32_t _acknum;
	uint32_t _seqnum;
	int _f_psh;
	std::string _additional_param;
	bool _is_rst;
};


class RedirectNotificationG: public Poco::Notification
	// The notification sent to worker threads.
{
public:
	typedef Poco::AutoPtr<RedirectNotificationG> Ptr;
	
	RedirectNotificationG(int user_port, int dst_port, void *user_ip, void *dst_ip, int ip_version, uint32_t acknum, uint32_t seqnum, int f_psh, char *additional_param, bool is_rst=false):
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
private:
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

struct redirectEvent
{
	uint16_t _user_port;
	uint16_t _dst_port;
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
	uint8_t _ip_version;
	uint32_t _acknum;
	uint32_t _seqnum;
	uint8_t _f_psh;
	char *_additional_param;
	uint8_t _is_rst;
};



/// Данная задача отсылает редирект заданному клиенту
class SenderTask: public Poco::Task
{
public:
	SenderTask(BSender *snd, int instance);
	~SenderTask();

	void runTask();

	// очередь, куда необходимо писать отправные данные...
	static Poco::NotificationQueue queue;
private:
	BSender *sender;
	Poco::Logger& _logger;
};

#endif
