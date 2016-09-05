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

/// Данная задача отсылает редирект заданному клиенту
class SenderTask: public Poco::Task
{
public:
	SenderTask(struct CSender::params &prm);
	~SenderTask();

	void runTask();

	// очередь, куда необходимо писать отправные данные...
	static Poco::NotificationQueue queue;

private:
	CSender *sender;
	static Poco::FastMutex _mutex;
	Poco::Logger& _logger;
};

#endif
