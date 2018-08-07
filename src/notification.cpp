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

#include "notification.h"
#include <rte_config.h>
#include <rte_cycles.h>
#include <Poco/Net/IPAddress.h>
#include "sender.h"

NotifyManager *NotifyManager::_instance;
Poco::NotificationQueue NotifyManager::queue;

NotifyManager::NotifyManager(int size, std::map<int, struct NotificationParams> &prms) :
	Task("NotifyManager"),
	 _logger(Poco::Logger::get("NotifyManager")),
	_params(prms)
{
	subs.reserve(size);
	_timeout = 300;
	_instance = this;
	for(auto const &prm : prms)
	{
		_senders.insert(std::make_pair(prm.first, new CSender((struct CSender::params &)prm.second.prm)));
	}
}


NotifyManager::~NotifyManager()
{
	for(auto const &i : _senders)
	{
		delete i.second;
	}
}

bool NotifyManager::needNotify(uint32_t ip, int group_id)
{
	auto got = subs.find(ip);
	if(got == subs.end())
	{
		queue.enqueueNotification(new UpdateNotification(ip, group_id));
		return true;
	} else {
		if(got->second.need_redirect)
		{
			got->second.need_redirect = false;
			got->second.redirects++;
			queue.enqueueNotification(new UpdateNotification(ip, group_id));
			return true;
		}
	}
	return false;
}

void NotifyManager::runTask()
{
	_logger.debug("Starting NotifyManager...");
	uint64_t last_check = time(NULL);
	while(!isCancelled())
	{
		Poco::Notification::Ptr pNf(queue.waitDequeueNotification(_timeout));
		if (pNf)
		{
			UpdateNotification::Ptr pUpdateNf = pNf.cast<UpdateNotification>();
			if (pUpdateNf)
			{
				int group_id = pUpdateNf->group_id();
				auto prm = _params.find(group_id);
				if(prm != _params.end())
				{
					auto sub = subs.find(pUpdateNf->getIP());
					if(sub != subs.end())
					{
						uint64_t tm = time(NULL);
						sub->second.last_redirect = tm;
						sub->second.next_redirect = tm + prm->second.period;
					} else {
						uint64_t tm = time(NULL);
						struct subscriber s;
						s.ipv4 = pUpdateNf->getIP();
						s.need_redirect = false;
						s.last_redirect = tm;
						s.next_redirect = tm + prm->second.period;
						s.redirects++;
						s.repeat = prm->second.repeat;
						std::pair<uint32_t, struct subscriber> entry(pUpdateNf->getIP(), s);
						subsLock.lock();
						subs.insert(entry);
						subsLock.unlock();
						_logger.debug("Subscriber with ip %d successfully inserted to the subscriber database", (int) pUpdateNf->getIP());
					}
				} else {
					_logger.error("Unable to find notify group %d", group_id);
				}
			}
			NotifyRedirect::Ptr pNotifyNf = pNf.cast<NotifyRedirect>();
			if (pNotifyNf)
			{
				int notify_group = pNotifyNf->notify_group();
				auto const r = _senders.find(notify_group);
				if(r == _senders.end())
				{
					_logger.error("Unable to find sender for group with id %d", notify_group);
				} else {
					r->second->HTTPRedirect(pNotifyNf->user_port(), pNotifyNf->dst_port(), pNotifyNf->user_ip(), pNotifyNf->dst_ip(), pNotifyNf->ip_version(), pNotifyNf->acknum(), pNotifyNf->seqnum(), pNotifyNf->f_psh(), pNotifyNf->additional_param().c_str(), pNotifyNf->additional_param().length());
//					struct redirect_params rp = r->second;
//					std::string full_url("@HTTP/1.1 "+rp.code+"\r\nLocation: " + rp.redirect_url + pNotifyNf->additional_param() + "\r\nConnection: close\r\n");
//					sender->Redirect(pNotifyNf->user_port(), pNotifyNf->dst_port(), pNotifyNf->user_ip(), pNotifyNf->dst_ip(), pNotifyNf->ip_version(), pNotifyNf->acknum(), pNotifyNf->seqnum(), pNotifyNf->f_psh(), full_url);
				}
			}
		}
		uint64_t tm = time(NULL);
		if(last_check + 1 < tm)
		{
			for(auto &sub : subs)
			{
				if(!sub.second.need_redirect && sub.second.next_redirect < tm)
				{
					if(sub.second.repeat)
					{
						if(sub.second.repeat < sub.second.redirects)
							sub.second.need_redirect = true;
					} else {
						sub.second.need_redirect = true;
					}
				}
			}
		}
	}

	_logger.debug("Stopping NotifyManager...");
}

static inline void printSub(struct cmdline *cl, uint32_t ip, struct subscriber &sub)
{
	char buff[20];
	Poco::Net::IPAddress ipp((void *)&ip,sizeof(in_addr));
	cmdline_printf(cl, "Subscriber with ip %s:\n", ipp.toString().c_str());
	strftime(buff, 20, "%d-%m-%Y %H:%M:%S", localtime((time_t *)&sub.last_redirect));
	cmdline_printf(cl, "Last redirect: %s\n", buff);
	strftime(buff, 20, "%d-%m-%Y %H:%M:%S", localtime((time_t *)&sub.next_redirect));
	cmdline_printf(cl, "Next redirect: %s\n", buff);
	cmdline_printf(cl, "Redirected times: %lu\n", sub.redirects);
}

void NotifyManager::printSubscribers(struct cmdline* cl, uint32_t ip)
{
	NotifyManager *nm = _instance;
	if(ip)
	{
		auto got = nm->subs.find(ip);
		if(got == nm->subs.end())
		{
			cmdline_printf(cl, "Subscriber not found\n");
		} else {
			printSub(cl, ip, got->second);
		}
	} else {
		for(auto const &sub : nm->subs)
		{
			printSub(cl, sub.first, (struct subscriber &)sub.second);
		}
		cmdline_printf(cl, "Displayed %lu entries\n", nm->subs.size());
	}
}
