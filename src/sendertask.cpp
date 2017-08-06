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

#include "sendertask.h"
#include "sender.h"
#include <rte_cycles.h>

Poco::NotificationQueue SenderTask::queue;

SenderTask::SenderTask(BSender *snd, int instance):
	Task("SenderTask-"+std::to_string(instance)),
	sender(snd),
	_logger(Poco::Logger::get("SenderTask-"+std::to_string(instance)))
{

}


SenderTask::~SenderTask()
{
	delete sender;
}

void SenderTask::runTask()
{
	_logger.debug("Starting SenderTask...");
	pthread_t tid = pthread_self();
	pthread_setname_np(tid, name().c_str());
	while(!isCancelled())
	{
		Poco::Notification::Ptr pNf(queue.waitDequeueNotification());
		if (pNf)
		{
			RedirectNotificationG::Ptr pRedirectNf = pNf.cast<RedirectNotificationG>();
			if (pRedirectNf)
			{
				if(pRedirectNf->is_rst())
					sender->SendRST(pRedirectNf->user_port(), pRedirectNf->dst_port(),pRedirectNf->user_ip(),pRedirectNf->dst_ip(), pRedirectNf->ip_version(), pRedirectNf->acknum(), pRedirectNf->seqnum(), pRedirectNf->f_psh());
				else
					sender->Redirect(pRedirectNf->user_port(), pRedirectNf->dst_port(),pRedirectNf->user_ip(),pRedirectNf->dst_ip(), pRedirectNf->ip_version(), pRedirectNf->acknum(), pRedirectNf->seqnum(), pRedirectNf->f_psh(), pRedirectNf->additional_param().c_str());
			}
		}
	}

	_logger.debug("Stopping SenderTask...");
}

