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

Poco::FastMutex SenderTask::_mutex;
Poco::NotificationQueue SenderTask::queue;

SenderTask::SenderTask(struct CSender::params &prm):
	Task("SenderTask"),
	sender(new CSender(prm)),
	_logger(Poco::Logger::get("SenderTask"))
{

}


SenderTask::~SenderTask()
{
	delete sender;
}

void SenderTask::runTask()
{
	_logger.debug("Starting SenderTask...");

	while(!isCancelled())
	{
		Poco::Notification::Ptr pNf(queue.waitDequeueNotification());
		if (pNf)
		{
			RedirectNotification::Ptr pRedirectNf = pNf.cast<RedirectNotification>();
			if (pRedirectNf)
			{
				if(pRedirectNf->is_rst())
					sender->SendRST(pRedirectNf->user_port(), pRedirectNf->dst_port(),pRedirectNf->user_ip(),pRedirectNf->dst_ip(), pRedirectNf->acknum(), pRedirectNf->seqnum(), pRedirectNf->f_psh());
				else
					sender->Redirect(pRedirectNf->user_port(), pRedirectNf->dst_port(),pRedirectNf->user_ip(),pRedirectNf->dst_ip(), pRedirectNf->acknum(), pRedirectNf->seqnum(), pRedirectNf->f_psh(), pRedirectNf->additional_param());
			}
		}
	}

	_logger.debug("Stopping SenderTask...");
}

