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

#include "reloadtask.h"
#include "main.h"
#include "worker.h"
#include "acl.h"

Poco::Event ReloadTask::_event;


ReloadTask::ReloadTask(extFilter *parent, std::vector<DpdkWorkerThread*> &workerThreadVector):
	Task("ReloadTask"),
	_parent(parent),
	_logger(Poco::Logger::get("ReloadTask")),
	workerThreadVec(workerThreadVector)
{

}


ReloadTask::~ReloadTask()
{
}

void ReloadTask::runTask()
{
	_logger.debug("Starting reload task...");
	pthread_t tid = pthread_self();
	pthread_setname_np(tid, name().c_str());
	while (!isCancelled())
	{
		if(_event.tryWait(300))
		{
			std::set<struct rte_acl_ctx *> to_del;
			_logger.information("Reloading data from files...");
			if(_parent->loadACL(&to_del))
			{
				_logger.error("Unable to load ACLs");
			} else {
				_logger.information("ACLs successfully loaded");
			}
			if(_parent->getTriesManager()->getBLManager()->update())
			{
				_logger.error("Unable to update blacklists");
			} else {
				_logger.information("Blacklists successfully loaded");
			}
			for(auto it = to_del.begin(); it != to_del.end(); it++)
			{
				rte_acl_free(*it);
			}
		}
	}
	_logger.debug("Stopping reload task...");
}
