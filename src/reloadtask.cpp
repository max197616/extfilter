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

#include "dtypes.h"
#include "reloadtask.h"
#include "main.h"
#include "AhoCorasickPlus.h"
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
	while (!isCancelled())
	{
		if(_event.tryWait(300))
		{
			_logger.information("Reloading data from files...");

			if(_parent->getACL()->initACL(_parent->getHostsFile(), _parent->getSSLIpsFile(), _parent->extFilter::getNuma()) != 0)
			{
				_logger.error("Unable to reload ACLs");
			} else {
				_logger.information("ACLs successfully reloaded");
			}

			for(std::vector<DpdkWorkerThread*>::iterator it=workerThreadVec.begin(); it != workerThreadVec.end(); it++)
			{
				if(dynamic_cast<WorkerThread*>(*it) == nullptr)
					continue;
				WorkerConfig& config=(static_cast<WorkerThread*>(*it))->getConfig();
				AhoCorasickPlus *to_del_atm;
				DomainsMatchType *to_del_dm;
				AhoCorasickPlus *atm_new;
				DomainsMatchType *dm_new;
				EntriesData *datas_new;
				if(!_parent->getSSLFile().empty())
				{
					atm_new = new AhoCorasickPlus();
					dm_new = new DomainsMatchType;
					try
					{
						_parent->loadDomains(_parent->getSSLFile(), atm_new, dm_new);
						atm_new->finalize();
						config.atmSSLDomainsLock.lock();
						to_del_atm = config.atmSSLDomains;
						to_del_dm = config.SSLdomainsMatchType;
						config.atmSSLDomains = atm_new;
						config.SSLdomainsMatchType = dm_new;
						config.atmSSLDomainsLock.unlock();
						delete to_del_atm;
						delete to_del_dm;
						_logger.information("Reloaded data for ssl domains list for core %u", (*it)->getCoreId());
					} catch (Poco::Exception &excep)
					{
						_logger.error("Got exception while reload ssl data: %s", excep.displayText());
						delete atm_new;
						delete dm_new;
					}
				}
				if(!_parent->getDomainsFile().empty() && !_parent->getURLsFile().empty())
				{
					atm_new = new AhoCorasickPlus();
					datas_new = new EntriesData();
					EntriesData *datas_del;
					try
					{
						_parent->loadDomainsURLs(_parent->getDomainsFile(), _parent->getURLsFile(), atm_new, datas_new);
						atm_new->finalize();
						config.atmLock.lock();
						to_del_atm = config.atm;
						config.atm = atm_new;
						datas_del = config.entriesData;
						config.entriesData = datas_new;
						config.atmLock.unlock();
						delete to_del_atm;
						delete datas_del;
						_logger.information("Reloaded data for domains and urls list for core %u", (*it)->getCoreId());
					} catch (Poco::Exception &excep)
					{
						_logger.error("Got exception while reload domains and urls data: %s", excep.displayText());
						delete atm_new;
						delete datas_new;
					}
				}
			}
		}
	}
	_logger.debug("Stopping reload task...");
}
