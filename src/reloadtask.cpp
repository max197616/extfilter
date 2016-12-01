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


Poco::Event ReloadTask::_event;


ReloadTask::ReloadTask(extFilter *parent, std::vector<pcpp::DpdkWorkerThread*> &workerThreadVector):
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
			for(std::vector<pcpp::DpdkWorkerThread*>::iterator it=workerThreadVec.begin(); it != workerThreadVec.end(); it++)
			{
				if(dynamic_cast<WorkerThread*>(*it) == nullptr)
					continue;
				WorkerConfig& config=(static_cast<WorkerThread*>(*it))->getConfig();
				AhoCorasickPlus *to_del_atm;
				DomainsMatchType *to_del_dm;
				AhoCorasickPlus *atm_new;
				DomainsMatchType *dm_new;
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
				if(!_parent->getDomainsFile().empty())
				{
					atm_new = new AhoCorasickPlus();
					dm_new = new DomainsMatchType;
					try
					{
						_parent->loadDomains(_parent->getDomainsFile(),atm_new,dm_new);
						atm_new->finalize();
						config.atmDomainsLock.lock();
						to_del_atm = config.atmDomains;
						to_del_dm = config.domainsMatchType;
						config.atmDomains = atm_new;
						config.domainsMatchType = dm_new;
						config.atmDomainsLock.unlock();
						delete to_del_atm;
						delete to_del_dm;
					_logger.information("Reloaded data for domains list for core %u", (*it)->getCoreId());
					} catch (Poco::Exception &excep)
					{
						_logger.error("Got exception while reload domains data: %s", excep.displayText());
						delete atm_new;
						delete dm_new;
					}
				}
				if(!_parent->getURLsFile().empty())
				{
					atm_new = new AhoCorasickPlus();
					try
					{
						_parent->loadURLs(_parent->getURLsFile(),atm_new);
						atm_new->finalize();
						config.atmLock.lock();
						to_del_atm = config.atm;
						config.atm = atm_new;
						config.atmLock.unlock();
						delete to_del_atm;
						_logger.information("Reloaded data for urls list for core %u", (*it)->getCoreId());
					} catch (Poco::Exception &excep)
					{
						_logger.error("Got exception while reload urls data: %s", excep.displayText());
						delete atm_new;
					}
				}
				if(!_parent->getHostsFile().empty())
				{
					IPPortMap *ip_port_map = new IPPortMap;
					Patricia *newp = new Patricia();
					try
					{
						IPPortMap *old;
						Patricia *old_p;
						_parent->loadHosts(_parent->getHostsFile(),ip_port_map,newp);
						config.ipportMapLock.lock();
						old = config.ipportMap;
						old_p = config.ipPortMap;
						config.ipportMap = ip_port_map;
						config.ipPortMap = newp;
						config.ipportMapLock.unlock();
						delete old;
						delete old_p;
						_logger.information("Reloaded data for ip port list for core %u", (*it)->getCoreId());
					} catch (Poco::Exception &excep)
					{
						_logger.error("Got exception while reload ip port data: %s", excep.displayText());
						delete ip_port_map;
					}
				}
				if(!_parent->getSSLIpsFile().empty() && config.block_undetected_ssl)
				{
					Patricia *ssl_ips = new Patricia;
					try
					{
						_parent->loadSSLIP(_parent->getSSLIpsFile(),ssl_ips);
						Patricia *ssl_ips_old;
						config.sslIPsLock.lock();
						ssl_ips_old = config.sslIPs;
						config.sslIPs = ssl_ips;
						config.sslIPsLock.unlock();
						delete ssl_ips_old;
						_logger.information("Reloaded data for ssl ip list for core %u", (*it)->getCoreId());
					} catch (Poco::Exception &excep)
					{
						_logger.error("Got exception while reload ip ssl data: %s", excep.displayText());
						delete ssl_ips;
					}
				}
			}
		}
	}
	_logger.debug("Stopping reload task...");
}
