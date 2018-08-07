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

#include <rte_config.h>
#include <rte_lcore.h>

class DpdkWorkerThread
{
public:
	virtual ~DpdkWorkerThread() {}
	virtual bool run(uint32_t coreId) = 0;
	virtual void stop() = 0;
	inline uint32_t getCoreId()
	{
		return m_CoreId;
	}
	inline void setCoreId(uint32_t core_id)
	{
		m_CoreId=core_id;
	}
private:
	uint32_t m_CoreId;
};


inline int dpdkWorkerThreadStart(void *ptr)
{
	DpdkWorkerThread* workerThread = (DpdkWorkerThread*)ptr;
	workerThread->run(rte_lcore_id());
	return 0;
}
