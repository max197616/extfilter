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
