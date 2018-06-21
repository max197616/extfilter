
#pragma once

#include "worker.h"

class BWorkerThread: public WorkerThread
{
public:
	BWorkerThread(uint8_t worker_id, const std::string& name, WorkerConfig &workerConfig, dpi_library_state_t* state, struct ESender::nparams &sp, struct rte_mempool *mp);
	~BWorkerThread() {}

	bool run(uint32_t coreId);
};

