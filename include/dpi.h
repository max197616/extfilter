#pragma once

#include <stdlib.h>
#include <stdint.h>

struct dpi_flow_info
{
	char *url;
	uint16_t url_size;
	bool use_pool;
	struct rte_mempool *mempool;
	struct rte_mempool *dpi_mempool;
	void free_mem()
	{
		if(!use_pool)
		{
			if(url)
				free(url);
		} else {
			rte_mempool_put(mempool, url);
		}
	}
};

