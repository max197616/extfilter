#pragma once

#include <stdlib.h>
#include <stdint.h>

struct dpi_flow_info
{
	char *url;
	uint16_t url_size;
	char *host;
	uint16_t host_size;
	void free_mem()
	{
		if(url)
			free(url);
		if(host)
			free(host);
	}
};

