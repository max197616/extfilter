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

dpi_identification_result_t dpi_stateful_identify_application_protocol_new(dpi_library_state_t* state, const unsigned char* pkt, u_int32_t length, u_int32_t current_time, uint32_t hash);