
#include "ssli.h"
#include <rte_config.h>
#include <rte_mempool.h>
#include "worker.h"

// for debug only
#include <Poco/Util/ServerApplication.h>

#include <iostream>

uint8_t ssl_inspector(dpi_library_state_t* lib_state, dpi_pkt_infos_t* pkt, const unsigned char* payload, u_int32_t data_length, dpi_tracking_informations_t* t)
{
	uint8_t result = DPI_PROTOCOL_NO_MATCHES;
	WorkerThread *worker = (WorkerThread *) lib_state->ssl_external_inspector_user_data;
	ssl_state *state = (ssl_state *)t->ssl_information[pkt->direction].mempool;
	ssl_state static_state;
	if(state == nullptr)
	{
		// first check
		if(payload[0] != 0x16)
			return result;
		state = worker->allocateSSLState();
		if(unlikely(state == nullptr))
		{
			worker->getStats().dpi_no_mempool_ssl++;
			state = &static_state;
			ssl_init_state(state);
		} else {
			t->ssl_information[pkt->direction].mempool = state;
		}
	}
	int res = parse_ssl(payload, data_length, state);
	switch (res)
	{
		case 0:
		{
			result = DPI_PROTOCOL_MATCHES;
			break;
		}
		case 1:
		{
			worker->setNeedBlock(worker->checkSNIBlocked((const char *)&state->buf[0], state->cmnname_size, pkt));
			result = DPI_PROTOCOL_MATCHES;
			break;
		}
		case 2:
			result = DPI_PROTOCOL_MORE_DATA_NEEDED;
			worker->getStats().dpi_ssl_partial_packets++;
			break;
		case -1:
		{
			if(likely(state->mempool))
				rte_mempool_put(state->mempool, state);
			t->ssl_information[pkt->direction].mempool = nullptr;
			break;
		}
		default:
			break;
	}
	return result;
}

