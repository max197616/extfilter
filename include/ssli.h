#pragma once

#include "ssl.h"

#include "api.h"

class WorkerThread;

int init_ssl_inspector(rte_mempool *mempool, WorkerThread *wt);
uint8_t ssl_inspector(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* payload, u_int32_t data_length, dpi_tracking_informations_t* t);
