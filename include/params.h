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
#include <rte_malloc.h>
#include "dtypes.h"
#include "cfg.h"

class FlowStorage;
struct rte_mempool;
class NotifyManager;

struct flow_storage_params_t
{
	int worker_id;
	const uint64_t *p_lifetime;
	rte_mempool *mempool;
	int part_no;
	uint32_t recs_number;
};

struct memory_config_t
{
	uint8_t parts_of_flow; // количество частей, на которое разбивается таблица (для каждого worker'a)
	uint32_t mask_parts_flow; // маска для выбора части = flow_hash & mask_parts_flow
	uint32_t flows_number; // общее количество flows в системе
	uint32_t recs_number; // количество элементов в хэше и массиве для каждого worker'а
};

struct memory_configs_t
{
	memory_config_t ipv4;
	memory_config_t ipv6;
	uint32_t http_entries;
	uint32_t ssl_entries;
};


struct fragmentation_config_t
{
	bool state;
	int table_size;
};

struct fragmentation_configs_t
{
	fragmentation_config_t ipv4;
	fragmentation_config_t ipv6;
};

struct memory_pool_t
{
	rte_mempool *mempool;
	uint32_t entries; // количество элементов
};

struct memory_pools_t
{
	memory_pool_t ssl_entries;
	memory_pool_t http_entries;
};

struct global_params_t
{
	memory_configs_t memory_configs;
	fragmentation_configs_t frag_configs;
	bool tcp_reordering;
	uint8_t workers_number;
	uint64_t flow_lifetime[2]; // [0] для flows, который завершены или установлены без данных, [1] для flows с данными
	uint8_t answer_duplication;
	operation_modes operation_mode;
	bool jumbo_frames;
	unsigned int max_pkt_len;
};

struct common_data_t
{
	memory_pools_t mempools;
};

struct flow_storage_t
{
	FlowStorage **flows; // количество из memory_configs.[ipv4|ipv6].parts_of_flow
};

struct worker_params_t
{
	flow_storage_t flows_ipv4;
	flow_storage_t flows_ipv6;
	bool notify_enabled;
	NotifyManager *nm;
	uint8_t sender_port;
	uint16_t tx_queue_id;
} __rte_cache_aligned;

struct lcore_params {
	uint8_t port_id;
	uint8_t port_type;
	uint8_t queue_id;
	uint8_t lcore_id;
	uint8_t mapto;
} __rte_cache_aligned;

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t port_type;
	uint8_t queue_id;
} __rte_cache_aligned;

struct mbuf_table
{
	uint16_t len;
	struct rte_mbuf* m_table[EXTFILTER_CAPTURE_BURST_SIZE];
};

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	struct rte_acl_ctx *cur_acx_ipv4, *new_acx_ipv4;
	struct rte_acl_ctx *cur_acx_ipv6, *new_acx_ipv6;
	uint8_t sender_port;
	uint16_t n_tx_port;
	uint16_t tx_queue;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

struct filter_tx
{
	struct mbuf_table *mbuf;
	bool to_client;
};


extern const global_params_t *global_prm;
extern common_data_t *common_data;
extern worker_params_t worker_params[MAX_WORKER_THREADS];
