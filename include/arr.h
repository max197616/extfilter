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

#define DPDK_MEMALLOC 1

#ifdef DPDK_MEMALLOC
#include <rte_config.h>
#include <rte_malloc.h>
#endif

enum en_alfs_type_t
{
	en_alfs_short,
	en_alfs_long
};

// массив с самыми старыми записями в начале и самыми свежими в конце.
// в голове массива всегда самая старая запись
template <typename T>
class ArrayListFixedSize
{
private:
	struct node
	{
		T *p_flow;
		uint32_t next;
		uint32_t prev;
	} __rte_cache_aligned;

	uint64_t lifetime;
	uint32_t cnt;
	node *p_nodes_arr;
	uint32_t head;
	uint32_t tail;
	uint8_t worker_id;
	en_alfs_type_t alfs_type;
	uint32_t max_view_list;
	uint32_t allocated;

public:
	struct cntrs
	{
		uint64_t err_alloc;
		uint64_t alien_rec;
		uint64_t oldest;
	} counters;

	ArrayListFixedSize()
	{
		counters = { 0 };
		cnt = 0;
		max_view_list = 0;
		worker_id = 0;
		head = -1;
		tail = -1;
	}

	~ArrayListFixedSize()
	{
#ifdef DPDK_MEMALLOC
		rte_free(p_nodes_arr);
#else
		delete p_nodes_arr;
#endif
	}

	inline uint32_t getAllocated()
	{
		return allocated;
	}

	inline int init(u_int32_t n_entries, int worker_id_, en_alfs_type_t alfs_type_, uint64_t lifetime_, u_int32_t max_view_list_)
	{
		alfs_type = alfs_type_;
		max_view_list = max_view_list_;
		worker_id = worker_id_;
		lifetime = lifetime_;
#ifdef DPDK_MEMALLOC
		p_nodes_arr = (ArrayListFixedSize<T>::node *)rte_zmalloc(NULL, sizeof(struct node) * n_entries, RTE_CACHE_LINE_SIZE);
#else
		p_nodes_arr = new (std::nothrow) node[n_entries];
#endif
		if(p_nodes_arr != nullptr)
		{
			memset(p_nodes_arr, 0, sizeof(node) * n_entries);
			allocated = n_entries;
			return 0;
		}
		return -1;
	}

	inline void moveBackRec(uint32_t rec_id)
	{
		if(rec_id != tail)
		{
			node *need_node = &p_nodes_arr[rec_id];
			if(rec_id == head)
			{
				uint32_t next_idx = need_node->next;
				head = next_idx;
				need_node->next = -1;
				p_nodes_arr[next_idx].prev = -1;
				need_node->prev = tail;
				p_nodes_arr[tail].next = rec_id;
			} else {
				p_nodes_arr[need_node->prev].next = need_node->next;
				p_nodes_arr[need_node->next].prev = need_node->prev;
				need_node->prev = tail;
				p_nodes_arr[tail].next = rec_id;
				need_node->next = -1;
			}
			tail = rec_id;
		}
	}

	// передвигает записи с номером idx_alfs в конец массива. обновляется всемя последней модификации записи...
	inline void moveBack(T *r, uint64_t timestamp, ArrayListFixedSize<T> *other_alfs)
	{
		uint32_t idx_alfs = r->cmn.idx_alfs;
		r->cmn.last_timestamp = timestamp;
		moveBackRec(idx_alfs);
		other_alfs->moveBackRec(idx_alfs);
	}

	inline T *getOldestMoveBack(uint64_t timestamp, ArrayListFixedSize<T> *p_bind_alfs_)
	{
		if(tail == -1 || max_view_list == 0)
			return nullptr;
		node *oldest_node = &p_nodes_arr[head]; // at the head always oldest node...
		T *result = oldest_node->p_flow;
		uint32_t next_node_idx = oldest_node->next;
		if(oldest_node->p_flow->cmn.alfs_type == alfs_type)
		{
			if(lifetime <= (timestamp - result->cmn.last_timestamp)) // expired
			{
				moveBack(result, timestamp, p_bind_alfs_);
				counters.oldest++;
				return result;
			}
			return nullptr;
		}
		uint64_t old_aliens = counters.alien_rec;
		while(next_node_idx != -1 && max_view_list > (counters.alien_rec - old_aliens))
		{
			counters.alien_rec++;
			moveBackRec(result->cmn.idx_alfs);
			result = p_nodes_arr[next_node_idx].p_flow;
			next_node_idx = p_nodes_arr[next_node_idx].next;
			if(result->cmn.alfs_type == alfs_type)
			{
				if(lifetime <= (timestamp - result->cmn.last_timestamp)) // expired
				{
					moveBack(result, timestamp, p_bind_alfs_);
					counters.oldest++;
					return result;
				}
				return nullptr;
			}
		}
		return nullptr;
	}

	// добавляет запись в конец массива, т.к. она самая свежая
	inline void add_rec(T *p_)
	{
		p_->cmn.idx_alfs = cnt;
		node *nodes = p_nodes_arr;
		nodes[cnt].next = -1;
		nodes[cnt].p_flow = p_;
		if(unlikely(head == -1)) // first element
		{
			head = cnt;
			nodes[cnt].prev = -1;
			nodes[cnt].next = -1;
		} else {
			nodes[tail].next = cnt;
			nodes[cnt].prev = tail;
		}
		tail = cnt;
		cnt++;
	}

	inline bool can_add_rec()
	{
		if(cnt < allocated)
			return true;
		counters.err_alloc++;
		return false;
	}
};
