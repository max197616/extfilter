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

#include <api.h>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include "dtypes.h"

namespace http {

enum header_state
{
	hstate_nothing = 0,
	hstate_host
};

struct http_rec
{
	char *buf; // указатель на буфер
	uint16_t buf_size; // размер буфера.
	uint16_t length; // длина того, что находится в буфере.
};

struct http_req_buf : pool_holder_t
{
	char url_buf[600];
	char host[255];
	struct http_rec uri;
	struct http_rec host_r;
	header_state h_state;
	char h_prev_char;
	inline void init()
	{
		uri.buf = &url_buf[0];
		uri.buf_size = sizeof(url_buf);
		uri.length = 0;
		url_buf[0] = 0;
		host[0] = 0;
		host_r.buf_size = sizeof(host);
		host_r.buf = &host[0];
		host_r.length = 0;
		h_state = hstate_nothing;
		mempool = nullptr;
	}
} __rte_cache_aligned;

int on_url_ext (http_parser *p, const char* at, size_t length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data);

int on_header_field_ext(http_parser *p, const char *at, size_t length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data);

int on_header_value_ext(http_parser *p, const char *at, size_t length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data);

}
