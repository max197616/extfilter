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

#include "http.h"
#include "worker.h"

namespace http
{

int on_url_ext (http_parser *p, const char* at, size_t length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	WorkerThread *obj = (WorkerThread *) user_data;
//	if(length > 0 && p->type==HTTP_REQUEST && (p->method == DPI_HTTP_POST || p->method == DPI_HTTP_GET || p->method == DPI_HTTP_HEAD))
	if(length > 0 && p->type==HTTP_REQUEST && p->method == DPI_HTTP_GET)
	{
		struct http_req_buf *d = (struct http_req_buf *) *flow_specific_user_data;
		if(d == nullptr)
		{
			d = obj->allocateHTTPBuf();
			if(unlikely(d == nullptr))
			{
				obj->getStats().dpi_no_mempool_http++;
				return 0;
			}
			*flow_specific_user_data = d;
		}
		if(d->uri.length + length > d->uri.buf_size)
			length = d->uri.buf_size - d->uri.length;
		if(likely(length > 0))
		{
			for(size_t i = 0; i < length; i++)
				d->uri.buf[d->uri.length++] = at[i];
//			rte_memcpy(d->uri.buf + d->uri.length, at, length);
//			d->uri.length += length;
		}
	}
	return 0;
}

int on_header_field_ext(http_parser *p, const char *at, size_t length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	if(*flow_specific_user_data != NULL && length > 0)
	{
		struct http_req_buf *d = (struct http_req_buf *) *flow_specific_user_data;
		for(size_t z = 0; z < length; z++)
		{
			switch (d->h_state)
			{
				case hstate_nothing:
					switch (at[z])
					{
						case 'h':
						case 'H':
							d->h_state = http::hstate_host;
							d->h_prev_char = at[z];
							break;
					}
					break;
				case hstate_host:
					if(((d->h_prev_char == 'h' || d->h_prev_char == 'H') && (at[z] == 'o' || at[z] == 'O')) || ((d->h_prev_char == 'O' || d->h_prev_char == 'o') && (at[z] == 's' || at[z] == 'S')))
					{
						d->h_prev_char = at[z];
						break;
					}
					if((d->h_prev_char == 's' || d->h_prev_char == 'S') && (at[z] == 't' || at[z] == 'T'))
					{
						d->host_r.length = 0;
						break;
					}
					d->h_state = hstate_nothing;
					break;
				default:
					d->h_prev_char = 0;
					d->h_state = hstate_nothing;
					break;
			}
		}
	}
	return 0;
}

int on_header_value_ext(http_parser *p, const char *at, size_t length, dpi_pkt_infos_t* pkt_informations, void** flow_specific_user_data, void* user_data)
{
	if(*flow_specific_user_data != NULL && length > 0)
	{
		struct http::http_req_buf *d = (struct http::http_req_buf *) *flow_specific_user_data;
		switch (d->h_state)
		{
			case http::hstate_host:
				if(d->host_r.length + length > d->host_r.buf_size)
					length = d->host_r.buf_size - d->host_r.length;
				for(size_t i = 0; i < length; i++)
					d->host_r.buf[d->host_r.length++] = at[i];
//				rte_memcpy(d->host_r.buf + d->host_r.length, at, length);
//				d->host_r.length += length;
				break;
			default:
				break;
		}
	}
	return 0;
}



}