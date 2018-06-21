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

// maximum active threads
#define MAX_WORKER_THREADS 10

#define DEFAULT_MBUF_POOL_SIZE 8191
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_LCORE_PARAMS 1024
#define NB_SOCKETS 4
#define MAX_RX_QUEUE_PER_PORT 128
#define EXTF_RX_DESC_DEFAULT 256
#define EXTF_TX_DESC_DEFAULT 512
#define PERCENT_URL_ENTRIES 0.20

#define MAX_JUMBO_PKT_LEN  9600

#define EXTFILTER_CAPTURE_BURST_SIZE 32
#define EXTFILTER_WORKER_BURST_SIZE EXTFILTER_CAPTURE_BURST_SIZE
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MAX_REDIRECT_URL_SIZE 1189


const char r_line1[] = "HTTP/1.1 302 Moved Temporarily\r\n";
const char r_line2[] = "Location: ";
const char r_line3[] = "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const char f_lines[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

const char uri_p[] = "uri=http%3A%2F%2F";

#define OUR_REDIR_SIZE (sizeof(r_line1) + sizeof(r_line2) + sizeof(r_line3) - 3)
#define OUR_PAYLOAD_SIZE 1400


