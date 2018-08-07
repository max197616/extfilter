

#ifndef __ssl_h
#define __ssl_h

#include <stdint.h>
#include <memory.h>
#include <rte_config.h>
#include <rte_malloc.h>
#include "dtypes.h"

enum ssl_wp_t
{
	ssl_wp_header = 0,
	ssl_wp_handshake_hdr,
	ssl_wp_begin_cmnname,
	ssl_wp_size_cmnname,
	ssl_wp_skip_cmnname,
	ssl_wp_cmnname,
	ssl_wp_skip,
	ssl_wp_len_1byte,
	ssl_wp_len_2bytes,
	ssl_wp_exts_len_2bytes,
	ssl_wp_ext_type,
	ssl_wp_ext_serv_list,
	ssl_wp_ext_serv_type,
	ssl_wp_ext_serv_name,
	ssl_wp_copy_sni,
	ssl_wp_ext_len,
	ssl_wp_ext_data,
	ssl_wp_pdu
};

#define SSL_BUF_SIZE 256

struct ssl_state : pool_holder_t
{
	ssl_wp_t wp;
	uint8_t content_type;
	uint8_t tls_version_major;
	uint8_t tls_version_minor;
	uint8_t handshake_type;
	uint16_t total_len;
	uint16_t parsed_len;
	uint16_t cmnname_pos;
	uint16_t cmnname_size;
	uint16_t parse_cmnname;
	uint16_t cmnname_found;
	uint16_t skip_size;
	uint16_t state_idx;
	uint8_t buf[SSL_BUF_SIZE];

	inline void reset()
	{
		memset(&wp, 0, sizeof(ssl_state) - sizeof(pool_holder_t) - SSL_BUF_SIZE);
	}

	inline void init()
	{
		reset();
		mempool = nullptr;
	}

} __rte_cache_aligned;

struct ssl_state_parse_change_t
{
	ssl_wp_t next_state;
	uint16_t next_state_size;
} __rte_cache_aligned;

/*
	return:
	0 - ssl, without sni
	1 - ssl, with sni
	-1 - not ssl packet
	2 - need more data
*/
int parse_ssl(const unsigned char* app_data, uint32_t data_length, ssl_state *state);

static inline void ssl_init_state(ssl_state *state)
{
	memset(&state->wp, 0, sizeof(ssl_state) - SSL_BUF_SIZE - sizeof(void *));
};


#endif
