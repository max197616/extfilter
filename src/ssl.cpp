#include <rte_config.h>
#include <rte_memcpy.h>
/*
   SSL packet parser with state for better perfomance.
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ssl.h"

#define DPI_DEBUG_SSL 1


#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define SSL_MAX_TLS_PACKET 4095
#define TLS_HEADER_LEN 5

static ssl_state_parse_change_t ssl_state_parse_change[] =
{
	{ ssl_wp_len_1byte, 1 }, //0 after Random
	{ ssl_wp_skip, 0 }, //1 after Session ID Length
	{ ssl_wp_len_2bytes, 2 }, //2 after Session ID
	{ ssl_wp_skip, 0 }, //3 after Cipher Length
	{ ssl_wp_len_1byte, 1 }, //4 after Cipher
	{ ssl_wp_skip, 0 }, //5 after Compression Method length
	{ ssl_wp_exts_len_2bytes, 2 }, //6 after Compression Methods
	{ ssl_wp_ext_type, 0 }, //7 after Extensions length
	{ ssl_wp_len_2bytes, 2 }, //8 after Extension Type
	{ ssl_wp_len_2bytes, 2 }, //9 Extension Server Name length
	{ ssl_wp_ext_serv_list, 1 }, //10 Extension Server Name list
	{ ssl_wp_ext_serv_type, 0 }, //11 Extension Server Name type
	{ ssl_wp_len_2bytes, 2 }, //12 Server Name
	{ ssl_wp_ext_serv_name, 0 }, //13 Server Name
	{ ssl_wp_pdu, 0 }, //14 Empty1
	{ ssl_wp_pdu, 0 }, //15 Empty2
	{ ssl_wp_pdu, 0 }, //16 Empty3
	{ ssl_wp_ext_data, 0 }, //17 after Extension length
	{ ssl_wp_len_2bytes, 2 } //18 after Extension type
};

static inline bool ssl_check_state(int a, ssl_state *state)
{
	if(a >= 0)
	{
		if(state->parsed_len <= state->total_len || state->total_len <= 0)
			return true;
	}
	return false;
}

// args:
// pos - current position
// buf - pointer to pyaload
// size - size of the payload
// state - state of the current flow
static inline int ssl_parse_len_2bytes(int pos, const uint8_t *buf, int size, ssl_state *state)
{
	int res;
	uint16_t old_skip_size = state->skip_size;
	if(old_skip_size > size - pos) // not all packet
	{
		state->parsed_len += size - pos;
		state->buf[0] = buf[pos];
		state->skip_size += pos - size;
		res = size;
	} else {
		if(state->skip_size == 2)
		{
			state->parsed_len += 2;
			state->skip_size = (buf[pos] << 8) + buf[pos + 1];
		} else {
			state->parsed_len += state->skip_size;
			state->skip_size = buf[pos] + (state->buf[0] << 8);
			state->buf[0] = 0;
		}
		if(state->wp == ssl_wp_exts_len_2bytes)
		{
			if(state->skip_size + state->parsed_len > state->total_len)
			{
				return -1;
			}
		}
		res = pos + old_skip_size;
		state->wp = ssl_state_parse_change[state->state_idx].next_state;
		uint16_t nsl = ssl_state_parse_change[state->state_idx].next_state_size;
		if(nsl > 0)
			state->skip_size = nsl;
		state->state_idx++;
	}
	return res;
}

int parse_ssl(const unsigned char* app_data, uint32_t data_length, ssl_state *state)
{
	uint8_t *p_buf = &state->buf[0];
	uint32_t pos = 0;
	bool stop = false;
	do
	{
		if(state->total_len && state->total_len <= state->parsed_len)
			break;
		switch(state->wp)
		{
			case ssl_wp_header: if(data_length + state->parsed_len - pos <= 4)
					{
						if(data_length - pos + state->parsed_len > SSL_BUF_SIZE -1)
						{
							return -1;
						}
						for(uint16_t i = 0; i < data_length - pos; i++)
							p_buf[state->parsed_len++] = app_data[pos+i];
						if(!ssl_check_state(data_length, state))
							return -1;
						stop = true;
					} else {
						int offset;
						const uint8_t *buf;

						if(state->parsed_len > 0)
						{
							offset = TLS_HEADER_LEN - state->parsed_len;
							if(offset < 0)
							{
								return -1;
							}
							rte_memcpy(&state->buf[state->parsed_len], app_data, offset);
							buf = p_buf;
						} else {
							offset = TLS_HEADER_LEN;
							buf = &app_data[pos];
						}
						state->content_type = *buf;
						state->tls_version_major = buf[1];
						state->tls_version_minor = buf[2];
						state->total_len = (buf[3] << 8) + buf[4] + TLS_HEADER_LEN /* SSL Header */;
						if(state->total_len <= 8 || state->total_len > SSL_MAX_TLS_PACKET)
						{
							return -1;
						}
						state->wp = ssl_wp_handshake_hdr;
						if(state->content_type != TLS_HANDSHAKE_CONTENT_TYPE)
						{
							return -1;
						}
//							state->wp = ssl_wp_pdu;
						if(state->parsed_len > 0)
						{
							if(state->parsed_len > SSL_BUF_SIZE -1)
							{
								return -1;
							}
							memset(p_buf, 0, offset);
						}
						pos += offset;
						state->parsed_len += pos;
						if(!ssl_check_state(pos, state))
							return -1;
					}
					break;

			case ssl_wp_handshake_hdr:
						if(data_length - pos + state->parsed_len <= 8)
						{
							if(state->parsed_len - TLS_HEADER_LEN > SSL_BUF_SIZE - 1 || data_length - pos < 0 || state->parsed_len - TLS_HEADER_LEN + data_length - pos > SSL_BUF_SIZE - 1)
							{
								return -1;
							}
							for(uint16_t i = 0; i < data_length - pos; i++, state->parsed_len++)
								p_buf[state->parsed_len - TLS_HEADER_LEN] = app_data[pos+i];
							if(!ssl_check_state(data_length, state))
							{
								return -1;
							}
							stop = true;
						} else {
							int offset = 9 - state->parsed_len;
							if(offset < 0)
							{
								return -1;
							}
							uint8_t *buf;
							if(state->parsed_len > TLS_HEADER_LEN)
							{
								for(int i = 0; i < offset; i++)
									p_buf[state->parsed_len + i] = app_data[i];
								buf = p_buf;
							} else {
								buf = (uint8_t *)&app_data[pos];
							}
							uint8_t hs_type = *buf;
							state->handshake_type = hs_type;
							if(hs_type != 2 && hs_type != 11)
							{
								if(hs_type == 1) // client hello
								{
									state->skip_size = 34;
									state->wp = ssl_wp_skip;
									state->state_idx = 0;
								} else {
									state->wp = ssl_wp_pdu;
								}
							} else {
								state->wp = ssl_wp_begin_cmnname;
							}
							if(state->parsed_len - TLS_HEADER_LEN > SSL_BUF_SIZE - 1)
							{
								return -1;
							}
							if(state->parsed_len != TLS_HEADER_LEN)
							{
								memset(p_buf, 0, state->parsed_len - TLS_HEADER_LEN);
							}
							pos += offset;
							state->parsed_len += offset;
							if(!ssl_check_state(pos, state))
							{
								return -1;
							}
						}
						break;

			case ssl_wp_begin_cmnname:
					{
						uint16_t npos = state->parsed_len;
						if(data_length > pos)
						{
							if(state->total_len > npos)
							{
								uint8_t ch = state->buf[1];
								const uint8_t *p = &app_data[pos];
								while(1)
								{
									if(state->buf[0] == 0x55 && state->buf[1] == 0x04)
									{
										if(*p == 3)
										{
											state->wp = ssl_wp_size_cmnname;
											state->cmnname_pos = npos + 1;
										}
									}
									npos++;
									state->buf[0] = ch;
									pos++;
									state->parsed_len = npos;
									ch = *p;
									state->buf[1] = *p;
									if(data_length <= pos)
										break;
									p++;
									if(state->total_len <= npos)
									{
										state->reset();
										break;
									}
								}
								if(npos > state->total_len)
									state->reset();
							} else {
								state->reset();
							}
						} else {
							if(npos >= state->total_len)
							{
								state->reset();
							}
						}
						break;
					}

			case ssl_wp_size_cmnname:
						state->buf[0] = 0;
						state->buf[1] = 0;
						if(state->cmnname_pos + 1 == state->parsed_len)
						{
							state->cmnname_size = app_data[pos];
							state->cmnname_pos = state->parsed_len + 1;
							state->cmnname_found++;
							state->wp = state->cmnname_found == 2 ? ssl_wp_cmnname : ssl_wp_skip_cmnname;
						}
						pos++;
						state->parsed_len++;
						break;

			case ssl_wp_skip_cmnname:
					{
						int z = state->cmnname_pos + state->cmnname_size - state->parsed_len;
						int i = data_length - pos;
						if(z > i)
						{
							state->parsed_len += i;
							if(!ssl_check_state(data_length, state))
								return -1;
							stop = true;
						} else {
							if(z < 0)
							{
								return -1;
							}
							pos += z;
							state->wp = ssl_wp_begin_cmnname;
							state->parsed_len += z;
							state->cmnname_pos = 0;
							if(!ssl_check_state(pos, state))
								return -1;
						}
						break;
					}

			case ssl_wp_cmnname:
					{
						int i = data_length - pos;
						int z = state->cmnname_size + state->cmnname_pos - state->parsed_len;
						if(z > i)
						{
							if(i < 0 || i + state->parse_cmnname > SSL_BUF_SIZE - 1)
							{
								return -1;
							}
							for(int l = 0; l < i; l++)
								p_buf[state->parse_cmnname++] = app_data[pos+l];
							state->parsed_len += i;
							pos = data_length;
							if(!ssl_check_state(data_length, state))
								return -1;
						} else {
							if(z < 0)
							{
								return -1;
							}
							if(state->cmnname_size + state->cmnname_pos != state->parsed_len)
							{
								if(z + state->parse_cmnname > SSL_BUF_SIZE - 1)
									return -1;
								for(int l = 0; l < z; l++)
									p_buf[state->parse_cmnname + l] = app_data[pos + l];
								z = state->cmnname_size + state->cmnname_pos - state->parsed_len;
							}
							pos += z;
							state->parsed_len += z;
							state->wp = ssl_wp_pdu;
							state->parse_cmnname = state->parse_cmnname + z;
							state->buf[state->parse_cmnname] = 0;
						}
						break;
					}
			case ssl_wp_skip:
					if(state->skip_size >= data_length - pos)
					{
						state->parsed_len += data_length - pos;
						state->skip_size = state->skip_size - data_length + pos;
						stop = true;
					} else {
						state->parsed_len += state->skip_size;
						pos += state->skip_size;
						state->wp = ssl_state_parse_change[state->state_idx].next_state;
						state->skip_size = ssl_state_parse_change[state->state_idx].next_state_size;
						state->state_idx++;
					}
					break;

			case ssl_wp_len_1byte:
			case ssl_wp_ext_serv_list:
					state->skip_size = app_data[pos++];
					state->parsed_len++;
					state->wp = ssl_state_parse_change[state->state_idx++].next_state;
					break;

			case ssl_wp_len_2bytes:
			case ssl_wp_ext_len:
			case ssl_wp_exts_len_2bytes:
					{
						int new_pos = ssl_parse_len_2bytes(pos, app_data, data_length, state);
						if(new_pos < 0)
						{
							return -1;
						}
						pos = new_pos;
						break;
					}

			case ssl_wp_ext_type:
					if(state->skip_size)
					{
						if(app_data[pos] == 0 && app_data[pos+1] == 0) // server name extension
						{
							state->state_idx = 9;
						} else {
							state->state_idx = 17;
						}
						state->skip_size = 2;
						state->wp = ssl_wp_len_2bytes;
					} else {
						state->wp = ssl_state_parse_change[state->state_idx].next_state;
						state->skip_size = ssl_state_parse_change[state->state_idx].next_state_size;
					}
					pos += 2;
					state->parsed_len += 2;
					break;

			case ssl_wp_ext_serv_type:
						if(state->skip_size)
						{
							state->wp = ssl_wp_pdu;
						} else {
							state->wp = ssl_state_parse_change[state->state_idx].next_state;
							state->skip_size = ssl_state_parse_change[state->state_idx].next_state_size;
							state->state_idx++;
						}
						break;

			case ssl_wp_ext_serv_name:
						if(state->skip_size <= SSL_BUF_SIZE - 1)
						{
							state->wp = ssl_wp_copy_sni;
							state->cmnname_size = 0;
						} else {
							return -1;
						}
						break;

			case ssl_wp_copy_sni:
					{
						int i = data_length - pos;
						int j = state->skip_size - state->cmnname_size;
						if(i < j)
						{
							rte_memcpy(&state->buf[state->cmnname_size], &app_data[pos], i);
							state->parsed_len += i;
							state->cmnname_size += i;
							pos = data_length;
							state->buf[state->cmnname_size] = 0;
						} else {
							rte_memcpy(&state->buf[state->cmnname_size], &app_data[pos], j);
							state->cmnname_size += j;
							state->skip_size = 0;
							state->wp = ssl_wp_pdu;
							state->buf[state->cmnname_size] = 0;
							state->parsed_len = state->total_len;
							stop = true;
						}
						break;
					}

			case ssl_wp_ext_data:
					if(state->skip_size > data_length - pos)
					{
						state->parsed_len += data_length - pos;
						state->skip_size = state->skip_size - data_length + pos;
						stop = true;
					} else {
						state->parsed_len += state->skip_size;
						pos += state->skip_size;
						state->skip_size = 2;
						state->wp = ssl_wp_ext_type;
						state->state_idx = 9;
					}
					break;

			case ssl_wp_pdu:
					if(data_length - pos + state->parsed_len <= state->total_len)
					{
						state->parsed_len += data_length - pos;
						pos = data_length;
						if(!ssl_check_state(data_length, state))
							return -1;
					} else {
						if(state->cmnname_size > 0)
						{
							state->parsed_len = state->total_len;
							pos += state->total_len - state->parsed_len;
							if(!ssl_check_state(pos, state))
								return -1;
						} else {
							pos += state->total_len - state->parsed_len;
							state->reset();
							if(!ssl_check_state(pos, state))
								return -1;
						}
					}
					break;

			default:
				return -1;
				break;
		}
	} while (data_length > pos && !stop);
	if(state->wp != ssl_wp_pdu)
	{
		if(state->total_len <= 0 || state->total_len > state->parsed_len)
			return 2;
		return 0;
	}
	return state->cmnname_size > 0;
}
