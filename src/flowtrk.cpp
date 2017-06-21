/*
 * Copyright (c) 2016, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <rte_config.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>
#include <algorithm>
#include "flowtrk.h"
#include "tcp.h"


#include <iostream>

FlowTracker::FlowTracker()
{
	initialize();
}

FlowTracker::~FlowTracker()
{

}

void FlowTracker::initialize()
{
	state_ = UNKNOWN;
	mss_ = -1;
}

void FlowTracker::data_callback(const data_available_callback_type& callback, void *user_data)
{
	_on_data_callback = callback;
	_user_data = user_data;
}

void FlowTracker::update_state(uint8_t flags, uint32_t seq)
{
	if ((flags & TCP::FIN) != 0)
	{
		state_ = FIN_SENT;
		_data_tracker.sequence_number(seq);
	} else if ((flags & TCP::RST) != 0)
	{
		state_ = RST_SENT;
	} else if (state_ == SYN_SENT && (flags & TCP::ACK) != 0)
	{
		state_ = ESTABLISHED;
	}
	else if (state_ == UNKNOWN && (flags & TCP::SYN) != 0)
	{
		state_ = SYN_SENT;
		_data_tracker.sequence_number(seq + 1);
/*        const TCP::option* mss_option = tcp.search_option(TCP::MSS);
        if (mss_option) {
            mss_ = mss_option->to<uint16_t>();
        }
        flags_.sack_permitted = tcp.has_sack_permitted();*/
        // сделано пока фильтр не видит syn пакетов...
//        } else if (state_ == UNKNOWN && (flags & TCP::ACK) != 0)
	} else if (state_ == UNKNOWN)
        {
		state_ = ESTABLISHED;
		_data_tracker.sequence_number(seq);
        }
}

void FlowTracker::process_packet(uint8_t *tcp_header, uint8_t *payload, int payload_len)
{
	tcp_hdr *tcph = (tcp_hdr *)tcp_header;
	update_state(tcph->tcp_flags, rte_be_to_cpu_32(tcph->sent_seq));
	if(flags_.ignore_data_packets)
		return;
	const uint32_t chunk_end = rte_be_to_cpu_32(tcph->sent_seq) + payload_len;
	const uint32_t current_seq = _data_tracker.sequence_number();
	// If the end of the chunk ends before the current sequence number or
	// if we're going to buffer this and we have a buffering callback, execute it
	if(TCP::sequence_compare(chunk_end, current_seq) < 0 || TCP::sequence_compare(rte_be_to_cpu_32(tcph->sent_seq), current_seq) > 0)
	{
//		std::cout << "out of order! chunk_end:" << chunk_end << " current_seq: " << current_seq << " state: " << state_ <<std::endl;
/*		if (on_out_of_order_callback_)
		{
			on_out_of_order_callback_(*this, tcp->seq(), raw->payload());
		}*/
	}
	// can process either way, since it will abort immediately if not needed
	payload_type _payload;
	_payload.reserve(payload_len);
	_payload.assign(payload, payload + payload_len);
	if (_data_tracker.process_payload(rte_be_to_cpu_32(tcph->sent_seq), _payload))
	{
		if (_on_data_callback)
		{
			_on_data_callback(*this, _user_data);
		}
	}

}

const FlowTracker::payload_type& FlowTracker::payload() const
{
	return _data_tracker.payload();
}

FlowTracker::payload_type& FlowTracker::payload()
{
	return _data_tracker.payload();
}

void FlowTracker::ignore_data_packets()
{
	flags_.ignore_data_packets = true;
}
