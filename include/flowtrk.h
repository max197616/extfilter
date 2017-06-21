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

#pragma once

#include <vector>
#include <array>
#include <map>
#include <functional>
#include <stdint.h>
#include "datatrk.h"

class FlowTracker
{
public:
	enum State
	{
		UNKNOWN,
		SYN_SENT,
		ESTABLISHED,
		FIN_SENT,
		RST_SENT
	};
	/** 
	 * The type used to store the payload
	 */
	typedef DataTracker::payload_type payload_type;

	/**
	 * The type used to store the buffered payload
	 */
	typedef DataTracker::buffered_payload_type buffered_payload_type;

	/**
	 * The type used to store the callback called when new data is available
	 */
	typedef std::function<void(FlowTracker&, void *)> data_available_callback_type;

	FlowTracker();
	~FlowTracker();

	/**
	 * \brief Sets the callback that will be executed when data is readable
	 *
	 * Whenever this flow has readable data, this callback will be executed.
	 * By readable, this means that there's non-out-of-order data captured.
	 *
	 * \param callback The callback to be executed   
	 */
	void data_callback(const data_available_callback_type& callback, void *user_data);

	/**
	 * \brief Processes a packet.
	 *
	 * If this packet contains data and starts or overlaps with the current
	 * sequence number, then the data will be appended to this flow's payload
	 * and the data_callback will be executed.
	 *
	 * If this packet contains out-of-order data, it will be buffered and the
	 * buffering_callback will be executed.
	 *
	 */
	void process_packet(uint8_t *tcp_header, uint8_t *payload, int payload_len);

	/**
	 * \brief Skip forward to a sequence number
	 *
	 * This allows to recover from packet loss, if we just do not see all packets of
	 * an original stream. This recovery can only sensibly triggered from the application
	 * layer.
	 *
	 * This method is particularly useful to call from an out of order callback, if
	 * the application wants to skip forward to this out of order block. The application
	 * will then get the normal data callback!
	 *
	 * IMPORTANT: If you call this method with a sequence number that is not exactly a
	 * TCP fragment boundary, the flow will never recover from this.
	 *
	 * \param seq The sequence number to skip to.
	 */
	void advance_sequence(uint32_t seq);

	/**
	 * \brief Indicates whether this flow is finished
	 *
	 * A finished is considered to be finished if either it sent a
	 * packet with the FIN or RST flags on. 
	 */
	bool is_finished() const;

	/**
	 * \brief Indicates whether a packet belongs to this flow
	 *
	 * Since Flow represents a unidirectional stream, this will only check
	 * the destination endpoint and not the source one.
	 *
	 * \param packet The packet to be checked
	 */
	bool packet_belongs(uint8_t *tcp_header) const;

	/** 
	 * Retrieves this flow's payload (const)
	 */
	const payload_type& payload() const;

	/** 
	 * Retrieves this flow's payload
	 */
	payload_type& payload();

	/** 
	 * Retrieves this flow's state
	 */
	State state() const;

	/** 
	 * Retrieves this flow's sequence number
	 */
	uint32_t sequence_number() const;

	/** 
	 * Retrieves this flow's buffered payload (const)
	 */
	const buffered_payload_type& buffered_payload() const;

	/** 
	 * Retrieves this flow's buffered payload
	 */
	buffered_payload_type& buffered_payload();

	/**
	 * Retrieves this flow's total buffered bytes
	 */
	uint32_t total_buffered_bytes() const;

	/**
	 * Sets the state of this flow
	     *
	     * \param new_state The new state of this flow
	     */
	void state(State new_state);

	/**
	 * \brief Sets whether this flow should ignore data packets
	 *
	 * If the data packets are ignored then the flow will just be 
	 * followed to keep track of its state.
	 */
	void ignore_data_packets();

	/**
	 * \brief Returns the MSS for this Flow.
	 *
	 * If the MSS option wasn't provided by the peer, -1 is returned
	 */
	int mss() const;

	/**
	 * \brief Indicates whether this Flow supports selective acknowledgements
	 */
	bool sack_permitted() const;


private:
	struct flags
	{
		flags() : is_v6(0), ignore_data_packets(0), sack_permitted(0), ack_tracking(0)
		{
		}

		uint32_t is_v6:1,
			 ignore_data_packets:1,
			 sack_permitted:1,
			 ack_tracking:1;
	};

	// seq in cpu order!
	void update_state(uint8_t tcp_flag, uint32_t seq);
	void initialize();

	data_available_callback_type _on_data_callback;
	void *_user_data;
	DataTracker _data_tracker;
	State state_;
	int mss_;
	flags flags_;

};