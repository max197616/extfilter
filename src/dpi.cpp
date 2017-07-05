#include <api.h>
#include <flow_table.h>
#include <string.h>
#include <iostream>
#include "dpi.h"

ipv4_flow_t* dpi_flow_table_find_or_create_flow_v4_new(dpi_library_state_t* state, dpi_pkt_infos_t* pkt_infos, uint32_t hash)
{
	return mc_dpi_flow_table_find_or_create_flow_v4(
			state, 0,
			dpi_compute_hash_v4_function_new((dpi_flow_DB_v4_t *)state->db4, hash),
			pkt_infos);
}

ipv6_flow_t* dpi_flow_table_find_or_create_flow_v6_new(dpi_library_state_t* state, dpi_pkt_infos_t* pkt_infos, uint32_t hash)
{
	return mc_dpi_flow_table_find_or_create_flow_v6(
			state, 0,
			dpi_compute_hash_v6_function_new((dpi_flow_DB_v6_t *)state->db6, hash),
			pkt_infos);
}


dpi_identification_result_t dpi_stateful_get_app_protocol_new(dpi_library_state_t *state, dpi_pkt_infos_t* pkt_infos, uint32_t hash)
{
	dpi_identification_result_t r;
	r.status=DPI_STATUS_OK;

	dpi_flow_infos_t* flow_infos=NULL;
	ipv4_flow_t* ipv4_flow=NULL;
	ipv6_flow_t* ipv6_flow=NULL;

	if(pkt_infos->ip_version==DPI_IP_VERSION_4){
		ipv4_flow=dpi_flow_table_find_or_create_flow_v4_new(state, pkt_infos, hash);
		if(ipv4_flow)
			flow_infos=&(ipv4_flow->infos);
	}else{
		ipv6_flow=dpi_flow_table_find_or_create_flow_v6_new(state, pkt_infos, hash);
		if(ipv6_flow)
			flow_infos=&(ipv6_flow->infos);
	}

	if(unlikely(flow_infos==NULL)){
		r.status=DPI_ERROR_MAX_FLOWS;
		return r;
	}

	r=dpi_stateless_get_app_protocol(state, flow_infos, pkt_infos);

	if(r.status==DPI_STATUS_TCP_CONNECTION_TERMINATED){
		if(ipv4_flow!=NULL){
			dpi_flow_table_delete_flow_v4((dpi_flow_DB_v4_t *)state->db4, state->flow_cleaner_callback, ipv4_flow);
		}else{
			dpi_flow_table_delete_flow_v6((dpi_flow_DB_v6_t *)state->db6, state->flow_cleaner_callback, ipv6_flow);
		}
	}
	return r;
}

dpi_identification_result_t dpi_stateful_identify_application_protocol_new(dpi_library_state_t* state, const unsigned char* pkt, u_int32_t length, u_int32_t current_time, uint32_t hash)
{
	dpi_identification_result_t r;
	r.status=DPI_STATUS_OK;
	dpi_pkt_infos_t infos;
	memset(&infos, 0, sizeof(infos));
	u_int8_t l3_status;

	r.status=dpi_parse_L3_L4_headers(state, pkt, length, &infos, current_time);

	if(unlikely(r.status==DPI_STATUS_IP_FRAGMENT || r.status<0)){
		return r;
	}

	if(infos.l4prot!=IPPROTO_TCP && infos.l4prot!=IPPROTO_UDP){
		r.status=DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
		return r;
	}

	l3_status=r.status;
	r.status=DPI_STATUS_OK;
	/**
	 * We return the status of dpi_stateful_get_app_protocol call,
	 * without giving informations on status returned
	 * by dpi_parse_L3_L4_headers. Basically we return the status which
	 * provides more informations.
	 */
	r=dpi_stateful_get_app_protocol_new(state, &infos, hash);

	if(l3_status==DPI_STATUS_IP_LAST_FRAGMENT){
		free((unsigned char*) infos.pkt);
	}

	return r;
}

