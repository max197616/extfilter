
#include "flow.h"

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

//#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
//#else
//#include <rte_jhash.h>
//#define DEFAULT_HASH_FUNC       rte_jhash
//#endif

rte_xmm_t mask0 = {.u32 = {BIT_8_TO_15, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS} };
rte_xmm_t mask1 = {.u32 = {BIT_16_TO_23, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS} };
rte_xmm_t mask2 = {.u32 = {ALL_32_BITS, ALL_32_BITS, 0, 0} };


