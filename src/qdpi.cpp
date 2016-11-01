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

#include "qdpi.h"
#include <stdlib.h>
#include <rte_config.h>
#include <rte_malloc.h>

//#define _USE_RTE_MEM

static void *malloc_wrapper(unsigned long size)
{
#ifdef _USE_RTE_MEM
	return rte_zmalloc(NULL,size,RTE_CACHE_LINE_SIZE);
#else
	return calloc(1,size);
#endif
}

static void free_wrapper(void *freeable)
{
#ifdef _USE_RTE_MEM
	rte_free(freeable);
#else
	free(freeable);
#endif
}

#if 0
void debug_printf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...) {
    va_list va_ap;
    struct tm result;

    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /*
    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else.
      extra_msg = "DEBUG: ";
    */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime, &result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    Poco::Util::Application& app = Poco::Util::Application::instance();
    std::string msg(&out_buf[0]);
    app.logger().information("nDPI message: %s",msg);

    fflush(stdout);

    va_end(va_ap);
}
#endif

struct ndpi_detection_module_struct* init_ndpi()
{
	set_ndpi_malloc(malloc_wrapper);
	set_ndpi_free(free_wrapper);
	struct ndpi_detection_module_struct* my_ndpi_struct = ndpi_init_detection_module();

	if (my_ndpi_struct == NULL) {
		return NULL;
	}

	my_ndpi_struct->http_dont_dissect_response = 0;

	NDPI_PROTOCOL_BITMASK all;

	NDPI_BITMASK_ADD(all,NDPI_PROTOCOL_HTTP);
	NDPI_BITMASK_ADD(all,NDPI_PROTOCOL_SSL);

	// enable all protocols
//	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(my_ndpi_struct, &all);

	return my_ndpi_struct;
}
