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

#include "utils.h"

#include <ctype.h>
static char hex_chars[]="0123456789ABCDEF";

std::size_t url_encode(char *buf, const char *from, std::size_t len, std::size_t buf_size)
{
	std::size_t res = 0;
	if(from)
	{
		while (*from != 0 && len > 0 && buf_size > 0)
		{
			res++;
			buf_size--;
			if(isalnum(*from) || *from == '-' || *from == '_' || *from == '.' || *from == '~')
				*buf++ = *from;
			else {
				*buf++ = '%';
				*buf++ = hex_chars[(*from >> 4) & 0x0f];
				*buf++ = hex_chars[*from & 0x0f];
				res += 2;
				buf_size -= 2;
			}
			from++;
			len--;
		}
	}
	*buf = 0;
	return res;
}