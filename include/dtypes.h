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

enum port_types
{
	P_TYPE_SUBSCRIBER,
	P_TYPE_NETWORK,
	P_TYPE_SENDER
};

enum operation_modes
{
	OP_MODE_MIRROR,
	OP_MODE_INLINE
};

struct rte_mempool;

struct pool_holder_t
{
	rte_mempool *mempool;
};

