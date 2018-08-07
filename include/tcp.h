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

namespace TCP
{
	enum Flags
	{
		FIN = 1,
		SYN = 2,
		RST = 4,
		PSH = 8,
		ACK = 16,
		URG = 32,
		ECE = 64,
		CWR = 128
	};

inline int sequence_compare(uint32_t seq1, uint32_t seq2)
{
	static const uint32_t seq_number_diff = 2147483648U;
	if (seq1 == seq2)
		return 0;
	if (seq1 < seq2)
		return (seq2 - seq1 < seq_number_diff) ? -1 : 1;
	return (seq1 - seq2 > seq_number_diff) ? -1 : 1;
}

};