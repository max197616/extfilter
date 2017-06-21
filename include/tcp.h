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