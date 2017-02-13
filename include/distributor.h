
#pragma once

#include <rte_distributor.h>


class Distributor
{
public:
	Distributor(unsigned num_workers);
	~Distributor();

	inline struct rte_distributor *getDistributor()
	{
		return distr;
	}
	void flush()
	{
		rte_distributor_flush(distr);
	}
private:
	struct rte_distributor *distr;
	unsigned _num_workers;
};