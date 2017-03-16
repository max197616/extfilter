
#include <Poco/Util/ServerApplication.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <rte_config.h>
#include <rte_ethdev.h>

#include "distributor.h"

Distributor::Distributor(unsigned num_workers):
	_num_workers(num_workers)
{
	distr = rte_distributor_create("PKT_DIST", rte_socket_id(), _num_workers);
	if(!distr)
	{
		Poco::Util::Application::instance().logger().fatal("Unable to create rte_distributor");
		throw Poco::Exception("Unable to create rte_distributor");
	}
}


Distributor::~Distributor()
{

}

