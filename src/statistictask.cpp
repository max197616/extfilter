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


#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <map>
#include <Poco/Util/ServerApplication.h>
#include <Poco/FileStream.h>
#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <sys/time.h>

#include "statistictask.h"
#include "stats.h"
#include "worker.h"

static struct timeval begin_time;

static std::map<int,uint64_t> map_last_pkts;

StatisticTask::StatisticTask(int sec, std::vector<DpdkWorkerThread*> &workerThreadVector, std::string &statisticsFile, std::vector<uint8_t> &ports):
	Task("StatisticTask"),
	_sec(sec),
	workerThreadVec(workerThreadVector),
	_statisticsFile(statisticsFile),
	_ports(ports)
{
}

static std::string formatBytes(u_int32_t howMuch)
{
	char unit = 'B';
	char buf[32];
	int buf_len=sizeof(buf);

	if(howMuch < 1024)
	{
		snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
	} else if(howMuch < 1048576)
	{
		snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
	} else {
		float tmpGB = ((float)howMuch)/1048576;
		if(tmpGB < 1024)
		{
			snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
		} else {
			tmpGB /= 1024;
			snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
		}
	}
	return std::string(buf);
}

static std::string formatPackets(float numPkts)
{
	char buf[32];
	int buf_len=sizeof(buf);
	if(numPkts < 1000)
	{
		snprintf(buf, buf_len, "%.2f", numPkts);
	} else if(numPkts < 1000000)
	{
		snprintf(buf, buf_len, "%.2f K", numPkts/1000);
	} else {
		numPkts /= 1000000;
		snprintf(buf, buf_len, "%.2f M", numPkts);
	}
	return std::string(buf);
}

void StatisticTask::OutStatistic()
{
	Poco::Util::Application& app = Poco::Util::Application::instance();
	struct timeval end;
	gettimeofday(&end, NULL);
	float traffic_throughput=0;
	uint64_t total_packets=0;
	uint64_t ip_packets=0;
	uint64_t ipv4_packets=0;
	uint64_t ipv6_packets=0;
	uint64_t bytes=0;
	uint64_t matched_ip_port=0;
	uint64_t matched_ssl=0;
	uint64_t matched_ssl_ip=0;
	uint64_t matched_domains=0;
	uint64_t matched_urls=0;
	uint64_t redirected_domains=0;
	uint64_t redirected_urls=0;
	uint64_t sended_rst=0;
	uint64_t active_flows=0;
	uint64_t deleted_flows=0;
	uint64_t r_received_packets=0;
	uint64_t r_missed_packets=0;
	uint64_t r_rx_nombuf = 0;
	uint64_t r_ierrors = 0;
	uint64_t ipv4_fragments=0;
	uint64_t ipv6_fragments=0;
	uint64_t ipv4_short_packets=0;
	uint64_t ndpi_ipv6_flows_count=0;
	uint64_t ndpi_ipv4_flows_count=0;

	Poco::FileOutputStream os;
	if(!_statisticsFile.empty())
	{
		os.open(_statisticsFile, std::ios::out | std::ios::trunc);
	}
	for(const auto &port : _ports)
	{
		struct rte_eth_stats rteStats;
		rte_eth_stats_get(port, &rteStats);
		app.logger().information("Port %d input packets %" PRIu64 ", input errors: %" PRIu64 ", mbuf errors: %" PRIu64 ", missed packets: %" PRIu64, (int)port, rteStats.ipackets, rteStats.ierrors, rteStats.rx_nombuf, rteStats.imissed);
		r_received_packets += rteStats.ipackets;
		r_missed_packets += rteStats.imissed;
		r_rx_nombuf += rteStats.rx_nombuf;
		r_ierrors += rteStats.ierrors;
	}
	for(std::vector<DpdkWorkerThread*>::iterator it=workerThreadVec.begin(); it != workerThreadVec.end(); it++)
	{
		int core=(int)(*it)->getCoreId();
		// statistic for worker thread
		if(dynamic_cast<WorkerThread*>(*it) != NULL)
		{
			app.logger().information("Worker thread on core %d statistics:", core);
			const ThreadStats stats=(static_cast<WorkerThread*>(*it))->getStats();
			unsigned int avg_pkt_size=0;
			uint64_t last_pkts=0;
			std::map<int,uint64_t>::iterator it1=map_last_pkts.find(core);
			if(it1 != map_last_pkts.end())
				last_pkts = it1->second;
			uint64_t tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin_time.tv_sec*1000000 + begin_time.tv_usec);
			float t = (float)((stats.total_packets-last_pkts)*1000000)/(float)tot_usec;
			traffic_throughput += t;
			map_last_pkts[core]=stats.total_packets;
			if(stats.ip_packets && stats.total_bytes)
				avg_pkt_size = (unsigned int)(stats.total_bytes/stats.ip_packets);
			total_packets += stats.total_packets;
			ip_packets += stats.ip_packets;
			ipv4_packets += stats.ipv4_packets;
			ipv6_packets += stats.ipv6_packets;
			bytes += stats.total_bytes;
			matched_ip_port += stats.matched_ip_port;
			matched_ssl += stats.matched_ssl;
			matched_ssl_ip += stats.matched_ssl_ip;
			matched_domains += stats.matched_domains;
			matched_urls += stats.matched_urls;
			redirected_domains += stats.redirected_domains;
			redirected_urls += stats.redirected_urls;
			sended_rst += stats.sended_rst;
			active_flows += stats.ndpi_flows_count;
			deleted_flows += stats.ndpi_flows_deleted;
			ipv4_fragments += stats.ipv4_fragments;
			ipv6_fragments += stats.ipv6_fragments;
			ipv4_short_packets += stats.ipv4_short_packets;
			ndpi_ipv6_flows_count += stats.ndpi_ipv6_flows_count;
			ndpi_ipv4_flows_count += stats.ndpi_ipv4_flows_count;

			app.logger().information("Thread seen packets: %" PRIu64 ", IP packets: %" PRIu64 " (IPv4 packets: %" PRIu64 ", IPv6 packets: %" PRIu64 "), seen bytes: %" PRIu64 ", Average packet size: %" PRIu32 " bytes, Traffic throughput: %s pps", stats.total_packets, stats.ip_packets, stats.ipv4_packets, stats.ipv6_packets, stats.total_bytes, avg_pkt_size, formatPackets(t));
			app.logger().information("Thread IPv4 fragments: %" PRIu64 ", IPv6 fragments: %" PRIu64 ", IPv4 short packets: %" PRIu64, stats.ipv4_fragments, stats.ipv6_fragments, stats.ipv4_short_packets);
			app.logger().information("Thread matched by ip/port: %" PRIu64 ", matched by ssl: %" PRIu64 ", matched by ssl/ip: %" PRIu64 ", matched by domain: %" PRIu64 ", matched by url: %" PRIu64, stats.matched_ip_port, stats.matched_ssl, stats.matched_ssl_ip, stats.matched_domains, stats.matched_urls);
			app.logger().information("Thread redirected domains: %" PRIu64 ", redirected urls: %" PRIu64 ", rst sended: %" PRIu64, stats.redirected_domains,stats.redirected_urls,stats.sended_rst);
			app.logger().information("Thread active flows: %" PRIu64 " (IPv4 flows: %" PRIu64 " IPv6 flows: %" PRIu64 "), expired flows: %" PRIu64 ", already detected blocked: %" PRIu64, stats.ndpi_flows_count, stats.ndpi_ipv4_flows_count, stats.ndpi_ipv6_flows_count, stats.ndpi_flows_deleted, stats.already_detected_blocked);
			if(!_statisticsFile.empty())
			{
				std::string worker_name("worker.core."+std::to_string(core));
				os << worker_name << ".total_packets=" << stats.total_packets << std::endl;
				os << worker_name << ".ip_packets=" << stats.ip_packets << std::endl;
				os << worker_name << ".ipv4_packets=" << stats.ipv4_packets << std::endl;
				os << worker_name << ".ipv6_packets=" << stats.ipv6_packets << std::endl;
				os << worker_name << ".total_bytes=" << stats.total_bytes << std::endl;
				os << worker_name << ".matched_ip_port=" << stats.matched_ip_port << std::endl;
				os << worker_name << ".matched_ssl=" << stats.matched_ssl << std::endl;
				os << worker_name << ".matched_ssl_ip=" << stats.matched_ssl_ip << std::endl;
				os << worker_name << ".matched_domains=" << stats.matched_domains << std::endl;
				os << worker_name << ".matched_ulrs=" << stats.matched_urls << std::endl;
				os << worker_name << ".active_flows=" << stats.ndpi_flows_count << std::endl;
				os << worker_name << ".expired_flows=" << stats.ndpi_flows_deleted << std::endl;
				os << worker_name << ".ipv4_fragments=" << stats.ipv4_fragments << std::endl;
				os << worker_name << ".ipv6_fragments=" << stats.ipv6_fragments << std::endl;
				os << worker_name << ".ipv4_short_packets=" << stats.ipv4_short_packets << std::endl;
			}
		}
	}
	gettimeofday(&begin_time, NULL);
	app.logger().information("All worker threads seen packets: %" PRIu64 ", IP packets: %" PRIu64 " (IPv4 packets: %" PRIu64 ", IPv6 packets: %" PRIu64 "), seen bytes: %" PRIu64 ", traffic throughtput: %s pps", total_packets, ip_packets, ipv4_packets, ipv6_packets, bytes, formatPackets(traffic_throughput));
	app.logger().information("All worker IPv4 fragments: %" PRIu64 ", IPv6 fragments: %" PRIu64 ", IPv4 short packets: %" PRIu64, ipv4_fragments, ipv6_fragments, ipv4_short_packets);
	app.logger().information("All worker threads matched by ip/port: %" PRIu64 ", matched by ssl: %" PRIu64 ", matched by ssl/ip: %" PRIu64 ", matched by domain: %" PRIu64 ",  matched by url: %" PRIu64, matched_ip_port, matched_ssl, matched_ssl_ip, matched_domains, matched_urls);
	app.logger().information("All worker threads redirected domains: %" PRIu64 ", redirected urls: %" PRIu64 ", rst sended: %" PRIu64, redirected_domains, redirected_urls, sended_rst);
	app.logger().information("All worker threads active flows: %" PRIu64 "(IPv4 flows: %" PRIu64 " IPv6 flows: %" PRIu64 "), expired flows: %" PRIu64, active_flows, ndpi_ipv4_flows_count, ndpi_ipv6_flows_count, deleted_flows);
	if(!_statisticsFile.empty())
	{
		std::string worker_name("allworkers");
		os << worker_name << ".total_packets=" << total_packets << std::endl;
		os << worker_name << ".ip_packets=" << ip_packets << std::endl;
		os << worker_name << ".ipv4_packets=" << ipv4_packets << std::endl;
		os << worker_name << ".ipv6_packets=" << ipv6_packets << std::endl;
		os << worker_name << ".total_bytes=" << bytes << std::endl;
		os << worker_name << ".matched_ip_port=" << matched_ip_port << std::endl;
		os << worker_name << ".matched_ssl=" << matched_ssl << std::endl;
		os << worker_name << ".matched_ssl_ip=" << matched_ssl_ip << std::endl;
		os << worker_name << ".matched_domains=" << matched_domains << std::endl;
		os << worker_name << ".matched_ulrs=" << matched_urls << std::endl;
		os << worker_name << ".active_flows=" << active_flows << std::endl;
		os << worker_name << ".expired_flows=" << deleted_flows << std::endl;
		os << worker_name << ".ipv4_fragments=" << ipv4_fragments << std::endl;
		os << worker_name << ".ipv6_fragments=" << ipv6_fragments << std::endl;
		os << worker_name << ".ipv4_short_packets=" << ipv4_short_packets << std::endl;
		
		worker_name.assign("allports");
		os << worker_name << ".received_packets=" << r_received_packets << std::endl;
		os << worker_name << ".missed_packets=" << r_missed_packets << std::endl;
		os << worker_name << ".rx_nombuf=" << r_rx_nombuf << std::endl;
		os << worker_name << ".ierrors=" << r_ierrors << std::endl;
	}
	if(!_statisticsFile.empty())
	{
		os.close();
	}

}

void StatisticTask::runTask()
{
	Poco::Util::Application& app = Poco::Util::Application::instance();
	app.logger().debug("Starting statistic task...");
	if(!_statisticsFile.empty())
	{
		Poco::FileOutputStream os(_statisticsFile);
		os << std::endl;
		os.close();
	}
	gettimeofday(&begin_time, NULL);
	int sleep_sec=_sec;
	if(!sleep_sec)
		sleep_sec=1;
	sleep_sec *= 1000;
	while (!isCancelled())
	{
		sleep(sleep_sec);
		if(_sec)
			OutStatistic();
	}
	app.logger().debug("Stopping statistic task...");
}

