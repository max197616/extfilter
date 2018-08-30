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

#include "tries.h"
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include "utils.h"
#include <iostream>
#include <rte_config.h>
#include <rte_memcpy.h>

// value 1-5
#define TRIES_NUMBER 1

static int param_num_tries = TRIES_NUMBER;
static marisa::TailMode param_tail_mode = MARISA_TEXT_TAIL;
static marisa::NodeOrder param_node_order = MARISA_WEIGHT_ORDER;
static marisa::CacheLevel param_cache_level = MARISA_LARGE_CACHE;

bool Tries::search_prefix(marisa::Agent *agent, char *rhost, std::size_t rhost_size, char *url, std::size_t url_size)
{
	if(_is_mdomains_ready)
	{
		if(mdomains_trie.size() != 0 && (agent->set_query(rhost, rhost_size), mdomains_trie.common_prefix_search(*agent) ))
		{
			return true;
		}
	}
	if(_is_urls_ready)
	{
		if(urls_trie.size() != 0)
		{
			agent->set_query(url, url_size);
			return urls_trie.common_prefix_search(*agent);
		}
	}
	return false;
}

bool Tries::lookup(marisa::Agent *agent, char *rhost, std::size_t rhost_size, char *url, std::size_t url_size)
{
	if(_is_mdomains_ready)
	{
		if(mdomains_trie.size() != 0 && (agent->set_query(rhost, rhost_size), mdomains_trie.common_prefix_search(*agent) ))
		{
			return true;
		}
	}
	if(_is_urls_ready)
	{
		if(urls_trie.size() != 0)
		{
			agent->set_query(url, url_size);
			return urls_trie.lookup(*agent);
		}
	}
	return false;
}

TriesControl::TriesControl():
	active_trie(0),
	_logger(Poco::Logger::get("TriesControl")),
	_first_load(true),
	_domains_ch_time(0),
	_urls_ch_time(0),
	load_time(0)
{
}


int read_keys(std::istream &input, marisa::Keyset *m_domains, marisa::Keyset *urls, bool with_slashes = false)
{
	int lines = 0;
	std::string line;
	while (std::getline(input, line))
	{
		lines++;
		if(line[0] == '#' || line[0] == ';')
			continue;
		std::size_t pos = line.find("*.");
		if(pos != line.npos)
		{
			std::string s = line.substr(pos+1, line.length()-1);
			std::string s1(s.c_str()+1);
			if(with_slashes)
				s1 += "/";
			urls->push_back(s1.c_str(), s1.length()); // store domain without previous dot
			std::reverse(s.begin(), s.end());
			m_domains->push_back(s.c_str(), s.length()); // store reverse
		} else {
			std::string s(line.c_str());
			if(with_slashes)
				s += "/";
			urls->push_back(s.c_str(), s.length());
		}
	}
	return lines;
}

bool TriesControl::load(std::string &domains_f, std::string &urls_f, bool is_sni)
{
	marisa::Keyset m_domains;
	marisa::Keyset urls;
	int domains_lines = 0;
	int urls_lines = 0;
	struct stat f_stat;
	if(!domains_f.empty())
	{
		if(stat(domains_f.c_str(), &f_stat))
		{
			_logger.error("Unable to stat file '%s'", domains_f);
			return true;
		}
		if(_domains_ch_time != 0 && _domains_ch_time == f_stat.st_mtim.tv_sec)
		{
			_logger.information("Domains file '%s' is not changed from the last load", domains_f);
		} else {
			try
			{
				std::ifstream domains_file(domains_f, std::ios::binary);
				if(!domains_file)
				{
					_logger.error("Failed to open domains file '%s'", domains_f);
					return true;
				}
				domains_lines = read_keys(domains_file, &m_domains, &urls, is_sni ? false : true);
			} catch (const marisa::Exception &ex)
			{
				_logger.error("Working with domains failed: %s", std::string(ex.what()));
				return true;
			} catch (...)
			{
				_logger.error("Exception occured while working with domains file");
				return true;
			}
			_domains_ch_time = f_stat.st_mtim.tv_sec;
			_logger.information("Loaded %d lines from the domains file '%s'", domains_lines, domains_f);
		}
	}
	if(!urls_f.empty())
	{
		if(stat(urls_f.c_str(), &f_stat))
		{
			_logger.error("Unable to stat file '%s'", urls_f);
			return true;
		}
		if(_urls_ch_time != 0 && _urls_ch_time == f_stat.st_mtim.tv_sec)
		{
			_logger.information("URLs file '%s' is not changed from the last load", urls_f);
		} else {
			try
			{
				std::ifstream urls_file(urls_f, std::ios::binary);
				if(!urls_file)
				{
					_logger.error("Failed to open urls file '%s'", urls_f);
					return true;
				}
				urls_lines = read_keys(urls_file, &m_domains, &urls);
			} catch (const marisa::Exception &ex)
			{
				_logger.error("Working with urls failed: %s", std::string(ex.what()));
				return true;
			} catch (...)
			{
				_logger.error("Exception occured while working with urls file");
				return true;
			}
			_urls_ch_time = f_stat.st_mtim.tv_sec;
			_logger.information("Loaded %d lines from the urls file '%s'", urls_lines, urls_f);
		}
	}
	uint8_t need_load_trie = 0;
	uint8_t need_del_trie = (active_trie != 0);
	if(!_first_load) // not first load
		need_load_trie = (active_trie == 0);
	if(!m_domains.empty())
	{
		try
		{
			tries[need_load_trie].mdomains_trie.build(m_domains, param_num_tries | param_tail_mode | param_node_order | param_cache_level);
			tries[need_load_trie].setMDomainsReady();
			_logger.information("Masked domains: #keys %z, #nodes %z", tries[need_load_trie].mdomains_trie.num_keys(), tries[need_load_trie].mdomains_trie.num_nodes());
		} catch (const marisa::Exception &ex)
		{
			_logger.error("Unable to build marisa trie for masked domains: %s", std::string(ex.what()));
			return true;
		}
		
	}
	if(!urls.empty())
	{
		try
		{
			tries[need_load_trie].urls_trie.build(urls, param_num_tries | param_tail_mode | param_node_order | param_cache_level);
			tries[need_load_trie].setURLsReady();
			_logger.information("URLS: #keys %z, #nodes %z", tries[need_load_trie].urls_trie.num_keys(), tries[need_load_trie].urls_trie.num_nodes());
		} catch (const marisa::Exception &ex)
		{
			_logger.error("Unable to build marisa trie for urls: %s", std::string(ex.what()));
			return true;
		}
	}
	if(m_domains.empty() && urls.empty()) // nothing to do...
		return false;
	active_trie = need_load_trie;
	_logger.information("Set active trie in the slot %d", (int) active_trie);
	if(!_first_load) // not first load
	{
		sleep(1);
		_logger.information("Deleting trie in the slot %d", (int) need_del_trie);
		tries[need_del_trie].mdomains_trie.clear();
		tries[need_del_trie].urls_trie.clear();
	}
	_first_load = false;
	return false;
}

int TriesManager::checkURLBlocked(int thread_id, const char *hostname, uint32_t host_len, const char *uri, uint32_t uri_len, char **redir_url)
{
	char *rhost;
	char revhostname[4097];
	char url_buf[4097];
	int buf_len;
	char *url_entry;
	char enc_url[4096];
	revhostname[sizeof(revhostname)-1] = 0;
	if(host_len > sizeof(revhostname)-1)
	{
		buf_len = sizeof(revhostname)-1;
		host_len = sizeof(revhostname)-1;
		url_entry = &url_buf[sizeof(revhostname)-1];
		rhost = &revhostname[0];
		uri_len = 0;
	} else {
		if(host_len + uri_len > sizeof(url_buf)-1)
			uri_len = sizeof(url_buf) - 1 - host_len;
		buf_len = host_len + uri_len;
		url_entry = &url_buf[host_len];
		rhost = &revhostname[sizeof(revhostname) - 1 - host_len];
	}
	// перевод hostname в маленькие буквы и копирование hostname в обратном порядке в revhostname
	char *rh = &revhostname[sizeof(revhostname)-2];
	for(uint32_t i = 0; i < host_len; i++, rh--)
	{
		char v = hostname[i];
		if( v >= 'A' && v <= 'Z')
			v |= 0x20;
		url_buf[i] = v;
		*rh = v;
	}
	if(uri_len != 0)
	{
		for(uint32_t i = 0; i < uri_len; i++)
			url_entry[i] = uri[i];
	}
	url_buf[buf_len] = 0;
	try
	{
		if(_bl_manager.getHttpBlacklist()->getActiveTrie()->search_prefix(&_agents[thread_id], rhost, host_len, url_buf, buf_len))
		{
			struct BlacklistsManager::bl_service_profile *sp = _bl_manager.getActiveSP();
			if(redir_url && sp->redir_url[0] != 0) // make redir url
			{
				int res = sp->redir_url_size;
				if(sp->need_add_url)
				{
					char *r_url = &_url[thread_id][0];
					rte_memcpy(r_url, sp->redir_url, res);
					size_t enc_len = url_encode(enc_url, url_buf, buf_len, sizeof(enc_url) - 1);
					char *cptr = r_url + sp->redir_url_size;
					res += sizeof(uri_p) - 1 + enc_len;
					rte_memcpy(cptr, uri_p, sizeof(uri_p) - 1);
					cptr += sizeof(uri_p) - 1;
					rte_memcpy(cptr, enc_url, enc_len);
					*redir_url = r_url;
				} else {
					*redir_url = sp->redir_url;
				}
				return res;
			}
			return 1;
		}
	} catch (const marisa::Exception &ex)
	{
		_logger.error("Exception occured while search http: %s", std::string(ex.what()));
	}
	return 0;
}

int TriesManager::checkSNIBlocked(int thread_id, const char *sni, uint32_t sni_len)
{
	char revsni[4097];
	revsni[sizeof(revsni)-1] = 0;
	char *rptr = &revsni[sizeof(revsni)-2];
	if(sni_len > sizeof(revsni)-1)
		sni_len = sizeof(revsni)-1;
	for(uint32_t z=0; z < sni_len; z++, rptr--)
	{
		*rptr = sni[z];
	}
	try
	{
		if(_bl_manager.getSNIBlacklist()->getActiveTrie()->lookup(&_agents[thread_id], (rptr+1), sni_len, (char *)sni, sni_len))
		{
			return 1;
		}
	} catch (const marisa::Exception &ex)
	{
		_logger.error("Exception occured while search sni: %s", std::string(ex.what()));
	}
	return 0;
}

void BlacklistsManager::fillRedirURL(uint8_t profile, const char *redir_url, size_t url_length)
{
	_sp[profile].redir_url_size = url_length;
	if(!memcmp(redir_url, "http://", 7) || !memcmp(redir_url, "https://", 8))
	{
		strncpy(_sp[profile].redir_url, redir_url, sizeof(_sp[profile].redir_url)-1);
	} else {
		strncpy(stpcpy(_sp[profile].redir_url, "http://"), redir_url, sizeof(_sp[profile].redir_url)-1-7);
		_sp[profile].redir_url_size += 7;
	}
	_sp[profile].need_add_url = false;
	if(redir_url[url_length-1] == '?' || redir_url[url_length-1] == '&')
		_sp[profile].need_add_url = true;
	if(_sp[profile].redir_url_size > sizeof(_sp[profile].redir_url)-1)
		_sp[profile].redir_url_size = sizeof(_sp[profile].redir_url)-1;
}

void BlacklistsManager::fillProfile(uint8_t profile, std::string &_domains_file, std::string &_urls_file, std::string &_sni_file, const char *redir_url, size_t url_length)
{
	_sp[profile].domains_file = _domains_file;
	_sp[profile].urls_file = _urls_file;
	_sp[profile].sni_file = _sni_file;
	if(redir_url && url_length != 0 && redir_url[0] != 0)
	{
		fillRedirURL(profile, redir_url, url_length);
	} else {
		_sp[profile].redir_url[0] = 0;
		_sp[profile].redir_url_size = 0;
		_sp[profile].need_add_url = false;
	}
	
}

bool BlacklistsManager::init(std::string &_domains_file, std::string &_urls_file, std::string &_sni_file, const char *redir_url, size_t url_length)
{
	fillProfile(0, _domains_file, _urls_file, _sni_file, redir_url, url_length);
	_http_bl.load(_domains_file, _urls_file);
	std::string empty_s;
	_sni_bl.load(_sni_file, empty_s, true);
	_active_profile = 0;
	return false;
}

bool BlacklistsManager::update()
{
	if(_http_bl.load(_sp[_active_profile].domains_file, _sp[_active_profile].urls_file))
		return true;
	std::string empty_s;
	return _sni_bl.load(_sp[_active_profile].sni_file, empty_s, true);
}
