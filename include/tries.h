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

#include <Poco/Logger.h>
#include <marisa.h>
#include "cfg.h"

#define SEARCH_AGENTS MAX_WORKER_THREADS


class Tries
{
public:
	Tries() : _is_mdomains_ready(false), _is_urls_ready(false) {};
	~Tries() {};
	bool search_prefix(marisa::Agent *agent, char *rhost, std::size_t rhost_size, char *url, std::size_t url_size);
	bool lookup(marisa::Agent *agent, char *rhost, std::size_t rhost_size, char *url, std::size_t url_size);
	inline bool isMDomainsReady()
	{
		return _is_mdomains_ready;
	}
	inline bool isURLsReady()
	{
		return _is_urls_ready;
	}
	void setMDomainsReady()
	{
		_is_mdomains_ready = true;
	}
	void setURLsReady()
	{
		_is_urls_ready = true;
	}
public:
	// домены, содержащие маску
	marisa::Trie mdomains_trie;
	// url и домены без маски
	marisa::Trie urls_trie;
	bool _is_mdomains_ready;
	bool _is_urls_ready;
};

class TriesControl
{
public:
	TriesControl();
	~TriesControl() {};
	bool load(std::string &domains, std::string &urls, bool is_sni = false);

	inline Tries *getActiveTrie()
	{
		return &tries[active_trie];
	}

	Tries tries[2];
	uint8_t active_trie;
private:
	Poco::Logger& _logger;
	bool _first_load;
	time_t _domains_ch_time;
	time_t _urls_ch_time;
	time_t load_time;
};


class BlacklistsManager
{
public:
	struct bl_service_profile
	{
		std::string domains_file;
		std::string urls_file;
		std::string sni_file;
		char redir_url[OUR_PAYLOAD_SIZE - OUR_REDIR_SIZE];
		size_t redir_url_size;
		bool need_add_url;
	};
	BlacklistsManager() : _active_profile(0)
	{
		_sp[0].redir_url[0] = 0;
		_sp[1].redir_url[0] = 0;
		_sp[0].need_add_url = false;
		_sp[1].need_add_url = false;
		_sp[1].redir_url_size = 0;
		_sp[0].redir_url_size = 0;
	}
	~BlacklistsManager() {};
	inline TriesControl *getHttpBlacklist()
	{
		return &_http_bl;
	}
	inline TriesControl *getSNIBlacklist()
	{
		return &_sni_bl;
	}
	inline bl_service_profile *getActiveSP()
	{
		return &_sp[_active_profile];
	}
	inline void changeProfile()
	{
		_active_profile = _active_profile == 0 ? 1 : 0;
	}
	/// set active profile to 0, store file names in it, load blacklists
	bool init(std::string &_domains_file, std::string &_urls_file, std::string &_sni_file, const char *redir_url = nullptr, size_t url_length = 0);
	/// reload blacklists from the current active profile
	bool update();
	void fillRedirURL(uint8_t profile, const char *redir_url, size_t url_length);
	void fillProfile(uint8_t profile, std::string &_domains_file, std::string &_urls_file, std::string &_sni_file, const char *redir_url, size_t url_length);
private:
	uint8_t _active_profile;
	TriesControl _http_bl;
	TriesControl _sni_bl;
	struct bl_service_profile _sp[2];
};

class TriesManager
{
public:
	TriesManager() : _logger(Poco::Logger::get("TriesManager"))
	{};
	~TriesManager() {};

	int checkURLBlocked(int thread_id, const char *hostname, uint32_t host_len, const char *uri, uint32_t uri_len, char **redir_url);
	int checkSNIBlocked(int thread_id, const char *sni, uint32_t sni_len);
	inline BlacklistsManager *getBLManager()
	{
		return &_bl_manager;
	}
private:
	BlacklistsManager _bl_manager;
	marisa::Agent _agents[SEARCH_AGENTS];
	char _url[MAX_WORKER_THREADS][4096];
	Poco::Logger& _logger;
};
