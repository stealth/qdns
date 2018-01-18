/*
 * This file is part of quantum-dns.
 *
 * (C) 2014-2018 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
 *
 * quantum-dns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * quantum-dns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with quantum-dns. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef qdns_qdns_h
#define qdns_qdns_h

#include <map>
#include <list>
#include <string>
#include "provider.h"


namespace qdns {

class qdns {

	std::string err;

	struct {
		std::string pkt;
		std::string question;
		std::string reply;
	} client;

	typedef enum {
		QDNS_MATCH_INVALID	= 0,
		QDNS_MATCH_EXACT	= 0x1000,
		QDNS_MATCH_WILD		= 0x2000
	} match_type;

	struct match {
		std::string fqdn, name, question, field;

		// in network order:
		uint16_t type, _class;
		uint16_t a_count, rra_count, ad_count;
		uint32_t ttl;
		std::string rr;
		match_type mtype;

		match() : fqdn(""), name(""), question(""), field(""),
		          type(0), _class(0), a_count(0), rra_count(0), ad_count(0),
		          ttl(0), rr(""), mtype(QDNS_MATCH_INVALID)
		{}
	};

	bool nxdomain, resend;

	dns_provider *io{nullptr};

	// (qname, qtype) -> match
	std::map<std::pair<std::string, uint16_t>, std::list<match *>> exact_matches, wild_matches;
	std::map<std::string, int> once;

	std::string src;


protected:

	int build_error(const std::string &);

public:

	qdns() : err(""), client{"", "", ""}, nxdomain(1), resend(0), src("")
	{
	}

	virtual ~qdns()
	{
		delete io;
	}

	const char *why()
	{
		return err.c_str();
	}

	int init(const std::map<std::string, std::string> &);

	int parse_packet(const std::string &, std::string &, std::string &);

	int parse_zone(const std::string &);

	int loop();

};


} // namespace

#endif


