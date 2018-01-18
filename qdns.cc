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

#include <map>
#include <list>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <arpa/inet.h>
#include "qdns.h"
#include "misc.h"
#include "net-headers.h"


using namespace std;
using net_headers::dns_type;

namespace qdns {


int qdns::build_error(const string &s)
{
	err = "qdns::";
	err += s;
	if (errno) {
		err += ": ";
		err += strerror(errno);
	}
	return -1;
}


int qdns::init(const map<string, string> &args)
{
	if (args.count("laddr"))
		io = new (nothrow) socket_provider();
	else if (args.count("mon") > 0)
		io = new (nothrow) usipp_provider();

	if (!io)
		return build_error("init: OOM");

	if (io->init(args) < 0)
		return build_error(string("init:") + io->why());

	auto it = args.find("nxdomain");
	if (it != args.end())
		nxdomain = (strtoul(it->second.c_str(), NULL, 10) != 0);
	if (args.count("resend") > 0)
		resend = 1;

	return 0;
}


int qdns::loop()
{
	if (!io)
		return build_error("loop: no IO provider initialized");

	string log = "";
	int r = 0;

	for (;;) {
		client.pkt = "";
		client.reply = "";

		if (io->recv(client.pkt) < 0) {
			cerr<<io->why()<<endl;
			continue;
		}
		src = io->sender();
		r = parse_packet(client.pkt, client.reply, log);

		if (r == 0) {
			// return of 0 has reply equal pkt for resend
			if (io->resend(client.reply) < 0) {
				cerr<<src<<": "<<io->why()<<endl;
				continue;
			}
		} else if (r > 0) {
			if (io->reply(client.reply) < 0) {
				cerr<<src<<": "<<io->why()<<endl;
				continue;
			}
		} // in < 0 case, just log output

		cout<<src<<": "<<log<<endl;
	}

	return 0;
}


int qdns::parse_packet(const string &query, string &response, string &log)
{
	using net_headers::dnshdr;
	using net_headers::dns_type;

	log = "invalid query";
	response = "";

	if (query.size() <= sizeof(dnshdr))
		return -1;

	const char *ptr = query.c_str(), *end_ptr = ptr + query.size();

	dnshdr hdr;
	memcpy(&hdr, query.c_str(), sizeof(dnshdr));
	ptr += sizeof(dnshdr);

	// Huh? dst port 53 and no query?
	if (hdr.qr != 0 || hdr.opcode != 0)
		return -1;

	// only one question
	if (hdr.q_count != htons(1))
		return -1;

	// skip QNAME
	auto qptr = ptr;
	while (*ptr != 0 && ptr < end_ptr)
		++ptr;
	++ptr;

	// must also have QTYPE and QCLASS
	if (ptr + 2*sizeof(uint16_t) > end_ptr)
		return -1;

	uint16_t qtype = 0;
	memcpy(&qtype, ptr, sizeof(qtype));

	string qname = string(qptr, ptr - qptr);
	string question = string(qptr, ptr + 2*sizeof(uint16_t) - qptr);
	string fqdn = "";

	if (qname2host(qname, fqdn) <= 0)
		return -1;

	switch (ntohs(qtype)) {
	case dns_type::A:
		log = "A? ";
		break;
	case dns_type::AAAA:
		log = "AAAA? ";
		break;
	case dns_type::MX:
		log = "MX? ";
		break;
	case dns_type::CNAME:
		log = "CNAME? ";
		break;
	case dns_type::NS:
		log = "NS? ";
		break;
	case dns_type::PTR:
		log = "PTR? ";
		break;
	case dns_type::SRV:
		log = "SRV? ";
		break;
	case dns_type::TXT:
		log = "TXT? ";
		break;
	default:
		char s[32];
		snprintf(s, sizeof(s), "%d? ", ntohs(qtype));
		log = s;
	}

	log += fqdn;
	log += " -> ";

	bool found_domain = 1;
	auto it1 = exact_matches.find(make_pair(qname, qtype)), lit = it1;

	if (lit == exact_matches.end()) {
		string::size_type pos = string::npos, minpos = string::npos;

		// try to find largest substring match
		for (auto it2 = wild_matches.begin(); it2 != wild_matches.end(); ++it2) {
			if ((pos = qname.find(it2->first.first)) == string::npos || it2->first.second != qtype)
				continue;
			if (pos < minpos && pos + it2->first.first.size() == qname.size()) {
				minpos = pos;
				lit = it2;
			}
		}

		// If no entry found, NXDOMAIN
		if (minpos == string::npos) {
			found_domain = 0;
			log += "NDXOMAIN ";
			auto it3 = exact_matches.find(make_pair(string("\x9[forward]\0", 11), htons(dns_type::SOA)));
			if (it3 != exact_matches.end())
				lit = it3;

			// if -R was given, we are firewalling router,
			// so resend in case we cant resolve ourself
			if (resend) {
				log += "(resend)";
				response = query;
				return 0;
			}

			// NXDOMAIN answers prohibited (-X)
			if (!nxdomain) {
				log += "(nosend)";
				return -1;
			}
		}
	}

	// still nothing found?
	if (lit == exact_matches.end()) {
		log += "no [forward], (nosend)";
		return -1;
	}

	// map wasnt changed, so lit iterator still valid
	list<match *> &l = lit->second;

	if (l.size() == 0) {
		log += "NULL match. Missing -X?";
		return -1;
	}

	match *m = l.front();

	// TTL of 1 means, only handle this client src once
	if (l.size() == 1 && m->ttl == htonl(1)) {
		if (once.count(src) > 0) {
			log += "(once, nosend)";
			return -1;
		}
		once[src] = 1;
	}

	log += m->field;

	// reply-hdr
	dnshdr rhdr;
	memcpy(&rhdr, &hdr, sizeof(hdr));
	rhdr.qr = 1;
	rhdr.aa = 0;
	rhdr.tc = 0;
	rhdr.ra = 0;
	rhdr.unused = 0;
	if (!found_domain)
		rhdr.rcode = 3;
	else
		rhdr.rcode = 0;
	rhdr.q_count = hdr.q_count;
	rhdr.a_count = m->a_count;
	rhdr.rra_count = m->rra_count;
	rhdr.ad_count = m->ad_count;

	response = string((char *)&rhdr, sizeof(rhdr));
	response += question;
	response += m->rr;

	// shift list of matches. l is a ref to the list inside
	// the map, so the change really happens
	if (l.size() > 1) {
		l.push_back(m);
		l.pop_front();
	}

	return 1;
}



// beware: this function can overflow stack, if you place too many
// CNAMEs into the zone file.
int qdns::parse_zone(const string &file)
{
	FILE *f = fopen(file.c_str(), "r");
	if (!f)
		return build_error("parse_zone: fopen");

	char buf[1024], *ptr = NULL, name[256], type[256], ltype[256], ttlb[255], field[256], rr[1024], *rr_ptr = NULL;
	uint16_t off = 0, rlen = 0, zero = 0, dtype = 0, dltype = 0, dclass = htons(1), prio = 0, weight = 0;
	uint32_t ttl = 0, records = 0;
	uint32_t soa_ints[5] = {0x11223344, htonl(7200), htonl(7200), htonl(3600000), htonl(7200)};
	string dname = "", link_rr = "", dlname = "";
	net_headers::dns_srv_rr srv;
	map<string, string> A, AAAA;
	enum {
		RR_KIND_MATCHING	= 0,
		RR_KIND_LINKING		= 1
	} rr_kind = RR_KIND_MATCHING;

	// a compressed label, pointing right to original QNAME, so
	// that even on wildcard matches, we already have a full blown
	// answer RR in place, even without knowing the exact QNAME in advance
	uint16_t clbl = htons(((1<<15)|(1<<14))|sizeof(net_headers::dnshdr));

	memset(buf, 0, sizeof(buf));
	memset(name, 0, sizeof(name));
	memset(ltype, 0, sizeof(ltype));
	memset(type, 0, sizeof(type));
	memset(ttlb, 0, sizeof(ttlb));
	memset(field, 0, sizeof(field));

	while (fgets(buf, sizeof(buf), f)) {

		if (rr_kind == RR_KIND_MATCHING) {
			link_rr = "";
			dltype = 0;
		}

		memset(rr, 0, sizeof(rr));
		rr_ptr = rr;
		dname = "";
		dlname = "";

		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			++ptr;
		if (*ptr == ';' || *ptr == '\n')
			continue;

		// link following entry to already existing RR?
		if (*ptr == '@') {
			// wrong format? ignore!
			if (sscanf(ptr + 1, "%255[^ \t]%*[ \t]%255[^ \t;\n]", name, ltype) != 2)
				link_rr = "";
			else {
				link_rr = name;
				rr_kind = RR_KIND_LINKING;
			}
			continue;
		}

		if (sscanf(ptr, "%255[^ \t]%*[ \t]%255[^ \t]%*[ \t]IN%*[ \t]%255[^ \t]%*[ \t]%255[^ \t;\n]", name, ttlb, type, field) != 4)
			continue;

		// the next loop cycle we assume matching RR's until we find @ again.
		// this is to reset link_rr on loop start
		rr_kind = RR_KIND_MATCHING;

		//cout<<"Parsed: "<<name<<"<->"<<type<<"<->"<<ttlb<<"<->"<<field<<endl;

		if (host2qname(name, dname) <= 0)
			continue;
		if (dname.size() > 255)
			continue;

		// DNS type of current entry
		if (strcasecmp(type, "A") == 0) {
			dtype = htons(dns_type::A);
		} else if (strcasecmp(type, "MX") == 0) {
			dtype = htons(dns_type::MX);
		} else if (strcasecmp(type, "AAAA") == 0) {
			dtype = htons(dns_type::AAAA);
		} else if (strcasecmp(type, "NS") == 0) {
			dtype = htons(dns_type::NS);
		} else if (strcasecmp(type, "CNAME") == 0) {
			dtype = htons(dns_type::CNAME);
		} else if (strcasecmp(type, "SOA") == 0) {
			dtype = htons(dns_type::SOA);
		} else if (strcasecmp(type, "SRV") == 0) {
			dtype = htons(dns_type::SRV);
		} else if (strcasecmp(type, "TXT") == 0) {
			dtype = htons(dns_type::TXT);
		} else if (strcasecmp(type, "PTR") == 0) {
			dtype = htons(dns_type::PTR);
		} else
			continue;

		ttl = htonl(strtoul(ttlb, NULL, 10));

		match *m = nullptr;

		// use already existing match if linked to existing RR
		if (link_rr.size() > 0) {
			if (host2qname(link_rr, dlname) <= 0)
				continue;

			// DNS type of RR which we link to
			if (strcasecmp(ltype, "A") == 0) {
				dltype = htons(dns_type::A);
			} else if (strcasecmp(ltype, "MX") == 0) {
				dltype = htons(dns_type::MX);
			} else if (strcasecmp(ltype, "AAAA") == 0) {
				dltype = htons(dns_type::AAAA);
			} else if (strcasecmp(ltype, "NS") == 0) {
				dltype = htons(dns_type::NS);
			} else if (strcasecmp(ltype, "CNAME") == 0) {
				dltype = htons(dns_type::CNAME);
			} else if (strcasecmp(ltype, "SOA") == 0) {
				dltype = htons(dns_type::SOA);
			} else if (strcasecmp(ltype, "SRV") == 0) {
				dltype = htons(dns_type::SRV);
			} else if (strcasecmp(ltype, "TXT") == 0) {
				dltype = htons(dns_type::TXT);
			} else if (strcasecmp(ltype, "PTR") == 0) {
				dltype = htons(dns_type::PTR);
			} else
				continue;

			if (exact_matches.count(make_pair(dlname, dltype)) > 0)
				m = exact_matches.find(make_pair(dlname, dltype))->second.back();
			else if (wild_matches.count(make_pair(dlname, dltype)) > 0)
				m = wild_matches.find(make_pair(dlname, dltype))->second.back();
			else
				continue;

			// Can't use compression here, since its maybe an unrelated name.
			// Use (current) dname, not dlname.
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
		} else {
			m = new match;

			// keep a human readable copy of answer for later logging
			m->field = field;

			if (name[0] == '*') {
				off = 1;
				if (name[1] == '.')
					off = 2;
				memmove(name, name + off, sizeof(name) - off);
				m->mtype = QDNS_MATCH_WILD;

				// we changed 'name' array, so we need to encode again
				if (host2qname(name, dname) <= 0)
					continue;
				if (dname.size() > 255)
					continue;

				// wildcard matches have wrong byte-count in front
				dname.erase(0, 1);
			} else
				m->mtype = QDNS_MATCH_EXACT;

			// start constructing answer section RR's. See above comment
			// for compressed label ptr
			memcpy(rr_ptr, &clbl, sizeof(clbl));
			rr_ptr += sizeof(clbl);

			m->fqdn = name;

			// DNS encoded name
			m->name = dname;

			// TTL
			m->ttl = ttl;

			m->type = dtype;
			m->a_count = 0;
			m->ad_count = 0;
			m->rra_count = 0;
		}


		switch (ntohs(dtype)) {
		case dns_type::A:
			in_addr in;
			if (inet_pton(AF_INET, field, &in) != 1)
				continue;
			// construct RR as per RFC
			rlen = htons(4);
			memcpy(rr_ptr, &dtype, sizeof(dtype));
			rr_ptr += sizeof(dtype);
			memcpy(rr_ptr, &dclass, sizeof(dclass));
			rr_ptr += sizeof(dclass);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, &in, sizeof(in));
			rr_ptr += sizeof(in);

			// If we are linking against a SOA, reverse order since
			// Authority comes after answer section. dltype is the dtype of
			// the RR we are linking to (if any, otherwise its 0)
			if (dltype == htons(dns_type::SOA))
				m->rr = string(rr, rr_ptr - rr) + m->rr;
			else
				m->rr += string(rr, rr_ptr - rr);
			m->a_count += htons(1);
			break;

		case dns_type::MX:
			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 255)
				continue;
			rlen = htons(dname.size() + sizeof(uint16_t));
			memcpy(rr_ptr, &dtype, sizeof(dtype));
			rr_ptr += sizeof(dtype);
			memcpy(rr_ptr, &dclass, sizeof(dclass));
			rr_ptr += sizeof(dclass);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, &zero, sizeof(zero));		// preference
			rr_ptr += sizeof(zero);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			if (dltype == htons(dns_type::SOA))
				m->rr = string(rr, rr_ptr - rr) + m->rr;
			else
				m->rr += string(rr, rr_ptr - rr);
			m->a_count += htons(1);
			break;

		case dns_type::AAAA:
			in6_addr in6;
			if (inet_pton(AF_INET6, field, &in6) != 1)
				continue;
			rlen = htons(sizeof(in6));
			memcpy(rr_ptr, &dtype, sizeof(dtype));
			rr_ptr += sizeof(dtype);
			memcpy(rr_ptr, &dclass, sizeof(dclass));
			rr_ptr += sizeof(dclass);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, &in6, sizeof(in6));
			rr_ptr += sizeof(in6);
			if (dltype == htons(dns_type::SOA))
				m->rr = string(rr, rr_ptr - rr) + m->rr;
			else
				m->rr += string(rr, rr_ptr - rr);
			m->a_count += htons(1);
			break;

		case dns_type::NS:
			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 255)
				continue;
			rlen = htons(dname.size());
			memcpy(rr_ptr, &dtype, sizeof(dtype));
			rr_ptr += sizeof(dtype);
			memcpy(rr_ptr, &dclass, sizeof(dclass));
			rr_ptr += sizeof(dclass);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			if (dltype == htons(dns_type::SOA))
				m->rr = string(rr, rr_ptr - rr) + m->rr;
			else
				m->rr += string(rr, rr_ptr - rr);
			m->a_count += htons(1);
			break;

		case dns_type::CNAME:
			m->type = dtype;
			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 255)
				continue;
			rlen = htons(dname.size());
			memcpy(rr_ptr, &dtype, sizeof(dtype));
			rr_ptr += sizeof(dtype);
			memcpy(rr_ptr, &dclass, sizeof(dclass));
			rr_ptr += sizeof(dclass);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			if (dltype == htons(dns_type::SOA))
				m->rr = string(rr, rr_ptr - rr) + m->rr;
			else
				m->rr += string(rr, rr_ptr - rr);
			m->a_count += htons(1);
			break;

		// Once a SOA has been linked in, no other RR's must be linked,
		// as they must appear between answer and additional section
		case dns_type::SOA:
			m->type = dtype;
			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 255)
				continue;
			rlen = htons(2*dname.size() + sizeof(soa_ints));
			memcpy(rr_ptr, &dtype, sizeof(dtype));
			rr_ptr += sizeof(dtype);
			memcpy(rr_ptr, &dclass, sizeof(dclass));
			rr_ptr += sizeof(dclass);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			memcpy(rr_ptr, soa_ints, sizeof(soa_ints));
			rr_ptr += sizeof(soa_ints);
			m->rr += string(rr, rr_ptr - rr);
			m->rra_count = htons(1);
			break;
		case dns_type::SRV:
			m->type = dtype;
			if (sscanf(field, "%255[^:]:%hu:%hu:%hu", name, &prio, &weight, &srv.port) != 4)
				continue;
			if (host2qname(name, dname) <= 0)
				continue;
			if (dname.size() > 255)
				continue;
			srv.len = htons(dname.size() + 6);
			srv.type = dtype;
			srv._class = dclass;
			srv.ttl = ttl;
			srv.prio = htons(prio);
			srv.weight = htons(weight);
			srv.port = htons(srv.port);
			memcpy(rr_ptr, &srv, sizeof(srv));
			rr_ptr += sizeof(srv);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			m->rr += string(rr, rr_ptr - rr);
			m->a_count += htons(1);
			break;
		case dns_type::TXT:
		case dns_type::PTR:
			m->type = dtype;
			if (sscanf(field, "%255[^\n]", name) != 1)
				continue;
			if (host2qname(name, dname) <= 0)
				continue;
			if (dname.size() > 255)
				continue;
			rlen = htons(dname.size());
			memcpy(rr_ptr, &dtype, sizeof(dtype));
			rr_ptr += sizeof(dtype);
			memcpy(rr_ptr, &dclass, sizeof(dclass));
			rr_ptr += sizeof(dclass);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			m->rr += string(rr, rr_ptr - rr);
			m->a_count += htons(1);
			break;
		default:
			if (link_rr.size() == 0)
				delete m;
			continue;
		}

		// Only add new match if not linked to existing one
		if (link_rr.size() == 0) {
			if (m->mtype == QDNS_MATCH_EXACT)
				exact_matches[make_pair(m->name, m->type)].push_back(m);
			else
				wild_matches[make_pair(m->name, m->type)].push_back(m);
		}

		++records;
	}
	fclose(f);
	cout<<"Successfully loaded "<<records<<" Quantum-RR's.\n";
	return 0;
}


}

