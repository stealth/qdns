/*
 * This file is part of quantum-dns.
 *
 * (C) 2014 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
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
	if (hdr.qr != 0)
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
	default:
		char s[32];
		snprintf(s, sizeof(s), "%d? ", ntohs(qtype));
		log = s;
	}

	log += fqdn;
	log += " -> ";

	bool found_domain = 1;
	match m;
	auto it1 = exact_matches.find(make_pair(qname, qtype));
	if (it1 == exact_matches.end()) {
		string::size_type pos = string::npos, minpos = string::npos;

		// try to find largest substring match
		for (auto it2 : wild_matches) {
			if ((pos = qname.find(it2.first.first)) == string::npos || it2.first.second != qtype)
				continue;
			if (pos < minpos && pos + it2.first.first.size() == qname.size()) {
				minpos = pos;
				m = it2.second;
			}
		}

		// If no entry found, NXDOMAIN
		if (minpos == string::npos) {
			found_domain = 0;
			log += "NDXOMAIN ";
			auto it3 = exact_matches.find(make_pair(string("\x9[forward]\0", 11), htons(dns_type::SOA)));
			if (it3 != exact_matches.end())
				m = it3->second;

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
	} else
		m = it1->second;

	// TTL of 1 means, only handle this client src once
	if (m.ttl == htonl(1)) {
		if (once.count(src) > 0) {
			log += "(once, nosend)";
			return -1;
		}
		once[src] = 1;
	}

	log += m.field;

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
	rhdr.a_count = m.a_count;
	rhdr.rra_count = m.rra_count;
	rhdr.ad_count = m.ad_count;

	response = string((char *)&rhdr, sizeof(rhdr));
	response += question;
	response += m.rr;

	return 1;
}



int qdns::parse_zone(const string &file)
{
	FILE *f = fopen(file.c_str(), "r");
	if (!f)
		return build_error("parse_zone: fopen");

	char buf[1024], *ptr = NULL, name[256], type[256], ttlb[255], field[256], rr[1024], *rr_ptr = NULL;
	uint16_t off = 0, rlen = 0, zero = 0;
	uint32_t ttl = 0, records = 0;
	uint32_t soa_ints[5] = {0x11223344, htonl(7200), htonl(7200), htonl(3600000), htonl(7200)};
	string dname = "";
	map<string, string> A, AAAA;

	// a compressed label, pointing right to original QNAME, so
	// that even on wildcard matches, we already have a full blown
	// answer RR in place, even without knowing the exact QNAME in advance
	uint16_t clbl = htons(((1<<15)|(1<<14))|sizeof(net_headers::dnshdr));

	memset(buf, 0, sizeof(buf));
	memset(name, 0, sizeof(name));
	memset(type, 0, sizeof(type));
	memset(ttlb, 0, sizeof(ttl));
	memset(field, 0, sizeof(field));

	while (fgets(buf, sizeof(buf), f)) {
		memset(rr, 0, sizeof(rr));
		rr_ptr = rr;
		dname = "";

		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			++ptr;
		if (*ptr == ';' || *ptr == '\n')
			continue;

		if (sscanf(ptr, "%255[^ \t]%*[ \t]%255[^ \t]%*[ \t]IN%*[ \t]%255[^ \t]%*[ \t]%255[^ \t;\n]", name, ttlb, type, field) != 4)
			continue;

		//cout<<"Parsed: "<<name<<"<->"<<type<<"<->"<<ttlb<<"<->"<<field<<endl;

		match m;

		// keep a human readable copy of answer for later logging
		m.field = field;

		if (name[0] == '*') {
			off = 1;
			if (name[1] == '.')
				off = 2;
			memmove(name, name + off, sizeof(name) - off);
			m.mtype = QDNS_MATCH_WILD;
		} else
			m.mtype = QDNS_MATCH_EXACT;

		if (host2qname(name, dname) <= 0)
			continue;
		if (dname.size() > 255)
			continue;

		// start constructing answer section RR's. See above comment
		// for compressed label ptr
		memcpy(rr_ptr, &clbl, sizeof(clbl));
		rr_ptr += sizeof(clbl);

		m.fqdn = name;

		// DNS encoded name
		m.name = dname;

		// only supported class: IN
		m._class = htons(1);

		// TTL
		ttl = htonl(strtoul(ttlb, NULL, 10));
		m.ttl = ttl;

		if (strcasecmp(type, "A") == 0) {

			m.type = htons(dns_type::A);
			in_addr in;
			if (inet_pton(AF_INET, field, &in) != 1)
				continue;
			// construct RR as per RFC
			rlen = htons(4);
			memcpy(rr_ptr, &m.type, sizeof(m.type));
			rr_ptr += sizeof(m.type);
			memcpy(rr_ptr, &m._class, sizeof(m._class));
			rr_ptr += sizeof(m._class);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, &in, sizeof(in));
			rr_ptr += sizeof(in);
			m.rr = string(rr, rr_ptr - rr);

			m.a_count = htons(1);
			m.ad_count = 0;
			m.rra_count = 0;

			// keep an idea which names we already have an RR for, but take
			// the real dname in this RR, not the compressed label
			A[m.fqdn] = dname + m.rr.substr(2);

		} else if (strcasecmp(type, "MX") == 0) {
			m.type = htons(dns_type::MX);
			string ip_rr = "";

			// check for already existing A/AAAA RR's, as we
			// want to pass them along in answer
			if (A.count(field) > 0)
				ip_rr = A[field];
			else if (AAAA.count(field) > 0)
				ip_rr = AAAA[field];
			if (ip_rr.size() == 0)
				cerr<<"WARN: MX RR '"<<m.fqdn<<"' w/o A/AAAA RR for '"<<field<<"' defined until here.\n";
			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 256)
				continue;
			rlen = htons(dname.size() + sizeof(uint16_t));
			memcpy(rr_ptr, &m.type, sizeof(m.type));
			rr_ptr += sizeof(m.type);
			memcpy(rr_ptr, &m._class, sizeof(m._class));
			rr_ptr += sizeof(m._class);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, &zero, sizeof(zero));		// preference
			rr_ptr += sizeof(zero);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			m.rr = string(rr, rr_ptr - rr);
			if (ip_rr.size() > 0) {
				m.rr += ip_rr;
				m.ad_count = htons(1);
			} else
				m.ad_count = 0;
			m.a_count = htons(1);
			m.rra_count = 0;
		} else if (strcasecmp(type, "AAAA") == 0) {
			m.type = htons(dns_type::AAAA);
			in6_addr in6;
			if (inet_pton(AF_INET6, field, &in6) != 1)
				continue;
			rlen = htons(sizeof(in6));
			memcpy(rr_ptr, &m.type, sizeof(m.type));
			rr_ptr += sizeof(m.type);
			memcpy(rr_ptr, &m._class, sizeof(m._class));
			rr_ptr += sizeof(m._class);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, &in6, sizeof(in6));
			rr_ptr += sizeof(in6);
			m.rr = string(rr, rr_ptr - rr);
			m.a_count = htons(1);
			m.ad_count = 0;
			m.rra_count = 0;

			AAAA[m.fqdn] = dname + m.rr.substr(2);
		} else if (strcasecmp(type, "NS") == 0) {
			m.type = htons(dns_type::NS);
			string ip_rr = "";
			if (A.count(field) > 0)
				ip_rr = A[field];
			else if (AAAA.count(field) > 0)
				ip_rr = AAAA[field];
			if (ip_rr.size() == 0)
				cerr<<"WARN: NS RR '"<<m.fqdn<<"' w/o A/AAAA RR for '"<<field<<"' defined until here.\n";

			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 256)
				continue;
			rlen = htons(dname.size());
			memcpy(rr_ptr, &m.type, sizeof(m.type));
			rr_ptr += sizeof(m.type);
			memcpy(rr_ptr, &m._class, sizeof(m._class));
			rr_ptr += sizeof(m._class);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			m.rr = string(rr, rr_ptr - rr);
			if (ip_rr.size() > 0) {
				m.rr += ip_rr;
				m.ad_count = htons(1);
			} else
				m.ad_count = 0;
			m.a_count = htons(1);
			m.rra_count = 0;
		} else if (strcasecmp(type, "CNAME") == 0) {
			m.type = htons(dns_type::CNAME);
			string ip_rr = "";
			if (A.count(field) > 0)
				ip_rr = A[field];
			else if (AAAA.count(field) > 0)
				ip_rr = AAAA[field];
			if (ip_rr.size() == 0)
				cerr<<"WARN: CNAME RR '"<<m.fqdn<<"' w/o A/AAAA RR for '"<<field<<"' defined until here.\n";

			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 256)
				continue;
			rlen = htons(dname.size());
			memcpy(rr_ptr, &m.type, sizeof(m.type));
			rr_ptr += sizeof(m.type);
			memcpy(rr_ptr, &m._class, sizeof(m._class));
			rr_ptr += sizeof(m._class);
			memcpy(rr_ptr, &ttl, sizeof(ttl));
			rr_ptr += sizeof(ttl);
			memcpy(rr_ptr, &rlen, sizeof(rlen));
			rr_ptr += sizeof(rlen);
			memcpy(rr_ptr, dname.c_str(), dname.size());
			rr_ptr += dname.size();
			m.rr = string(rr, rr_ptr - rr);
			if (ip_rr.size() > 0) {
				m.rr += ip_rr;
				m.ad_count = htons(1);
			} else
				m.ad_count = 0;

			m.a_count = htons(1);
			m.rra_count = 0;
		} else if (strcasecmp(type, "SOA") == 0) {
			m.type = htons(dns_type::SOA);
			string ip_rr = "";
			if (A.count(field) > 0)
				ip_rr = A[field];
			else if (AAAA.count(field) > 0)
				ip_rr = AAAA[field];
			if (ip_rr.size() == 0)
				cerr<<"WARN: SOA RR '"<<m.fqdn<<"' w/o A/AAAA RR for '"<<field<<"' defined until here.\n";
			if (host2qname(field, dname) <= 0)
				continue;
			if (dname.size() > 256)
				continue;
			rlen = htons(2*dname.size() + sizeof(soa_ints));
			memcpy(rr_ptr, &m.type, sizeof(m.type));
			rr_ptr += sizeof(m.type);
			memcpy(rr_ptr, &m._class, sizeof(m._class));
			rr_ptr += sizeof(m._class);
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
			m.rr = string(rr, rr_ptr - rr);
			if (ip_rr.size() > 0) {
				m.rr += ip_rr;
				m.ad_count = htons(1);
			} else
				m.ad_count = 0;
			m.a_count = 0;
			m.rra_count = htons(1);
		} else
			continue;

		if (m.mtype == QDNS_MATCH_EXACT)
			exact_matches[make_pair(m.name, m.type)] = m;
		else
			wild_matches[make_pair(m.name, m.type)] = m;

		++records;
	}
	fclose(f);
	cout<<"Successfully loaded "<<records<<" Quantum-RR's.\n";
	return 0;
}


}

