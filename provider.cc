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
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <usi++/usi++.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "provider.h"


using namespace std;
using namespace usipp;

namespace qdns {


int socket_provider::init(const map<string, string> &args)
{
	auto it = args.find("laddr");

	if (it != args.end())
		laddr = it->second;

	if ((it = args.find("lport")) != args.end())
		lport = it->second;

	addrinfo *ai = NULL;
	if (getaddrinfo(laddr.c_str(), lport.c_str(), NULL, &ai) != 0)
		return build_error("init: failed to resolve 'laddr'");

	if ((sock = socket(ai->ai_family, SOCK_DGRAM, 0)) < 0)
		return build_error("init: socket");

	if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0)
		return build_error("init: bind");

	family = ai->ai_family;

	return 0;
}


int socket_provider::recv(string &pkt)
{
	pkt = "";

	char buf[1024];
	sockaddr *from = (sockaddr *)&from4;
	socklen_t flen = sizeof(from4);

	if (family == AF_INET6) {
		from = (sockaddr *)&from6;
		flen = sizeof(from6);
	}

	memset(buf, 0, sizeof(buf));

	ssize_t r = 0;
	if ((r = recvfrom(sock, buf, sizeof(buf), 0, from, &flen)) < 0)
		return build_error("recv: recvfrom");

	pkt = string(buf, r);

	return 0;
}


int socket_provider::reply(const string &pkt)
{
	sockaddr *from = (sockaddr *)&from4;
	socklen_t flen = sizeof(from4);

	if (family == AF_INET6) {
		from = (sockaddr *)&from6;
		flen = sizeof(from6);
	}

	if (sendto(sock, pkt.c_str(), pkt.size(), 0, from, flen) < 0)
		return build_error("send: sendto");

	return 0;
}


int socket_provider::build_error(const string &s)
{
	err = "socket_provider::";
	err += s;
	if (errno) {
		err += ": ";
		err += strerror(errno);
	}
	return -1;
}


string socket_provider::sender()
{
	char buf[256];
	string s = "<err>";

	memset(buf, 0, sizeof(buf));

	if (family == AF_INET) {
		if (!inet_ntop(AF_INET, &from4.sin_addr, buf, sizeof(buf)))
			return s;
		s = buf;
		snprintf(buf, sizeof(buf), ":%d", ntohs(from4.sin_port));
		s += buf;
	} else {
		if (!inet_ntop(AF_INET6, &from6.sin6_addr, buf, sizeof(buf)))
			return s;
		s = buf;
		snprintf(buf, sizeof(buf), "#%d", ntohs(from6.sin6_port));
		s += buf;
	}
	return s;
}



int usipp_provider::init(const map<string, string> &args)
{
	string dev = "eth0", f = "udp and dst port 53";

	auto it = args.find("mon");
	if (it != args.end())
		dev = it->second;

	if ((it = args.find("filter")) != args.end()) {
		f = it->second;
		f += " and udp and dst port 53";
	}
	if (args.count("6") > 0) {
		mon6 = new (nothrow) UDP6("::");
		family = AF_INET6;

		if (mon6->init_device(dev, 1, 1500) < 0)
			return build_error("init: " + string(mon6->why()));
		if (mon6->setfilter(f) < 0)
			return build_error("init: " + string(mon6->why()));

	} else {
		mon4 = new (nothrow) UDP4("0.0.0.0");
		family = AF_INET;
		if (mon4->init_device(dev, 1, 1500) < 0)
			return build_error("init: " + string(mon4->why()));
		if (mon4->setfilter(f) < 0)
			return build_error("init: " + string(mon4->why()));
	}

	return 0;
}


int usipp_provider::recv(string &pkt)
{
	pkt = "";

	if (!mon4 && !mon6)
		return build_error("usipp_provider not initialized");

	if (mon4) {
		mon4->sniffpack(pkt);
		if (!pkt.size())
			return build_error("recv: " + string(mon4->why()));
		mon4->get_src(src4);
	} else if (mon6) {
		mon6->sniffpack(pkt);
		if (!pkt.size())
			return build_error("recv: " + string(mon6->why()));
		mon6->get_src(src6);
	}

	return 0;
}


int usipp_provider::reply(const string &pkt)
{
	if (!mon4 && !mon6)
		return build_error("usipp_provider not initialized");
	if (mon4) {
		uint32_t s = mon4->get_src();
		uint32_t d = mon4->get_dst();
		mon4->set_src(d);
		mon4->set_dst(s);
		mon4->set_dstport(mon4->get_srcport());
		mon4->set_srcport(53);
		mon4->set_options("");
		mon4->set_totlen(0);	// IPv4 len
		mon4->set_len(0);	// UDP len
		mon4->set_udpsum(0);
		mon4->set_sum(0);
		if (mon4->sendpack(pkt) < 0)
			return build_error("reply: " + string(mon4->why()));
	} else if (mon6) {
		usipp::in6_addr s = mon6->get_src();
		usipp::in6_addr d = mon6->get_dst();
		mon6->set_src(d);
		mon6->set_dst(s);
		mon6->set_dstport(mon6->get_srcport());
		mon6->set_srcport(53);
		mon6->clear_headers();
		mon6->set_payloadlen(0);
		mon6->set_len(0);
		mon6->set_udpsum(0);
		if (mon6->sendpack(pkt) < 0)
			return build_error("reply: " + string(mon6->why()));
	}
	return 0;
}


int usipp_provider::resend(const string &pkt)
{
	if (!mon4 && !mon6)
		return build_error("usipp_provider not initialized");
	if (mon4) {
		if (mon4->sendpack(pkt) < 0)
			return build_error("reply: " + string(mon4->why()));
	} else if (mon6) {
		if (mon6->sendpack(pkt) < 0)
			return build_error("reply: " + string(mon6->why()));
	}
	return 0;
}


string usipp_provider::sender()
{
	if (mon4)
		return src4;
	else if (mon6)
		return src6;
	return "<err>";
}


int usipp_provider::build_error(const string &s)
{
	err = "usipp_provider::";
	err += s;
	if (errno) {
		err += ": ";
		err += strerror(errno);
	}
	return -1;
}


} // namespace

