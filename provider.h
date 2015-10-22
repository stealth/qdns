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

#ifndef qdns_provider_h
#define qdns_provider_h

#include <map>
#include <string>
#include <cstdint>
#include <usi++/usi++.h>
#include <netinet/in.h>

namespace qdns {

class dns_provider {

protected:

	std::string err;

	virtual int build_error(const std::string &) = 0;


public:
	dns_provider() = default;

	virtual ~dns_provider()
	{
	}

	virtual int init(const std::map<std::string, std::string> &) = 0;

	virtual int recv(std::string &pkt) = 0;

	virtual int reply(const std::string &pkt) = 0;

	virtual std::string sender() = 0;

	virtual int resend(const std::string &pkt)
	{
		return 0;
	}


	const char *why()
	{
		return err.c_str();
	}
};



class socket_provider : public dns_provider {

	int sock, family;
	std::string laddr, lport;

	sockaddr_in from4;
	sockaddr_in6 from6;

protected:

	int build_error(const std::string &);


public:

	socket_provider() : sock(-1), family(AF_INET), laddr("0.0.0.0"), lport("53")
	{
	}

	virtual ~socket_provider()
	{
	}

	virtual int init(const std::map<std::string, std::string> &);

	virtual int recv(std::string &pkt);

	virtual int reply(const std::string &pkt);

	virtual std::string sender();
};


class usipp_provider : public dns_provider {

	usipp::UDP4 *mon4;
	usipp::UDP6 *mon6;

	std::string src4;
	std::string src6;

	int family;

protected:

	int build_error(const std::string &);


public:
	usipp_provider() : mon4(NULL), mon6(NULL),
	           src4(""), src6(""), family(AF_UNSPEC)
	{}

	virtual int init(const std::map<std::string, std::string> &);

	virtual int recv(std::string &pkt);

	virtual int reply(const std::string &pkt);

	virtual int resend(const std::string &pkt);

	virtual std::string sender();
};


}  // namespace

#endif

