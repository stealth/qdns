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
#include <string>
#include <unistd.h>
#include <iostream>
#include "qdns.h"


using namespace std;


void usage()
{
	cout<<"\nqdns [-Z zonefile] [-X] [-6] [-l local IPv4/6] [-p local port(=53)] [-M dev] [-R (Attention!)]\n\n"
	    <<"\t-X\tdo not send NXDOMAIN if no RR was found in zonefile\n"
	    <<"\t-M\trather than listening on (p)ort, capture on this device and also answer queries not for us\n"
	    <<"\t-R\tresend query rather than sending NXDOMAIN; only useful on a router with 2 NICs and a DROP FORWARD policy\n"
	    <<"\t\twhere resend is not seen via input NIC again! otherwise it recursively loops and spams peer with the same DNS query\n"
	    <<"\t-f\talso apply this filter when using -M mode\n"
	    <<"\t-6\tbind to v6 address or use IP6 capture when -M mode\n"
	    <<"\t-Z\tuse this zonefile (default=stdin)\n"
	    <<"\t-l\tbind to this address\n"
	    <<"\t-p\tbind to this port\n\n";
}


int main(int argc, char **argv)
{
	int c = 0;
	map<string, string> args;
	bool laddr_set = 0;

	cout<<"\nQUANTUM-DNS server (C) 2014-2018 Sebastian Krahmer -- https://github.com/stealth/qdns\n\n";

	args["laddr"] = "0.0.0.0";
	args["nxdomain"] = "1";
	args["zone"] = "/dev/stdin";

	while ((c = getopt(argc, argv, "l:p:M:6XRZ:f:")) != -1) {
		switch (c) {
		case 'f':
			args["filter"] = string(optarg);
			break;
		case 'l':
			args["laddr"] = string(optarg);
			laddr_set = 1;
			break;
		case 'p':
			args["lport"] = string(optarg);
			break;
		case 'M':
			args["mon"] = string(optarg);	// device
			args.erase("laddr");
			break;
		case '6':
			args["6"] = "1";
			if (!laddr_set && args.count("mon") == 0)
				args["laddr"] = "::";
			break;
		case 'R':
			args["resend"] = "1";
			break;
		case 'X':
			args["nxdomain"] = "0";
			break;
		case 'Z':
			args["zone"] = string(optarg);
			break;
		default:
			usage();
			return 1;
		}

	}

	qdns::qdns *quantum_dns = new (nothrow) qdns::qdns();

	if (quantum_dns->init(args) < 0) {
		cerr<<quantum_dns->why()<<endl;
		delete quantum_dns;
		return -1;
	}

	if (quantum_dns->parse_zone(args["zone"]) < 0) {
		cerr<<quantum_dns->why()<<endl;
		delete quantum_dns;
		return -1;
	}

	quantum_dns->loop();

	delete quantum_dns;
	return 0;
}

