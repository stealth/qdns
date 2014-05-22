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

#ifndef __misc_h__
#define __misc_h__

#include <string>

namespace qdns {

int host2qname(const std::string &, std::string &);

int qname2host(const std::string &, std::string &);


}


#endif

