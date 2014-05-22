CXX=c++
CXXFLAGS=-Wall -std=c++11 -pedantic -O2 -c
LD=c++
LDFLAGS=-lusi++ -lpcap -ldnet

all: provider.o qdns.o main.o misc.o
	$(LD) $(LDFLAGS) *.o -o qdns

misc.o: misc.cc misc.h
	$(CXX) $(CXXFLAGS) misc.cc

provider.o: provider.cc provider.h
	$(CXX) $(CXXFLAGS) provider.cc

qdns.o: qdns.cc qdns.h
	$(CXX) $(CXXFLAGS) qdns.cc

main.o: main.cc
	$(CXX) $(CXXFLAGS) main.cc

clean:
	rm -f *.o


