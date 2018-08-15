

CXX=c++

# define this, if you also want to use layer2 sockets to be used
# on IPv6 on Linux, which isn't necessary there, as Linux may pass
# IPv6 headers on raw sockets, unlike on BSD etc.
#DEFS=-DUSE_L2TX

CXXFLAGS=-Wall -std=c++11 -pedantic -O2 -c -I/usr/local/include $(DEFS)
LD=c++
LIBS=-lusi++ -lpcap

# on some systems where libdumbnet isnt installed, this isnt needed
LIBS+=-ldnet

LDFLAGS=$(LIBS) -L/usr/local/lib

all: provider.o qdns.o main.o misc.o
	$(LD) *.o $(LDFLAGS) -o qdns

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


