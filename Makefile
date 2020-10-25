LDLIBS=-lpcap -pthread

all: arp-spoof

arp-spoof: main.o arp_spoofing.o arphdr.o ethhdr.o iphdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
