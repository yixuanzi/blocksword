CC=gcc
LD=ld

bs:abuse.o abuse_http.o abuse_icmp.o abuse_tcp.o abuse_udp.o derule.o func.o http.o icmp.o ip.o pdata.o sysconfig.o tcp.o udp.o main.o bspcap.o
	$(LD) -o $@ $^ -lpcap

abuse.o:abuse/abuse.c
	$(CC) -c -I include $^ -o $@
abuse_http.o:abuse/abuse_http.c
	$(CC) -c -I include $^ -o $@
abuse_icmp.o:abuse/abuse_icmp.c
	$(CC) -c -I include $^ -o $@
abuse_tcp.o:abuse/abuse_tcp.c
	$(CC) -c -I include $^ -o $@
abuse_udp.o:abuse/abuse_udp.c
	$(CC) -c -I include $^ -o $@
derule.o:analysis/derule.c
	$(CC) -c -I include $^ -o $@
func.o:analysis/func.c
	$(CC) -c -I include $^ -o $@
http.o:analysis/http.c
	$(CC) -c -I include $^ -o $@
icmp.o:analysis/icmp.c
	$(CC) -c -I include $^ -o $@
ip.o:analysis/ip.c
	$(CC) -c -I include $^ -o $@
pdata.o:analysis/pdata.c
	$(CC) -c -I include $^ -o $@
sysconfig.o:analysis/sysconfig.c
	$(CC) -c -I include $^ -o $@
tcp.o:analysis/tcp.c
	$(CC) -c -I include $^ -o $@
udp.o:analysis/udp.c
	$(CC) -c -I include $^ -o $@
main.o:main/main.c
	$(CC) -c -I include $^ -o $@
bspcap.o:pcap/bspcap.c
	$(CC) -c -I include $^ -o $@


clean:
	rm *.o 
