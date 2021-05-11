object = sniffer.o
cc = gcc
#scanner : scanner.o
#	cc scanner -o scanner.o

sniffer : $(object)
	cc -o sniffer $(object) -lpthread
sniffer.o : sniffer.c sniffer.h
	cc -c -g sniffer.c
run : sniffer
	sudo ./sniffer
.PHONY :clean
clean :
	-rm sniffer $(object)
	sudo rm -rf ./snifflog
	sudo ifconfig ens33 -promisc
