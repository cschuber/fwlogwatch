# $Id: Makefile,v 1.8 2002/02/14 20:48:49 bwess Exp $

# Linux
CFLAGS=-pipe -O2 -Wall #-pedantic -g -p
LDFLAGS=-lcrypt

# Solaris
#CFLAGS=-DSOLARIS -pipe -O2 -Wall #-pedantic -g
#LDFLAGS=-lcrypt -lnsl -lsocket

# You can add -DLOGDOTS to CFLAGS if your log host logs FQDNs
# and you only want the hostnames in the output.


CC=gcc
OBJ= cisco.o compare.o ipchains.o main.o modes.o net.o netfilter.o \
     output.o parser.o rcfile.o report.o resolve.o response.o utils.o
FLEX=flex
INSTALL=install
INSTALL_PROGRAM=$(INSTALL) -s -m 0755
INSTALL_DATA=$(INSTALL) -m 0644
SHELL=/bin/sh
.SUFFIXES:
.SUFFIXES: .c .o

all:	fwlogwatch

cisco.o:	main.h utils.h
compare.o:	compare.h main.h output.h
ipchains.o:	main.h utils.h
main.o:		main.h modes.h parser.h rcfile.h
modes.o:	compare.h main.h net.h output.h parser.h report.h response.h
net.o:		main.h utils.h
netfilter.o:	main.h utils.h
output.o:	main.h output.h resolve.h
parser.o:	cisco.h compare.h main.h netfilter.h parser.h
rcfile.o:	main.h parser.h rcfile.h
report.o:	main.h output.h resolve.h response.h
resolve.o:	main.h resolve.h
response.o:	main.h output.h response.h
utils.o:	main.h

ipchains.c:	ipchains.yy
	$(FLEX) ipchains.yy
cisco.c:	cisco.yy
	$(FLEX) cisco.yy
netfilter.c:	netfilter.yy
	$(FLEX) netfilter.yy

fwlogwatch:	$(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

install:	
	$(INSTALL_PROGRAM) fwlogwatch /usr/local/sbin/fwlogwatch
	$(INSTALL_DATA) fwlogwatch.8 /usr/local/man/man8/fwlogwatch.8

install-rpm:	
	$(INSTALL_PROGRAM) fwlogwatch /usr/sbin/fwlogwatch
	$(INSTALL_DATA) fwlogwatch.8 /usr/share/man/man8/fwlogwatch.8

install-config:	
	$(INSTALL_DATA) fwlogwatch.config /etc/fwlogwatch.config
	$(INSTALL_DATA) fwlogwatch.template /etc/fwlogwatch.template

uninstall:	
	@rm -f /usr/local/sbin/fwlogwatch /usr/local/man/man8/fwlogwatch.8 \
	/usr/sbin/fwlogwatch /usr/share/man/man8/fwlogwatch.8 \
	/etc/fwlogwatch.config /etc/fwlogwatch.template

profile:	
	$(CC) -static -g -p $(OBJ) -o fwlogwatch -lc_p $(LDFLAGS)

clean:
	rm -f *.o *~ *.bak ipchains.c cisco.c netfilter.c fwlogwatch
