# $Id: Makefile,v 1.5 2002/02/14 20:36:55 bwess Exp $

CC=gcc
CFLAGS=-pipe -O2 -Wall #-pedantic -g -p
OBJ= compare.o main.o modes.o net.o netfilter.o output.o parser.o \
  rcfile.o report.o resolve.o response.o utils.o
LDFLAGS=-lcrypt #-lefence
FLEX=flex
INSTALL=install
INSTALL_PROGRAM=$(INSTALL) -s -m 0755
INSTALL_DATA=$(INSTALL) -m 0644
SHELL=/bin/sh
.SUFFIXES:
.SUFFIXES: .c .o

all:	fwlogwatch

compare.o:	compare.h main.h output.h
main.o:		main.h modes.h parser.h rcfile.h
modes.o:	compare.h main.h net.h output.h parser.h report.h response.h
net.o:		main.h utils.h
netfilter.o:	main.h netfilter.h
output.o:	main.h output.h resolve.h
parser.o:	compare.h main.h parser.h
rcfile.o:	main.h parser.h rcfile.h
report.o:	main.h output.h resolve.h response.h
resolve.o:	main.h resolve.h
response.o:	main.h output.h response.h
utils.o:	main.h

netfilter.c:	netfilter.yy
	$(FLEX) netfilter.yy

fwlogwatch:	$(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

install:	
	$(INSTALL_PROGRAM) fwlogwatch /usr/local/sbin/fwlogwatch
	$(INSTALL_DATA) fwlogwatch.8 /usr/local/man/man8/fwlogwatch.8

install-rpm:	
	$(INSTALL_PROGRAM) fwlogwatch /usr/sbin/fwlogwatch
	$(INSTALL_DATA) fwlogwatch.8 /usr/man/man8/fwlogwatch.8

install-config:	
	$(INSTALL_DATA) fwlogwatch.config /etc/fwlogwatch.config
	$(INSTALL_DATA) fwlogwatch.template /etc/fwlogwatch.template

uninstall:	
	@rm -f /usr/local/sbin/fwlogwatch /usr/local/man/man8/fwlogwatch.8 \
	/usr/sbin/fwlogwatch /usr/man/man8/fwlogwatch.8 \
	/etc/fwlogwatch.config /etc/fwlogwatch.template

profile:	
	$(CC) -static -g -p $(OBJ) -o fwlogwatch -lc_p $(LDFLAGS)

clean:
	rm -f *.o *~ *.bak netfilter.c fwlogwatch
