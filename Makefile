# $Id: Makefile,v 1.14 2002/02/14 21:15:35 bwess Exp $

# Linux
CC = gcc
CFLAGS = -pipe -O2 -Wall #-pedantic #-g #-p
LDFLAGS = #-g #-static -p
LIBS = -lcrypt -lz #-lc_p

# Solaris
#LIBS = -lnsl -lsocket -lz -lcrypt
#
#CC = gcc
#CFLAGS = -DSOLARIS -pipe -O2 -Wall #-pedantic #-g
#LDFLAGS = #-g
#
#CC = cc
#CFLAGS = -DSOLARIS -v -fast -xCC

# OpenBSD
#CC = gcc
#CFLAGS = -pipe -O2 -Wall #-pedantic #-g #-p
#LDFLAGS = #-g
#LIBS = -lz


# You can add -DLOGDOTS to CFLAGS if your cisco log host logs FQDNs and you
# only want the hostnames in the output. -DLONG_NAMES will also allow long
# list/chain/branch/interface names.


LEX = flex
LFLAGS = -B #-f #-p -p -d

INSTALL = install
INSTALL_PROGRAM = $(INSTALL) -s -m 0755
INSTALL_DATA = $(INSTALL) -m 0644
INSTALL_DIR = /usr
CONF_DIR = /etc

OBJS = cisco.o compare.o ipchains.o ipfilter.o main.o modes.o net.o \
       netfilter.o output.o parser.o rcfile.o report.o resolve.o \
       response.o utils.o

all:	fwlogwatch

cisco.o:	main.h utils.h
compare.o:	compare.h main.h output.h
ipchains.o:	main.h utils.h
ipfilter.o:	main.h utils.h
main.o:		main.h modes.h parser.h rcfile.h
modes.o:	compare.h main.h net.h output.h parser.h report.h response.h
net.o:		main.h utils.h
netfilter.o:	main.h utils.h
output.o:	main.h output.h resolve.h
parser.o:	cisco.h compare.h ipchains.h ipfilter.h main.h netfilter.h \
		parser.h
rcfile.o:	main.h parser.h rcfile.h
report.o:	main.h output.h resolve.h response.h
resolve.o:	main.h resolve.h
response.o:	main.h output.h response.h
utils.o:	main.h

fwlogwatch:	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

install:	all
	$(INSTALL_PROGRAM) fwlogwatch $(INSTALL_DIR)/local/sbin/fwlogwatch
	$(INSTALL_DATA) fwlogwatch.8 $(INSTALL_DIR)/local/man/man8/fwlogwatch.8

install-rpm:	all
	$(INSTALL_PROGRAM) fwlogwatch $(INSTALL_DIR)/sbin/fwlogwatch
	$(INSTALL_DATA) fwlogwatch.8 $(INSTALL_DIR)/share/man/man8/fwlogwatch.8

install-config:	
	$(INSTALL_DATA) fwlogwatch.config $(CONF_DIR)/fwlogwatch.config
	$(INSTALL_DATA) fwlogwatch.template $(CONF_DIR)/fwlogwatch.template

uninstall:	
	@rm -f $(INSTALL_DIR)/local/sbin/fwlogwatch \
		$(INSTALL_DIR)/local/man/man8/fwlogwatch.8 \
		$(INSTALL_DIR)/sbin/fwlogwatch \
		$(INSTALL_DIR)/share/man/man8/fwlogwatch.8 \
		$(CONF_DIR)/fwlogwatch.config \
		$(CONF_DIR)/etc/fwlogwatch.template

clean:
	rm -f *.o *~ *.bak fwlogwatch
