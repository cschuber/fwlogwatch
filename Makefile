# $Id: Makefile,v 1.19 2002/02/14 21:48:38 bwess Exp $

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
#CFLAGS = -pipe -O2 -Wall
#LIBS = -lz

# FreeBSD
#CC = gcc
#CFLAGS = -pipe -O2 -Wall -I/usr/local/include
#LIBS = -L/usr/local/lib -lintl -lcrypt -lz

# You might want to add -DSHORT_NAMES to CFLAGS if you only intend to
# analyze log formats with short list/chain/branch/interface names like
# ipchains. You can also add -DLOGDOTS if your cisco log host logs FQDNs
# and you only want the hostnames in the output.


LEX = flex
LFLAGS = -B #-f #-p -p -d

INSTALL = install
INSTALL_PROGRAM = $(INSTALL) -s -m 0755
INSTALL_SCRIPT = $(INSTALL) -m 0755
INSTALL_DATA = $(INSTALL) -m 0644

OBJS = cisco_ios.o cisco_pix.o compare.o ipchains.o ipfilter.o \
       main.o modes.o net.o netfilter.o output.o parser.o \
       rcfile.o report.o resolve.o response.o utils.o whois.o

all:	fwlogwatch

cisco_ios.o:	main.h utils.h
cisco_pix.o:	main.h utils.h
compare.o:	compare.h main.h output.h
ipchains.o:	main.h utils.h
ipfilter.o:	main.h utils.h
main.o:		main.h modes.h parser.h rcfile.h
modes.o:	compare.h main.h net.h output.h parser.h report.h \
		response.h whois.h
net.o:		main.h utils.h
netfilter.o:	main.h utils.h
output.o:	main.h output.h resolve.h
parser.o:	cisco_ios.h cisco_pix.h compare.h ipchains.h ipfilter.h \
		main.h netfilter.h parser.h
rcfile.o:	main.h parser.h rcfile.h
report.o:	main.h output.h resolve.h response.h
resolve.o:	main.h resolve.h
response.o:	main.h output.h response.h
utils.o:	main.h
whois.o:	main.h utils.h

fwlogwatch:	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

install:	all
	$(INSTALL_PROGRAM) fwlogwatch /usr/local/sbin/fwlogwatch
	$(INSTALL_SCRIPT) contrib/fwlw_notify /usr/local/sbin/fwlw_notify
	$(INSTALL_SCRIPT) contrib/fwlw_respond /usr/local/sbin/fwlw_respond
	$(INSTALL_DATA) fwlogwatch.8 /usr/local/man/man8/fwlogwatch.8

install-config:
	$(INSTALL_DATA) fwlogwatch.config /etc/fwlogwatch.config
	$(INSTALL_DATA) fwlogwatch.template /etc/fwlogwatch.template

install-i18n:
	cd po; make
	$(INSTALL_DATA) po/de.mo /usr/share/locale/de/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/pt_BR.mo /usr/share/locale/pt/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/zh.mo /usr/share/locale/zh/LC_MESSAGES/fwlogwatch.mo

uninstall:
	@rm -f /usr/local/sbin/fwlogwatch \
		/usr/local/sbin/fwlw_notify \
		/usr/local/sbin/fwlw_respond \
		/usr/local/man/man8/fwlogwatch.8 \
		/usr/share/locale/de/LC_MESSAGES/fwlogwatch.mo \
		/usr/share/locale/pt/LC_MESSAGES/fwlogwatch.mo \
		/usr/share/locale/zh/LC_MESSAGES/fwlogwatch.mo \
		/etc/fwlogwatch.config \
		/etc/fwlogwatch.template

clean:
	rm -f *.o *~ *.bak fwlogwatch
	cd po; make clean
