# $Id: Makefile,v 1.22 2002/03/29 11:25:51 bwess Exp $

# Linux
CC = gcc
CFLAGS = -pipe -O2 -Wall #-pedantic -Wpointer-arith #-g #-p
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
#CFLAGS = -pipe -O2 -Wall -I/usr/local/include
#LIBS = -lz -L/usr/local/lib -lintl

# FreeBSD
#CC = gcc
#CFLAGS = -pipe -O2 -Wall -I/usr/local/include
#LIBS = -L/usr/local/lib -lintl -lcrypt -lz

# You might want to add -DSHORT_NAMES to CFLAGS if you only intend to
# analyze log formats with short list/chain/branch/interface names like
# ipchains. You can also add -DLOGDOTS if your Cisco log host logs FQDNs
# and you only want the hostnames in the output.


LEX = flex
LFLAGS = -B #-f #-p -p -d

INSTALL = install
INSTALL_PROGRAM = $(INSTALL) -s -m 0755
INSTALL_SCRIPT = $(INSTALL) -m 0755
INSTALL_DATA = $(INSTALL) -m 0644
INSTALL_DIR = /usr/local
CONF_DIR = /etc
LOCALE_DIR = /usr

OBJS = cisco_ios.o cisco_pix.o compare.o ipchains.o ipfilter.o \
       main.o modes.o net.o netfilter.o output.o parser.o \
       rcfile.o report.o resolve.o response.o utils.o whois.o win_xp.o

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
		main.h netfilter.h parser.h win_xp.h
rcfile.o:	main.h parser.h rcfile.h
report.o:	main.h output.h resolve.h response.h
resolve.o:	main.h resolve.h
response.o:	main.h output.h response.h
utils.o:	main.h
whois.o:	main.h utils.h
win_xp.o:	main.h utils.h

fwlogwatch:	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

install:	all
	$(INSTALL_PROGRAM) fwlogwatch $(INSTALL_DIR)/sbin/fwlogwatch
	$(INSTALL_SCRIPT) contrib/fwlw_notify $(INSTALL_DIR)/sbin/fwlw_notify
	$(INSTALL_SCRIPT) contrib/fwlw_respond $(INSTALL_DIR)/sbin/fwlw_respond
	$(INSTALL_DATA) fwlogwatch.8 $(INSTALL_DIR)/share/man/man8/fwlogwatch.8

install-config:
	$(INSTALL_DATA) fwlogwatch.config $(CONF_DIR)/fwlogwatch.config
	$(INSTALL_DATA) fwlogwatch.template $(CONF_DIR)/fwlogwatch.template

install-i18n:
	cd po; make
	$(INSTALL_DATA) po/de.mo $(LOCALE_DIR)/share/locale/de/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/pt_BR.mo $(LOCALE_DIR)/share/locale/pt_BR/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/sv.mo $(LOCALE_DIR)/share/locale/sv/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/zh_CN.mo $(LOCALE_DIR)/share/locale/zh_CN/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/zh_TW.mo $(LOCALE_DIR)/share/locale/zh_TW/LC_MESSAGES/fwlogwatch.mo

install-rhinit:
	$(INSTALL_SCRIPT) contrib/fwlogwatch.init.redhat $(CONF_DIR)/rc.d/init.d/fwlogwatch

uninstall:
	@rm -f $(INSTALL_DIR)/sbin/fwlogwatch \
		$(INSTALL_DIR)/sbin/fwlw_notify \
		$(INSTALL_DIR)/sbin/fwlw_respond \
		$(INSTALL_DIR)/man/man8/fwlogwatch.8 \
		$(LOCALE_DIR)/share/locale/de/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/pt_BR/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/sv/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/zh_CN/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/zh_TW/LC_MESSAGES/fwlogwatch.mo \
		$(CONF_DIR)/fwlogwatch.config \
		$(CONF_DIR)/fwlogwatch.template

clean:
	rm -f *.o *~ *.bak fwlogwatch
	cd po; make clean
