# Copyright (C) 2000-2011 Boris Wesslowski
# $Id: Makefile,v 1.32 2011/11/14 12:53:52 bwess Exp $

# You might want to add -DSHORT_NAMES to CFLAGS if you only intend to analyze
# log formats with short list/chain/branch/interface names like ipchains.
# You can also add -DLOGDOTS if your Cisco log host logs FQDNs and you only
# want the host names in the output.
# -DHAVE_ZLIB enables support for gzip compressed files.
# -DHAVE_GETTEXT enables localization support.
# -DHAVE_ADNS enables support for asynchronous DNS lookups.

# Linux
CC = gcc
CFLAGS = -DHAVE_ZLIB -DHAVE_GETTEXT -pipe -O2 -Wall #-pedantic -Wpointer-arith #-g #-p
LDFLAGS = -s #-g #-static -p
LIBS = -lcrypt -lz #-ladns #-lc_p

# Mac OS X
#CC = gcc
#CFLAGS = -DHAVE_ZLIB -pipe -O2 -Wall
#LIBS = -lz

# Solaris
#LIBS = -lnsl -lsocket -lcrypt -lz
#
#CC = gcc
#CFLAGS = -DSOLARIS -DHAVE_ZLIB -DHAVE_GETTEXT -pipe -O2 -Wall #-pedantic #-g
#LDFLAGS = #-g
#
#CC = cc
#CFLAGS = -DSOLARIS -DHAVE_ZLIB -DHAVE_GETTEXT -v -fast -xCC

# OpenBSD
#CC = gcc
#CFLAGS = -DHAVE_ZLIB -DHAVE_GETTEXT -pipe -O2 -Wall -I/usr/local/include
#LIBS = -L/usr/local/lib -lz -lintl

# FreeBSD
#CC = gcc
#CFLAGS = -DHAVE_ZLIB -DHAVE_GETTEXT -pipe -O2 -Wall -I/usr/local/include
#LIBS = -L/usr/local/lib -lcrypt -lz -lintl


LEX = flex
LFLAGS = -B --nounput #-f #-p -p -d

INSTALL = install
INSTALL_PROGRAM = $(INSTALL) -m 0755
INSTALL_SCRIPT = $(INSTALL) -m 0755
INSTALL_DATA = $(INSTALL) -m 0644
INSTALL_DIR = /usr/local
CONF_DIR = /etc
LOCALE_DIR = /usr

OBJS = cisco_ios.o cisco_pix.o compare.o ipchains.o ipfilter.o ipfw.o \
       lancom.o main.o modes.o net.o netfilter.o netscreen.o output.o \
       parser.o rcfile.o resolve.o response.o snort.o utils.o whois.o

all:	fwlogwatch

cisco_ios.o:	main.h utils.h
cisco_pix.o:	main.h utils.h
compare.o:	compare.h main.h output.h utils.h
ipchains.o:	main.h utils.h
ipfilter.o:	main.h utils.h
ipfw.o:		main.h utils.h
lancom.o:	main.h utils.h
main.o:		main.h modes.h parser.h rcfile.h utils.h
modes.o:	compare.h main.h net.h output.h parser.h rcfile.h \
		resolve.h response.h utils.h whois.h
net.o:		compare.h main.h output.h resolve.h response.h utils.h
netfilter.o:	main.h utils.h
netscreen.o:	main.h utils.h
output.o:	main.h output.h resolve.h utils.h whois.h
parser.o:	cisco_ios.h cisco_pix.h compare.h ipchains.h ipfilter.h \
		ipfw.h main.h netfilter.h netscreen.h parser.h snort.h
rcfile.o:	main.h parser.h rcfile.h utils.h
resolve.o:	main.h resolve.h utils.h
response.o:	main.h response.h utils.h
snort.o:	main.h utils.h
utils.o:	main.h
whois.o:	main.h utils.h

fwlogwatch:	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

install:	all
	$(INSTALL_PROGRAM) fwlogwatch $(INSTALL_DIR)/sbin/fwlogwatch
	$(INSTALL_SCRIPT) contrib/fwlw_notify $(INSTALL_DIR)/sbin/fwlw_notify
	$(INSTALL_SCRIPT) contrib/fwlw_respond $(INSTALL_DIR)/sbin/fwlw_respond
	$(INSTALL_DATA) fwlogwatch.8 $(INSTALL_DIR)/share/man/man8/fwlogwatch.8

install-config:
	$(INSTALL_DATA) fwlogwatch.config $(CONF_DIR)/fwlogwatch.config

install-i18n:
	cd po; make
	$(INSTALL_DATA) po/de.mo $(LOCALE_DIR)/share/locale/de/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/ja.mo $(LOCALE_DIR)/share/locale/ja/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/pt.mo $(LOCALE_DIR)/share/locale/pt/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/sv.mo $(LOCALE_DIR)/share/locale/sv/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/zh_CN.mo $(LOCALE_DIR)/share/locale/zh_CN/LC_MESSAGES/fwlogwatch.mo
	$(INSTALL_DATA) po/zh_TW.mo $(LOCALE_DIR)/share/locale/zh_TW/LC_MESSAGES/fwlogwatch.mo

install-rhinit:
	$(INSTALL_SCRIPT) contrib/fwlogwatch.init.redhat $(CONF_DIR)/rc.d/init.d/fwlogwatch

uninstall:
	@rm -f $(INSTALL_DIR)/sbin/fwlogwatch \
		$(INSTALL_DIR)/sbin/fwlw_notify \
		$(INSTALL_DIR)/sbin/fwlw_respond \
		$(INSTALL_DIR)/share/man/man8/fwlogwatch.8 \
		$(LOCALE_DIR)/share/locale/de/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/ja/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/pt/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/sv/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/zh_CN/LC_MESSAGES/fwlogwatch.mo \
		$(LOCALE_DIR)/share/locale/zh_TW/LC_MESSAGES/fwlogwatch.mo \
		$(CONF_DIR)/fwlogwatch.config \

clean:
	rm -f *.o *~ *.bak fwlogwatch
	cd po; make clean

indent:
	indent --k-and-r-style --indent-level 2 --line-length 180 *.c *.h
