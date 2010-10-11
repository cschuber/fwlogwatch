# Copyright (C) 2000-2006 Boris Wesslowski
# $Id: Makefile,v 1.13 2010/10/11 12:17:44 bwess Exp $

all:
	msgfmt -v -o de.mo de.po
	msgfmt -v -o ja.mo ja.po
	msgfmt -v -o pt_BR.mo pt_BR.po
	msgfmt -v -o sv.mo sv.po
	msgfmt -v -o zh_CN.mo zh_CN.po
	msgfmt -v -o zh_TW.mo zh_TW.po

strings:
	xgettext -d fwlogwatch -k_ ../*.c ../*.h

merge:
	msgmerge -v -o de.po.new de.po fwlogwatch.pot
	msgmerge -v -o ja.po.new ja.po fwlogwatch.pot
	msgmerge -v -o pt_BR.po.new pt_BR.po fwlogwatch.pot
	msgmerge -v -o sv.po.new sv.po fwlogwatch.pot
	msgmerge -v -o zh_CN.po.new zh_CN.po fwlogwatch.pot
	msgmerge -v -o zh_TW.po.new zh_TW.po fwlogwatch.pot

clean:
	rm -f *~ *.mo
