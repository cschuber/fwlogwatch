# $Id: Makefile,v 1.7 2002/05/15 22:24:44 bwess Exp $

all:
	msgfmt -v -o de.mo de.po
	msgfmt -v -o pt_BR.mo pt_BR.po
	msgfmt -v -o sv.mo sv.po
	msgfmt -v -o zh_CN.mo zh_CN.po
	msgfmt -v -o zh_TW.mo zh_TW.po

strings:
	xgettext -d fwlogwatch -k_ ../*.c ../*.h

merge:
	msgmerge -v -o de.po.new de.po fwlogwatch.pot
	msgmerge -v -o pt_BR.po.new pt_BR.po fwlogwatch.pot
	msgmerge -v -o sv.po.new sv.po fwlogwatch.pot
	msgmerge -v -o zh_CN.po.new zh_CN.po fwlogwatch.pot
	msgmerge -v -o zh_TW.po.new zh_TW.po fwlogwatch.pot

clean:
	rm -f *~ *.mo
