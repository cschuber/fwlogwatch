# $Id: Makefile,v 1.3 2002/02/14 21:55:19 bwess Exp $

all:	
	msgfmt -v -o de.mo de.po
	msgfmt -v -o pt_BR.mo pt_BR.po
	msgfmt -v -o zh_CN.mo zh_CN.po
	msgfmt -v -o se.mo se.po

strings:	
	xgettext -d fwlogwatch -k_ ../*.c ../*.h

merge:	
	msgmerge -v -o de.po.new de.po fwlogwatch.pot
	msgmerge -v -o pt_BR.po.new pt_BR.po fwlogwatch.pot
	msgmerge -v -o zh_CN.po.new zh_CN.po fwlogwatch.pot
	msgmerge -v -o se.po.new se.po fwlogwatch.pot

clean:
	rm -f *~ *.mo
