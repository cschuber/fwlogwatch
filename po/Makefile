# $Id: Makefile,v 1.2 2002/02/14 21:48:38 bwess Exp $

all:	
	msgfmt -v -o de.mo de.po
	msgfmt -v -o pt_BR.mo pt_BR.po
	msgfmt -v -o zh.mo zh.po

strings:	
	xgettext -d fwlogwatch -k_ ../*.c

merge:	
	msgmerge -v -o de.po.new de.po fwlogwatch.pot
	msgmerge -v -o pt_BR.po.new pt_BR.po fwlogwatch.pot
	msgmerge -v -o zh.po.new zh.po fwlogwatch.pot

clean:
	rm -f *~ *.mo
