# $Id: Makefile,v 1.1 2002/02/14 21:36:54 bwess Exp $

strings:	
	xgettext -d fwlogwatch -k_ ../*.c

merge:	
	msgmerge -v -o de.po.new de.po fwlogwatch.pot

de:	
	msgfmt -v -o de.mo de.po

clean:
	rm -f *~ *.mo
