# $Id: Makefile,v 1.2 2002/02/14 20:09:16 bwess Exp $

CC=gcc
CFLAGS=-pipe -O2 -Wall #-pedantic -g -p
OBJ=main.o rcfile.o modes.o parser.o compare.o output.o resolve.o \
    report.o response.o utils.o
LDFLAGS=#-lefence

all:	fwlogwatch

compare.o:	compare.h main.h output.h
main.o:		main.h modes.h parser.h rcfile.h
modes.o:	compare.h main.h output.h parser.h report.h response.h
output.o:	main.h output.h resolve.h
parser.o:	compare.h main.h parser.h
rcfile.o:	main.h parser.h rcfile.h
report.o:	main.h output.h resolve.h response.h
resolve.o:	main.h resolve.h
response.o:	main.h output.h response.h
utils.o:	main.h

fwlogwatch:	$(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

install:	
	install -s -m 0755 fwlogwatch /usr/local/sbin/fwlogwatch
	install -m 0644 fwlogwatch.config /etc/fwlogwatch.config
	install -m 0644 fwlogwatch.template /etc/fwlogwatch.template
	install -m 0644 fwlogwatch.8 /usr/local/man/man8/fwlogwatch.8

clean:
	rm -f *.o *~ fwlogwatch
