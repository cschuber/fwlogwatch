/* $Id: resolve.h,v 1.20 2002/02/14 21:55:19 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(struct in_addr ip);

#endif
