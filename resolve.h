/* $Id: resolve.h,v 1.24 2002/05/15 22:24:44 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(struct in_addr ip);

#endif
