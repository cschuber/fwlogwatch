/* $Id: resolve.h,v 1.19 2002/02/14 21:48:38 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(struct in_addr ip);

#endif
