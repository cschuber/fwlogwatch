/* $Id: resolve.h,v 1.22 2002/03/29 11:25:52 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(struct in_addr ip);

#endif
