/* $Id: resolve.h,v 1.26 2003/03/22 23:16:49 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(struct in_addr ip);

#endif
