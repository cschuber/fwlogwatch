/* $Id: resolve.h,v 1.1 2002/02/14 19:43:03 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(char *ip);

#endif
