/* $Id: resolve.h,v 1.3 2002/02/14 20:25:35 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(char *ip);

#endif