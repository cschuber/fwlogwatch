/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: resolve.h,v 1.29 2004/04/25 18:56:22 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char * resolve_protocol(int proto);
char * resolve_service(int port, char *proto);
char * resolve_hostname(struct in_addr ip);

#endif
