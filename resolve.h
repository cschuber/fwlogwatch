/* Copyright (C) 2000-2013 Boris Wesslowski */
/* $Id: resolve.h,v 1.33 2013/05/23 15:04:15 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char *resolve_protocol(int proto);
char *resolve_service(int port, char *proto);
char *resolve_address(struct in6_addr ip);
void init_dns_cache(struct in6_addr *ip, char *hostname);

#ifdef HAVE_ADNS
enum {
  RES_ADNS_PC,
  RES_ADNS_HS
};
void adns_preresolve(unsigned char mode);
#endif

struct in6_addr *resolve_hostname_from_cache(char *name);

#endif
