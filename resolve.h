/* Copyright (C) 2000-2010 Boris Wesslowski */
/* $Id: resolve.h,v 1.31 2010/10/11 12:28:33 bwess Exp $ */

#ifndef _RESOLVE_H
#define _RESOLVE_H

char *resolve_protocol(int proto);
char *resolve_service(int port, char *proto);
char *resolve_hostname(struct in_addr ip);

#ifdef HAVE_ADNS
enum {
  RES_ADNS_PC,
  RES_ADNS_HS
};
void adns_preresolve(unsigned char mode);
#endif

#endif
