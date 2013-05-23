/* Copyright (C) 2000-2013 Boris Wesslowski */
/* $Id: whois.h,v 1.17 2013/05/23 15:04:15 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry *whois(struct in6_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
