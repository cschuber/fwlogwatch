/* Copyright (C) 2000-2011 Boris Wesslowski */
/* $Id: whois.h,v 1.16 2011/11/14 12:53:52 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry *whois(struct in6_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
