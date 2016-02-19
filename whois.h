/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: whois.h,v 1.18 2016/02/19 16:09:27 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry *whois(struct in6_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
