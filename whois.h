/* Copyright (C) 2000-2006 Boris Wesslowski */
/* $Id: whois.h,v 1.14 2010/10/11 12:17:44 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry * whois(struct in_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
