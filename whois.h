/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: whois.h,v 1.13 2004/04/25 18:56:23 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry * whois(struct in_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
