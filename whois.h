/* Copyright (C) 2000-2010 Boris Wesslowski */
/* $Id: whois.h,v 1.15 2010/10/11 12:28:33 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry *whois(struct in_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
