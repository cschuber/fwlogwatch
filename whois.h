/* $Id: whois.h,v 1.11 2003/04/08 21:43:04 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry * whois(struct in_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
