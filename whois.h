/* $Id: whois.h,v 1.7 2002/05/08 17:24:09 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry * whois(struct in_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
