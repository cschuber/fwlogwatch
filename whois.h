/* $Id: whois.h,v 1.3 2002/02/14 21:48:38 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry * whois(struct in_addr ip);
void whois_connect(const char *whois_server);
void whois_close();

#endif
