/* $Id: whois.h,v 1.6 2002/03/29 11:25:52 bwess Exp $ */

#ifndef _WHOIS_H
#define _WHOIS_H

struct whois_entry * whois(struct in_addr ip);
void whois_connect(const char *whois_server);
void whois_close(void);

#endif
