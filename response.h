/* $Id: response.h,v 1.11 2002/02/14 21:04:28 bwess Exp $ */

#ifndef _RESPONSE_H
#define _RESPONSE_H

#define IP_FW_F_PRN     0x0001 /* from <linux/ip_fw.h>,
				  gcc segfaults if included */

void look_for_log_rules();
void show_mode_opts(char *buf);
void modify_firewall(unsigned char action);
void remove_old();
void look_for_alert();

#endif
