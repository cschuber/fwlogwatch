/* $Id: response.h,v 1.2 2002/02/14 20:09:16 bwess Exp $ */

#ifndef _RESPONSE_H
#define _RESPONSE_H

#define IP_FW_F_PRN     0x0001 /* from <linux/ip_fw.h>,
				  gcc segfaults if included */

void remove_old();
void look_for_log_rules();
void look_for_alert();
void modify_firewall(unsigned char action);

#endif
