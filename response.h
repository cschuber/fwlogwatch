/* $Id: response.h,v 1.22 2002/03/29 11:25:52 bwess Exp $ */

#ifndef _RESPONSE_H
#define _RESPONSE_H

#define IP_FW_F_PRN     0x0001 /* from <linux/ip_fw.h>,
				  gcc segfaults if included */

void check_for_ipchains(void);
void check_script_perms(char *name);
void modify_firewall(unsigned char action);
void remove_old(void);
void look_for_alert(void);

#endif
