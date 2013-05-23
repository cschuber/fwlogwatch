/* Copyright (C) 2000-2013 Boris Wesslowski */
/* $Id: response.h,v 1.33 2013/05/23 15:04:15 bwess Exp $ */

#ifndef _RESPONSE_H
#define _RESPONSE_H

#define IP_FW_F_PRN     0x0001	/* from <linux/ip_fw.h>,
				   gcc segfaults if included */

void check_for_ipchains(void);
void check_script_perms(char *name);
void modify_firewall(unsigned char action);
void remove_old(unsigned char mode);
void look_for_alert(void);
struct known_hosts *fwlw_hs_mergesort(struct known_hosts *list);

#endif
