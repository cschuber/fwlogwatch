/* $Id: utils.h,v 1.9 2002/02/14 20:54:34 bwess Exp $ */

#ifndef _UTILS_H
#define _UTILS_H

void *xmalloc(int size);
void log_exit();
void run_command(char *buf);
void free_conn_data();
void free_dns_cache();
void free_hosts();
void init_line();
void mode_error();
void build_time(char *smonth, int day, int hour, int minute, int second);
unsigned char convert_ip(char *ip, struct in_addr *addr);

#endif
