/* $Id: utils.h,v 1.20 2002/02/14 21:55:19 bwess Exp $ */

#ifndef _UTILS_H
#define _UTILS_H

char *xstrncpy(char *dest, const char *src, size_t n);
void *xmalloc(int size);
void log_exit(unsigned char returncode);
void run_command(char *buf);
void free_conn_data();
void free_dns_cache();
void free_hosts();
void free_exclude_data();
void init_line();
void mode_error();
void build_time(char *smonth, int day, int hour, int minute, int second);
unsigned char convert_ip(char *ip, struct in_addr *addr);
unsigned long int parse_cidr(char *input);
void add_known_host(char *ip);
void add_exclude_hp(char *input, unsigned char mode);

#endif
