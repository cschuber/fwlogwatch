/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: utils.h,v 1.29 2004/04/25 18:56:22 bwess Exp $ */

#ifndef _UTILS_H
#define _UTILS_H

char *xstrncpy(char *dest, const char *src, size_t n);
void *xmalloc(int size);
void log_exit(unsigned char returncode);
void run_command(char *buf);
void free_conn_data(void);
void free_dns_cache(void);
void free_whois(void);
void free_hosts(void);
void free_exclude_data(void);
void init_line(void);
void mode_error(void);
void build_time(char *smonth, int day, int hour, int minute, int second);
unsigned char convert_ip(char *ip, struct in_addr *addr);
unsigned long int parse_cidr(char *input);
void add_known_host(char *ip);
void add_exclude_hpb(char *input, unsigned char mode);
void add_input_file(char *name);
void free_input_file(void);
void generate_email_header(FILE *fd);
void fdprintf(int fd, char *format, ...);

#endif
