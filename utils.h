/* $Id: utils.h,v 1.6 2002/02/14 20:42:15 bwess Exp $ */

#ifndef _UTILS_H
#define _UTILS_H

void *xmalloc(int size);
void log_exit();
void run_command(char *buf);
void free_conn_data();
void free_dns_cache();
void free_hosts();
void init_line();

#endif
