/* $Id: utils.h,v 1.2 2002/02/14 20:09:16 bwess Exp $ */

#ifndef _UTILS_H
#define _UTILS_H

void *xmalloc(int size);
void log_exit();
void run_command(char *buf);
void free_conn_data();
void free_dns_cache();
void free_hosts();

#endif
