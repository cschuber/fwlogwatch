/* $Id: compare.h,v 1.25 2002/08/20 21:17:44 bwess Exp $ */

#ifndef _COMPARE_H
#define _COMPARE_H

#include "main.h"

struct conn_data *fwlw_mergesort(struct conn_data *list1);
void sort_data(void);
void build_list(void);
int list_stats(void);
void show_list(FILE *fd);

#endif
