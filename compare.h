/* $Id: compare.h,v 1.20 2002/02/14 21:55:19 bwess Exp $ */

#ifndef _COMPARE_H
#define _COMPARE_H

#include "main.h"

struct conn_data *fwlw_mergesort(struct conn_data *list1);
void sort_data();
void build_list();
int list_stats();
void show_list();

#endif
