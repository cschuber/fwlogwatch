/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: compare.h,v 1.29 2004/04/25 18:56:19 bwess Exp $ */

#ifndef _COMPARE_H
#define _COMPARE_H

#include "main.h"

struct conn_data *fwlw_mergesort(struct conn_data *list1);
void sort_data(void);
void build_list(void);
int list_stats(void);
void show_list(FILE *fd);

#endif
