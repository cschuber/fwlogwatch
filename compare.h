/* Copyright (C) 2000-2011 Boris Wesslowski */
/* $Id: compare.h,v 1.32 2011/11/14 12:53:52 bwess Exp $ */

#ifndef _COMPARE_H
#define _COMPARE_H

#include "main.h"

struct conn_data *fwlw_pc_mergesort(struct conn_data *list1);
void sort_data(unsigned char mode);
void build_list(void);
int list_stats(void);
void show_list(FILE * fd);

#endif
