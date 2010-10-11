/* Copyright (C) 2000-2010 Boris Wesslowski */
/* $Id: compare.h,v 1.31 2010/10/11 12:28:33 bwess Exp $ */

#ifndef _COMPARE_H
#define _COMPARE_H

#include "main.h"

struct conn_data *fwlw_pc_mergesort(struct conn_data *list1);
void sort_data(unsigned char mode);
void build_list(void);
int list_stats(void);
void show_list(FILE * fd);

#endif
