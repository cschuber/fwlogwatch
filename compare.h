/* $Id: compare.h,v 1.1 2002/02/14 19:43:03 bwess Exp $ */

#ifndef _COMPARE_H
#define _COMPARE_H

#include "main.h"

void build_list(struct log_line *input);
void sort_list(int field, char mode);
int list_stats();
void show_list();

#endif
