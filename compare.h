/* $Id: compare.h,v 1.2 2002/02/14 20:09:16 bwess Exp $ */

#ifndef _COMPARE_H
#define _COMPARE_H

#include "main.h"

void build_list(struct log_line *input);
void sort_list(int field, char mode);
int list_stats();
void show_list();

#endif
