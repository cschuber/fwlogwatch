/* $Id: output.h,v 1.7 2002/02/14 20:45:42 bwess Exp $ */

#ifndef _OUTPUT_H
#define _OUTPUT_H

#include "main.h"

void output_timediff(time_t start, time_t end, char *td);
void output_resolved(struct conn_data *input);
void output_html_header();
void output_html_table();
void output_html_footer();

#endif
