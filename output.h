/* $Id: output.h,v 1.22 2002/03/29 11:25:52 bwess Exp $ */

#ifndef _OUTPUT_H
#define _OUTPUT_H

#include "main.h"

void output_timediff(time_t start, time_t end, char *td);
void output_tcp_opts(struct conn_data *input, char *buf);
void output_html(struct conn_data *input);
void output_plain(struct conn_data *input);
void output_html_header(void);
void output_html_table(void);
void output_html_footer(void);
void output_raw_data(struct conn_data *input);

#endif
