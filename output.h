/* $Id: output.h,v 1.26 2003/03/22 23:16:49 bwess Exp $ */

#ifndef _OUTPUT_H
#define _OUTPUT_H

#include "main.h"

void output_timediff(time_t start, time_t end, char *td);
void output_tcp_opts(struct conn_data *input, char *buf);
void output_html(struct conn_data *input, FILE *fd);
void output_plain(struct conn_data *input, FILE *fd);
void output_html_header(FILE *fd);
void output_html_table(FILE *fd);
void output_html_footer(FILE *fd);
void output_raw_data(struct conn_data *input);

#endif
