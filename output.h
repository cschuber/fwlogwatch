/* $Id: output.h,v 1.28 2003/06/23 15:26:53 bwess Exp $ */

#ifndef _OUTPUT_H
#define _OUTPUT_H

#include "main.h"

void output_timediff(time_t start, time_t end, char *td);
void output_tcp_opts(struct conn_data *input, char *buf);
void output_html_entry(struct conn_data *input, FILE *fd);
void output_text_entry(struct conn_data *input, FILE *fd);
void output_html_table(FILE *fd);
void output_html_header(int fd);
void output_html_footer(int fd);
void output_raw_data(struct conn_data *input);

#endif
