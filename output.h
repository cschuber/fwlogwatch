/* Copyright (C) 2000-2011 Boris Wesslowski */
/* $Id: output.h,v 1.32 2011/11/14 12:53:52 bwess Exp $ */

#ifndef _OUTPUT_H
#define _OUTPUT_H

#include "main.h"

void output_timediff(time_t start, time_t end, char *td);
void output_tcp_opts(struct conn_data *input, char *buf);
void output_html_entry(struct conn_data *input, FILE * fd);
void output_text_entry(struct conn_data *input, FILE * fd);
void output_html_table(FILE * fd);
void output_html_header(int fd);
void output_html_footer(int fd);
void output_raw_data(struct conn_data *input);

#endif
