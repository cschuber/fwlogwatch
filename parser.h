/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: parser.h,v 1.34 2016/02/19 16:09:27 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
