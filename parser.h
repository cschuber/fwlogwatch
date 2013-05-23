/* Copyright (C) 2000-2013 Boris Wesslowski */
/* $Id: parser.h,v 1.33 2013/05/23 15:04:15 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
