/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: parser.h,v 1.29 2004/04/25 18:56:22 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
