/* Copyright (C) 2000-2006 Boris Wesslowski */
/* $Id: parser.h,v 1.30 2010/10/11 12:17:44 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
