/* Copyright (C) 2000-2011 Boris Wesslowski */
/* $Id: parser.h,v 1.32 2011/11/14 12:53:52 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
