/* $Id: parser.h,v 1.20 2002/02/14 21:55:19 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers();

#endif
