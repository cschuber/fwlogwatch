/* $Id: parser.h,v 1.24 2002/05/15 22:24:44 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
