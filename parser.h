/* $Id: parser.h,v 1.22 2002/03/29 11:25:52 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
