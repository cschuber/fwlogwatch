/* $Id: parser.h,v 1.21 2002/02/24 14:27:30 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
