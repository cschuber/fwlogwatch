/* $Id: parser.h,v 1.27 2003/04/08 21:42:45 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
