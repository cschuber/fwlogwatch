/* $Id: parser.h,v 1.26 2003/03/22 23:16:49 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
int parse_time(char *input);
void select_parsers(void);

#endif
