/* $Id: parser.h,v 1.7 2002/02/14 20:45:42 bwess Exp $ */

#ifndef _PARSER_H
#define _PARSER_H

unsigned char parse_line(char *input, int linenum);
unsigned char get_times(FILE *fd, char *begin, char *end);
int parse_time(char *input);

#endif
