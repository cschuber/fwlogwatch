/* $Id: parser.c,v 1.8 2002/02/14 20:48:49 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "parser.h"
#include "compare.h"
#include "utils.h"
#include "ipchains.h"
#include "netfilter.h"
#include "cisco.h"

extern struct options opt;

unsigned char parse_line(char *input, int linenum)
{
  unsigned char retval;

  if (strstr(input, " kernel: Packet log: ")) {
    retval = flex_ipchains(input, linenum);
    /* For ipchains log format see */
    /* /usr/src/linux-2.2.18/net/ipv4/ip_fw.c */
  } else if (strstr(input, "IN=")) {
    retval = flex_netfilter(input, linenum);
    /* For iptables/netfilter log format see */
    /* /usr/src/linux-2.4.0-test12/net/ipv4/netfilter/ipt_LOG.c */
  } else if (strstr(input, "%SEC-6-IPACCESSLOG")) {
    /* For cisco log format see cisco online documentation */
    retval = flex_cisco(input, linenum);
  } else {
    if (opt.verbose == 2)
      fprintf(stderr, "_");
    return PARSE_NO_HIT;
  }

  if (retval == PARSE_OK) {
    if(opt.recent != 0) {
      if((opt.now - opt.line->time) > opt.recent) {
	if(opt.verbose == 2) {
	  fprintf(stderr, "o");
	}
	return PARSE_TOO_OLD;
      }
    }
    build_list();
    if (opt.verbose == 2)
      fprintf(stderr, ".");
  }
  return retval;
}

unsigned char get_times(FILE *fd, char *begin, char *end)
{
  char buf[BUFSIZE], month[3];
  int retval, day, hour, minute, second;
  struct stat info;

  rewind(fd);
  fgets(buf, BUFSIZE, fd);
  retval = sscanf(buf, "%3s %2d %2d:%2d:%2d ", month, &day, &hour, &minute, &second);
  if (retval != 5) {
    return PARSE_WRONG_FORMAT;
  }
  snprintf(begin, TIMESIZE, "%s %02d %02d:%02d:%02d", month, day, hour, minute, second);

  retval = fstat(fileno(fd), &info);
  if (retval == -1) {
    perror("fstat");
    return PARSE_ERROR;
  }

  if (info.st_size > 2048) {
    retval = fseek(fd, -1024, SEEK_END);
    if (retval == -1) {
      perror("fseek");
      return PARSE_ERROR;
    }
  }

  while(fgets(buf, BUFSIZE, fd))
    retval = sscanf(buf, "%3s %2d %2d:%2d:%2d ", month, &day, &hour, &minute, &second);

  if (retval != 5) {
    return PARSE_WRONG_FORMAT;
  }

  snprintf(end, TIMESIZE, "%s %02d %02d:%02d:%02d", month, day, hour, minute, second);

  return PARSE_OK;
}

int parse_time(char *input)
{
  char *string, *pnt, c;
  int seconds;

  string = strdup(input);
  pnt = string;
  while (isdigit((int)*pnt)) {
    pnt++;
  }
  c = *pnt;
  if (c != '\0') {
    *pnt = '\0';
    seconds = atoi(string);
    switch(c) {
    case 'm':
     seconds = seconds * 60;
      break;
    case 'h':
      seconds = seconds * 60 * 60;
      break;
    case 'd':
      seconds = seconds * 60 * 60 * 24;
      break;
    case 'w':
      seconds = seconds * 60 * 60 * 24 * 7;
      break;
    case 'M':
      seconds = seconds * 60 * 60 * 24 * 31;
      break;
    case 'y':
      seconds = seconds * 60 * 60 * 24 * 31 * 12;
      break;
    }
  } else {
    seconds = atoi(string);
  }

  free(string);
  return seconds;
}
