/* $Id: parser.c,v 1.7 2002/02/14 20:45:42 bwess Exp $ */

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
#include "netfilter.h"
#include "cisco.h"

extern struct options opt;

unsigned char ipchains(char *input, int linenum)
{
  int retval;
  char smonth[3];
  int month = 0, day, hour, minute, second;
  struct tm *t;
  int shost1, shost2, shost3, shost4;
  int dhost1, dhost2, dhost3, dhost4;
  int length, id, ttl, count;
  unsigned int tos, offset;

  if (strstr(input, "SYN")) {
    retval = sscanf(input,
		    "%3s %2d %2d:%2d:%2d %32s kernel: Packet log: "
		    "%10s %10s %10s "
		    "PROTO=%3d "
		    "%3d.%3d.%3d.%3d:%5d "
		    "%3d.%3d.%3d.%3d:%5d "
		    "L=%4d S=%4x I=%5d F=%6x T=%3d SYN (#%5d)\n",
		    smonth, &day, &hour, &minute, &second, opt.line->hostname,
		    opt.line->chainlabel, opt.line->branchname, opt.line->interface,
		    &opt.line->protocol,
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport,
		    &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport,
		    &length, &tos, &id, &offset, &ttl, &count);
    opt.line->syn = 1;
  } else {
    retval = sscanf(input,
		    "%3s %2d %2d:%2d:%2d %32s kernel: Packet log: "
		    "%10s %10s %10s "
		    "PROTO=%3d "
		    "%3d.%3d.%3d.%3d:%5d "
		    "%3d.%3d.%3d.%3d:%5d "
		    "L=%4d S=%4x I=%5d F=%6x T=%3d (#%5d)\n",
		    smonth, &day, &hour, &minute, &second, opt.line->hostname,
		    opt.line->chainlabel, opt.line->branchname, opt.line->interface,
		    &opt.line->protocol,
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport,
		    &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport,
		    &length, &tos, &id, &offset, &ttl, &count);
    opt.line->syn = 0;
  }
  if (retval != 26) {
    if (opt.verbose) {
      if(linenum != 0) {
	fprintf(stderr, "ipchains format mismatch in line %d: %d of 26 args, ignoring.\n", linenum, retval);
      } else {
	fprintf(stderr, "ipchains format mismatch: %d of 26 args, ignoring.\n", retval);
      }
    }
    return PARSE_WRONG_FORMAT;
  }

  t = localtime(&opt.now);
  if (strncmp(smonth, "Jan", 3) == 0) { month = 0; }
  if (strncmp(smonth, "Feb", 3) == 0) { month = 1; }
  if (strncmp(smonth, "Mar", 3) == 0) { month = 2; }
  if (strncmp(smonth, "Apr", 3) == 0) { month = 3; }
  if (strncmp(smonth, "May", 3) == 0) { month = 4; }
  if (strncmp(smonth, "Jun", 3) == 0) { month = 5; }
  if (strncmp(smonth, "Jul", 3) == 0) { month = 6; }
  if (strncmp(smonth, "Aug", 3) == 0) { month = 7; }
  if (strncmp(smonth, "Sep", 3) == 0) { month = 8; }
  if (strncmp(smonth, "Oct", 3) == 0) { month = 9; }
  if (strncmp(smonth, "Nov", 3) == 0) { month = 10; }
  if (strncmp(smonth, "Dec", 3) == 0) { month = 11; }
  t->tm_mon = month;
  t->tm_mday = day;
  t->tm_hour = hour;
  t->tm_min = minute;
  t->tm_sec = second;
  t->tm_isdst = -1;
  opt.line->time = mktime(t);

  snprintf(opt.line->shost, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);

  snprintf(opt.line->dhost, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);

  opt.line->count = 1;

  return PARSE_OK;
}

unsigned char parse_line(char *input, int linenum)
{
  unsigned char retval;

  if (strstr(input, " kernel: Packet log: ")) {
    retval = ipchains(input, linenum);
    /* For ipchains log format see */
    /* /usr/src/linux-2.2.17/net/ipv4/ip_fw.c */
  } else if (strstr(input, "IN=")) {
    retval = flex_netfilter(input, linenum);
    /* For iptables/netfilter log format see */
    /* /usr/src/linux-2.4.0-test10/net/ipv4/netfilter/ipt_LOG.c */
  } else if (strstr(input, "%SEC-6-IPACCESSLOG")) {
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
