/* $Id: parser.c,v 1.13 2002/02/14 21:09:41 bwess Exp $ */

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
#include "cisco.h"
#include "ipchains.h"
#include "ipfilter.h"
#include "netfilter.h"

struct parser_options *excluded_first;
extern struct options opt;

unsigned char parse_line(char *input, int linenum)
{
  unsigned char retval;

  if ((opt.format & PARSER_IPCHAINS) && (strstr(input, " kernel: Packet log: "))) {
    /* For ipchains log format see (in kernel 2.2 source) */
    /* /usr/src/linux/net/ipv4/ip_fw.c */
    retval = flex_ipchains(input, linenum);
  } else if ((opt.format & PARSER_NETFILTER) && (strstr(input, "IN="))) {
    /* For netfilter log format see (in kernel 2.4 source) */
    /* /usr/src/linux/net/ipv4/netfilter/ipt_LOG.c */
    retval = flex_netfilter(input, linenum);
  } else if ((opt.format & PARSER_CISCO) && (strstr(input, "%SEC-6-IPACCESSLOG"))) {
    /* For cisco log format see CCO */
    retval = flex_cisco(input, linenum);
  } else if ((opt.format & PARSER_IPFILTER) && (strstr(input, " ipmon"))) {
    /* For ipfilter log format see the source */
    /* http://coombs.anu.edu.au/~avalon/ */
    retval = flex_ipfilter(input, linenum);
  } else {
    retval = PARSE_NO_HIT;
  }

  if (retval == PARSE_NO_HIT) {
    if (opt.verbose == 2)
      fprintf(stderr, "_");
    return PARSE_NO_HIT;
  }

  if (retval == PARSE_OK) {
    {
      struct parser_options *excluded_this;
      unsigned char match = P_MATCH_NONE;

      excluded_this = excluded_first;
      //while((excluded_this != NULL) && (match != P_MATCH_EXC)) {
      while(excluded_this != NULL) {
	if((excluded_this->mode & PARSER_MODE_HOST) != 0) {
	  /* host */
	  if((excluded_this->mode & PARSER_MODE_SRC) != 0) {
	    /* source */
	    if(opt.line->shost.s_addr == excluded_this->value) {
	      if((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  } else {
	    /* destination */
	    if(opt.line->dhost.s_addr == excluded_this->value) {
	      if((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  }
	} else {
	  /* port */
	  if((excluded_this->mode & PARSER_MODE_SRC) != 0) {
	    /* source */
	    if(opt.line->sport == excluded_this->value) {
	      if((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  } else {
	    /* destination */
	    if(opt.line->dport == excluded_this->value) {
	      if((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  }
	}

	if(((excluded_this->mode & PARSER_MODE_NOT) == 0) &&
	   (match == P_MATCH_NONE)) {
	  match = P_MATCH_EXC;
	}

	excluded_this = excluded_this->next;
      }

      if(match == P_MATCH_EXC) {
	if (opt.verbose == 2)
	  fprintf(stderr, "e");
	return PARSE_EXCLUDED;
      }
    }

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

void select_parsers()
{
  unsigned char i = 0;

  if (opt.format_sel[0] == '\0') {
    return;
  } else {
    opt.format = 0;
    while ((i < SHORTLEN) && (opt.format_sel[i] != '\0')) {
      switch (opt.format_sel[i]) {
      case 'i':
	opt.format = opt.format | PARSER_IPCHAINS;
	break;
      case 'n':
	opt.format = opt.format | PARSER_NETFILTER;
	break;
      case 'c':
	opt.format = opt.format | PARSER_CISCO;  
	break;
      case 'f':
	opt.format = opt.format | PARSER_IPFILTER;  
	break;
      default:
	fprintf(stderr, "Unknown parser: '%c'.\n", opt.format_sel[i]);
	exit(EXIT_FAILURE);
      }
      i++;
    }
  }
}
