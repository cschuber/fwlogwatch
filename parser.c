/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: parser.c,v 1.34 2016/02/19 16:09:27 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "cisco_ios.h"
#include "cisco_pix.h"
#include "compare.h"
#include "ipchains.h"
#include "ipfilter.h"
#include "ipfw.h"
#include "lancom.h"
#include "netfilter.h"
#include "netscreen.h"
#include "snort.h"
#include "utils.h"

struct parser_options *excluded_first;
extern struct options opt;

unsigned char parse_line(char *input, int linenum)
{
  unsigned char retval;
  char *pnt;

  pnt = strstr(input, " last message repeated ");
  if (pnt != NULL) {
    if (opt.repeated == 1) {
      char month[4], time[9], name[SHOSTLEN], rest[BUFSIZE];
      unsigned int day;
      if (sscanf(input, "%3s %u %8s %" SHOSTLEN_S "s %" BUFSIZE_S "s", month, &day, time, name, rest) == 5) {
	if (strncmp(opt.line->hostname, name, SHOSTLEN) == 0) {
	  opt.line->count = opt.orig_count * atoi(pnt + 23);
	  build_list();
	  if (opt.verbose == 2)
	    fprintf(stderr, "r");
	  return PARSE_OK;
	}
      }
      if (opt.verbose == 2)
	fprintf(stderr, "_");
      return PARSE_NO_HIT;
    }
  }

  if ((opt.format & PARSER_IPCHAINS) && (strstr(input, " kernel: Packet log: "))) {
    /* For ipchains log format see (in kernel 2.2 source) */
    /* /usr/src/linux/net/ipv4/ip_fw.c */
    retval = flex_ipchains(input, linenum);
  } else if ((opt.format & PARSER_NETFILTER) && (strstr(input, " OUT="))) {
    /* For netfilter log format see (in kernel 2.4 source) */
    /* /usr/src/linux/net/ipv4/netfilter/ipt_LOG.c */
    retval = flex_netfilter(input, linenum);
  } else if ((opt.format & PARSER_CISCO_IOS) && (strstr(input, "%SEC-6-IPACCESSLOG"))) {
    /* For cisco log format see CCO */
    retval = flex_cisco_ios(input, linenum);
  } else if ((opt.format & PARSER_IPFILTER) && (strstr(input, " ipmon"))) {
    /* For ipfilter log format see the source */
    /* http://coombs.anu.edu.au/~avalon/ */
    retval = flex_ipfilter(input, linenum);
  } else if ((opt.format & PARSER_IPFW) && (strstr(input, " ipfw: "))) {
    retval = flex_ipfw(input, linenum);
  } else if ((opt.format & PARSER_CISCO_PIX) && (strstr(input, "%PIX-") || strstr(input, "%FWSM-") || strstr(input, "%ASA-"))) {
    /* For cisco log format see CCO */
    retval = flex_cisco_pix(input, linenum);
  } else if ((opt.format & PARSER_NETSCREEN) && (strstr(input, " NetScreen "))) {
    retval = flex_netscreen(input, linenum);
  } else if ((opt.format & PARSER_LANCOM) && (strstr(input, " PACKET_ALERT: "))) {
    retval = lancom(input, linenum);
  } else if ((opt.format & PARSER_SNORT) && (strstr(input, " snort"))) {
    retval = flex_snort(input, linenum);
  } else {
    retval = PARSE_NO_HIT;
  }

  if (retval == PARSE_NO_HIT) {
    if (opt.verbose == 2)
      fprintf(stderr, "_");
    return PARSE_NO_HIT;
  }

  if (opt.recent != 0) {
    if ((opt.now - opt.line->time) > opt.recent) {
      if (opt.verbose == 2) {
	fprintf(stderr, "o");
      }
      return PARSE_TOO_OLD;
    }
  }

  if (retval == PARSE_OK) {
    {
      struct parser_options *excluded_this;
      unsigned char match = P_MATCH_NONE, include_rules_exist = 0;

      excluded_this = excluded_first;
      while (excluded_this != NULL) {
	if ((match != P_MATCH_EXC) && (excluded_this->mode & PARSER_MODE_HOST) != 0) {
	  struct in6_addr testhost;
	  int i;
	  if ((excluded_this->mode & PARSER_MODE_SRC) != 0) {
	    for (i = 0; i < 16; i++)
	      testhost.s6_addr[i] = opt.line->shost.s6_addr[i] & excluded_this->netmask.s6_addr[i];
	    if (compare_ipv6_equal(&testhost, &excluded_this->host) == 0) {
	      if ((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  } else {
	    for (i = 0; i < 16; i++)
	      testhost.s6_addr[i] = opt.line->dhost.s6_addr[i] & excluded_this->netmask.s6_addr[i];
	    if (compare_ipv6_equal(&testhost, &excluded_this->host) == 0) {
	      if ((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  }
	}
	if ((match != P_MATCH_EXC) && (excluded_this->mode & PARSER_MODE_PORT) != 0) {
	  if ((excluded_this->mode & PARSER_MODE_SRC) != 0) {
	    if ((unsigned long int) opt.line->sport == excluded_this->value) {
	      if ((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  } else {
	    if ((unsigned long int) opt.line->dport == excluded_this->value) {
	      if ((excluded_this->mode & PARSER_MODE_NOT) != 0) {
		match = P_MATCH_EXC;
	      } else {
		match = P_MATCH_INC;
	      }
	    }
	  }
	}
	if ((match != P_MATCH_EXC) && (excluded_this->mode & PARSER_MODE_CHAIN) != 0) {
	  if (strcmp(opt.line->chainlabel, excluded_this->svalue) == 0) {
	    if ((excluded_this->mode & PARSER_MODE_NOT) != 0) {
	      match = P_MATCH_EXC;
	    } else {
	      match = P_MATCH_INC;
	    }
	  }
	}
	if ((match != P_MATCH_EXC) && (excluded_this->mode & PARSER_MODE_BRANCH) != 0) {
	  if (strcmp(opt.line->branchname, excluded_this->svalue) == 0) {
	    if ((excluded_this->mode & PARSER_MODE_NOT) != 0) {
	      match = P_MATCH_EXC;
	    } else {
	      match = P_MATCH_INC;
	    }
	  }
	}

	if ((include_rules_exist == 0) && (excluded_this->mode & PARSER_MODE_NOT) == 0)
	  include_rules_exist++;

	excluded_this = excluded_this->next;
      }

      if ((match == P_MATCH_NONE) && (include_rules_exist))
	match = P_MATCH_EXC;

      if (match == P_MATCH_EXC) {
	if (opt.verbose == 2)
	  fprintf(stderr, "e");
	return PARSE_EXCLUDED;
      }
    }

    opt.orig_count = opt.line->count;
    build_list();
    if (opt.verbose == 2)
      fprintf(stderr, ".");
  }
  return retval;
}

int parse_time(char *input)
{
  char *string, *pnt, c;
  int seconds;

  string = strdup(input);
  pnt = string;
  while (isdigit((int) *pnt)) {
    pnt++;
  }
  c = *pnt;
  if (c != '\0') {
    *pnt = '\0';
    seconds = atoi(string);
    switch (c) {
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
      seconds = seconds * 60 * 60 * 24 * 30;
      break;
    case 'y':
      seconds = seconds * 60 * 60 * 24 * 365;
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
      case 'f':
	opt.format = opt.format | PARSER_IPFILTER;
	break;
      case 'c':
	opt.format = opt.format | PARSER_CISCO_IOS;
	break;
      case 'p':
	opt.format = opt.format | PARSER_CISCO_PIX;
	break;
      case 'e':
	opt.format = opt.format | PARSER_NETSCREEN;
	break;
      case 'l':
	opt.format = opt.format | PARSER_LANCOM;
	break;
      case 's':
	opt.format = opt.format | PARSER_SNORT;
	break;
      case 'b':
	opt.format = opt.format | PARSER_IPFW;
	break;
      default:
	fprintf(stderr, _("Unknown parser: '%c'.\n"), opt.format_sel[i]);
	exit(EXIT_FAILURE);
      }
      i++;
    }
  }
}
