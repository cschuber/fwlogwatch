/* $Id: win_xp.c,v 1.6 2003/03/22 23:16:49 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

unsigned char win_xp(char *input, int linenum)
{
  char *sinputs=input, *sinpute;
  int retval, year, day, month, hour, minute, second;
  struct tm *t;

  /* Read file header */
  if(*input=='#' || !isdigit((int)*input))
    return PARSE_NO_HIT;
  init_line();
  xstrncpy(opt.line->hostname, "-", SHORTLEN);
  xstrncpy(opt.line->chainlabel, "-", SHORTLEN);
  xstrncpy(opt.line->interface, "-", SHORTLEN);

  /* Read time */
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  retval = sscanf(sinputs, "%4d-%2d-%2d", &year, &month, &day);
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  retval = sscanf(sinputs, "%2d:%2d:%2d", &hour, &minute, &second);
  t = xmalloc(sizeof(struct tm));
  t->tm_year = year-1900;
  t->tm_mon = month-1;
  t->tm_mday = day;
  t->tm_hour = hour;
  t->tm_min = minute;
  t->tm_sec = second;
  t->tm_isdst = -1;
  opt.line->time = mktime(t);

  /* Read action */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (*sinputs == '-'){
    xstrncpy(opt.line->branchname, "-", SHORTLEN);
  } else {
    xstrncpy(opt.line->branchname, sinputs, SHORTLEN);
  }

  /* Read protocol */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if(strncmp(sinputs, "TCP", 3) == 0) opt.line->protocol = 6;
  else if(strncmp(sinputs, "UDP", 3) == 0) opt.line->protocol = 17;
  else if(strncmp(sinputs, "ICMP", 4) == 0) opt.line->protocol = 1;
  else {
    if(opt.verbose)
      fprintf(stderr, "win_xp parse error while reading proto in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read src ip */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (*sinputs != '-'){
    if(convert_ip(sinputs, &opt.line->shost) == IN_ADDR_ERROR) return PARSE_NO_HIT;
  } else {
    if(opt.verbose)
      fprintf(stderr, "win_xp parse error while reading shost in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read dst ip */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (*sinputs != '-'){
    if(convert_ip(sinputs, &opt.line->dhost) == IN_ADDR_ERROR) return PARSE_NO_HIT;
  } else {
    if(opt.verbose)
      fprintf(stderr, "win_xp parse error while reading dhost in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read src port */
  sinpute=sinpute+1;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (isdigit((int)*sinputs)){
    opt.line->sport=atoi(sinputs);
  } else if (*sinputs == '-' && (opt.line->protocol == 6 || opt.line->protocol == 17)) {
    if(opt.verbose)
      fprintf(stderr, "win_xp parse error while reading sport in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read dst port */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (isdigit((int)*sinputs)){
    opt.line->dport=atoi(sinputs);
  } else if (*sinputs == '-' && (opt.line->protocol == 6 || opt.line->protocol == 17)) {
    if(opt.verbose)
      fprintf(stderr, "win_xp parse error while reading dport in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read size */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (isdigit((int)*sinputs)){
    opt.line->datalen=atoi(sinputs);
  } else {
    opt.line->datalen=0;
  }

  /* Read tcp flags */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  while (*sinputs != '\0') {
    switch (*sinputs) {
    case '-':
      opt.line->flags = 0;
      break;
    case 'S':
      opt.line->flags = opt.line->flags | TCP_SYN;
      break;
    case 'A':
      opt.line->flags = opt.line->flags | TCP_ACK;
      break;
    case 'F':
      opt.line->flags = opt.line->flags | TCP_FIN;
      break;
    case 'P':
      opt.line->flags = opt.line->flags | TCP_PSH;
      break;
    default:
      if(opt.verbose)
	fprintf(stderr, "win_xp parse error in line %d, ignoring.\n", linenum);
      return PARSE_WRONG_FORMAT;
    }
    sinputs++;
  }

  /* Read tcpsyn tcpack and tcpwin, not used */
  sinpute++;
  sinpute = strchr(sinpute, ' ');
  sinpute++;
  sinpute = strchr(sinpute, ' ');
  sinpute++;
  sinpute = strchr(sinpute, ' ');

  /* Read icmp type */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (isdigit((int)*sinputs)){
    opt.line->sport=atoi(sinputs);
  }

  /* Read icmp code */
  sinpute++;
  sinputs=sinpute;
  sinpute = strchr(sinputs, ' ');
  if (sinpute != NULL)
    *sinpute = '\0';
  if (isdigit((int)*sinputs)){
    opt.line->dport=atoi(sinputs);
  }

  /* Ignore info at end of line */

  opt.line->count = 1;
  return PARSE_OK;
}
