/* $Id: lancom.c,v 1.4 2003/06/23 15:26:53 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

unsigned char lancom(char *input, int linenum)
{
  char *sinputs=input, *sinpute;
  int retval, day, hour, minute, second;
  char smonth[3];

  init_line();
  xstrncpy(opt.line->interface, "-", SHORTLEN);

  /* Read time */
  sinpute = sinputs+15;
  *sinpute = '\0';
  retval = sscanf(sinputs, "%3s %2d %2d:%2d:%2d", smonth, &day, &hour, &minute, &second);
  build_time(smonth, day, hour, minute, second);

  /* Read loghost */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ' ');
  *sinpute = '\0';
  xstrncpy(opt.line->hostname, sinputs, sinpute - sinputs + 1);

  /* Read chainlabel */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ' ');
  *sinpute = '\0';
  xstrncpy(opt.line->chainlabel, sinputs, sinpute - sinputs);

  /* Skip "Dst:" */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ':');
  sinpute++;

  /* Read dest IP */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ':');
  *sinpute = '\0';
  if(convert_ip(sinputs, &opt.line->dhost) == IN_ADDR_ERROR) {
    if(opt.verbose)
      fprintf(stderr, "lancom parse error while reading dhost in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read dest port */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ' ');
  retval = sscanf(sinputs, "%5d", &opt.line->dport);
  if (retval == 0) {
    if(opt.verbose)
      fprintf(stderr, "lancom parse error while reading dport in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Skip the "Src:" */
  sinputs = sinpute;
  sinpute = strchr(sinputs, ':');
  sinpute++;

  /* Read source IP */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ':');
  *sinpute = '\0';
  if(convert_ip(sinputs, &opt.line->shost) == IN_ADDR_ERROR) {
    if(opt.verbose)
      fprintf(stderr, "lancom parse error while reading shost in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read source port */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ' ');
  *sinpute = '\0';
  retval = sscanf(sinputs, "%5d", &opt.line->sport);
  if (retval == 0) {
    if(opt.verbose)
      fprintf(stderr, "lancom parse error while reading sport in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read protocol */
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, '(');
  if (sinpute == NULL) {
    if(opt.verbose)
      fprintf(stderr, "lancom parse error while looking for protocol in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, ')');
  *sinpute = '\0';
  if(strncmp(sinputs, "TCP", 3) == 0) opt.line->protocol = 6;
  else if(strncmp(sinputs, "UDP", 3) == 0) opt.line->protocol = 17;
  else {
    if(opt.verbose)
      fprintf(stderr, "lancom parse error while reading proto in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }

  /* Read branch name */
  sinpute++;
  sinpute++;
  sinpute++;
  sinputs = sinpute;
  sinpute = strchr(sinputs, '\0');
  xstrncpy(opt.line->branchname, sinputs, sinpute - sinputs);

  /* Set rest */
  opt.line->flags = 0;
  opt.line->count = 1;
  return PARSE_OK;
}
