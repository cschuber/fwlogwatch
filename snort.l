/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: snort.l,v 1.12 2016/02/19 16:09:27 bwess Exp $ */

%option prefix="snort"
%option outfile="snort.c"
%option noyywrap

%{
#define YY_NO_INPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void snort_parse_date(char *input);
void snort_parse_branch(char *input);
void snort_parse_ip(char *input, unsigned char mode);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z0-9._-]*
STRING2	[ -Z\\^-~]*
STRING3	[a-zA-Z(][ a-zA-Z0-9()/._-]*[a-zA-Z)]
LOGHOST	[0-9.a-zA-Z()_:-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
PROTO	"TCP"|"UDP"|"ICMP"

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	snort_parse_date(snorttext);
"snort: "									/* ignore */
"snort["{NUMBER}"]: "								/* ignore */
"["{NUMBER}":"{NUMBER}":"{DIGIT}"]"						/* ignore */
{STRING3}									xstrncpy(opt.line->chainlabel, snorttext, SHORTLEN); opt.parser=opt.parser|SNORT_CHAIN;
"[Classification: "{STRING2}"]"							snort_parse_branch(snorttext+17);
"[Priority: "{DIGIT}"]:"							/* ignore */
"{"{PROTO}"}"[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}				snort_parse_ip(snorttext+1, SNORT_OPT_SRC);
"{"{PROTO}"}"[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}":"{PORT}			snort_parse_ip(snorttext+1, SNORT_OPT_SRC|SNORT_OPT_PORT);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}					snort_parse_ip(snorttext, SNORT_OPT_DST);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}":"{PORT}				snort_parse_ip(snorttext, SNORT_OPT_DST|SNORT_OPT_PORT);
"spp_portscan: ".*								opt.parser=SNORT_NO_HIT;
"spp_stream4: ".*								opt.parser=SNORT_NO_HIT;
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", snorttext);
.		if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", snorttext);

%%

void snort_parse_date(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[4];

  retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s", smonth, &day, &hour, &minute, &second, opt.line->hostname);
  if (retval != 6)
    return;

  build_time(smonth, day, hour, minute, second);

  opt.parser = opt.parser | SNORT_DATE;
}

void snort_parse_branch(char *input)
{
  char *ptr;

  ptr = strchr(input, ']');
  *ptr = '\0';
  xstrncpy(opt.line->branchname, input, SHORTLEN);
  opt.parser = opt.parser | SNORT_BRANCH;
}

void snort_parse_ip(char *input, unsigned char mode)
{
  char ip[IPLEN];
  int retval, host1, host2, host3, host4;

  if ((mode & SNORT_OPT_SRC) != 0) {
    char proto[8];
    if ((mode & SNORT_OPT_PORT) != 0) {
      retval = sscanf(input, "%8s %3d.%3d.%3d.%3d:%5d", proto, &host1, &host2, &host3, &host4, &opt.line->sport);
      if (retval != 6)
	return;
    } else {
      retval = sscanf(input, "%8s %3d.%3d.%3d.%3d", proto, &host1, &host2, &host3, &host4);
      if (retval != 5)
	return;
    }

    if (strncmp(proto, "TCP", 3) == 0)
      opt.line->protocol = 6;
    else if (strncmp(proto, "UDP", 3) == 0)
      opt.line->protocol = 17;
    else if (strncmp(proto, "ICMP", 4) == 0)
      opt.line->protocol = 1;

    if (opt.line->protocol != 0)
      opt.parser = opt.parser | SNORT_PROTO;
  } else if ((mode & SNORT_OPT_DST) != 0) {
    if ((mode & SNORT_OPT_PORT) != 0) {
      retval = sscanf(input, "-> %3d.%3d.%3d.%3d:%5d", &host1, &host2, &host3, &host4, &opt.line->sport);
      if (retval != 5)
	return;
    } else {
      retval = sscanf(input, "-> %3d.%3d.%3d.%3d", &host1, &host2, &host3, &host4);
      if (retval != 4)
	return;
    }
  } else {
    return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", host1, host2, host3, host4);

  if ((mode & SNORT_OPT_SRC) != 0) {
    if (convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR)
      return;
    opt.parser = opt.parser | SNORT_SRC;
  } else if ((mode & SNORT_OPT_DST) != 0) {
    if (convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR)
      return;
    opt.parser = opt.parser | SNORT_DST;
  }
}

unsigned char flex_snort(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  snort_scan_string(input);
  snortlex();
  snort_delete_buffer(YY_CURRENT_BUFFER);

  xstrncpy(opt.line->interface, "-", SHORTLEN);
  opt.line->count = 1;

  if (opt.parser & SNORT_NO_HIT)
    return PARSE_NO_HIT;

  if (opt.parser == (SNORT_DATE | SNORT_CHAIN | SNORT_BRANCH | SNORT_PROTO | SNORT_SRC | SNORT_DST)) {
    return PARSE_OK;
  } else {
    if (opt.verbose)
      fprintf(stderr, "snort parse error in line %d, ignoring.\n", linenum);
    if (opt.verbose == 2)
      fprintf(stderr, "input was: \"%s\"\n", input);
    return PARSE_WRONG_FORMAT;
  }
}
