/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: ipfw.l,v 1.1 2004/04/25 18:56:21 bwess Exp $ */

%option prefix="ipfw"
%option outfile="ipfw.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void ipfw_parse_start(char *input);
void ipfw_parse_proto(char *input, unsigned char mode);
void ipfw_parse_ips(char *input, unsigned char mode);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9.-]*
LOGHOST	[0-9.a-zA-Z()_:-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
PROTO	"TCP"|"UDP"

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	ipfw_parse_start(ipfwtext);
" kernel: ipfw: "{NUMBER}	{ xstrncpy(opt.line->chainlabel, ipfwtext+15, SHORTLEN); opt.parser=opt.parser|IPFW_CHAIN; };
"Deny"				{ xstrncpy(opt.line->branchname, ipfwtext, SHORTLEN); opt.parser=opt.parser|IPFW_BRANCH; };
{PROTO}				ipfw_parse_proto(ipfwtext, IPFW_OPT_NONE);
"ICMP:"{NUMBER}"."{NUMBER}	ipfw_parse_proto(ipfwtext+5, IPFW_OPT_ICMP);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}			ipfw_parse_ips(ipfwtext, IPFW_OPT_NONE);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}":"{PORT}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}":"{PORT}	ipfw_parse_ips(ipfwtext, IPFW_OPT_PORTS);
"in via "{STRING}		{ xstrncpy(opt.line->interface, ipfwtext+7, SHORTLEN); opt.parser=opt.parser|IPFW_IF; }
[ ]				/* ignore whitespace */
[\n]				return 0;
{STRING}			if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", ipfwtext);
.				if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", ipfwtext);

%%

void ipfw_parse_start(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[3];

  retval = sscanf(input,
		  "%3s %2d %2d:%2d:%2d %32s",
		  smonth, &day, &hour, &minute, &second,
		  opt.line->hostname);
  if (retval != 6) {
    return;
  }

  build_time(smonth, day, hour, minute, second);

  opt.parser=opt.parser|IPFW_DATE;
}

void ipfw_parse_proto(char *input, unsigned char mode)
{
  int retval;
  char *pnt;

  if(mode == IPFW_OPT_NONE) {
    if(strncmp(input, "TCP", 3) == 0) opt.line->protocol = 6;
    if(strncmp(input, "UDP", 3) == 0) opt.line->protocol = 17;
  } else if(mode == IPFW_OPT_ICMP) {
    opt.line->protocol = 1;
    pnt = strstr(input, ".");
    *pnt = ' ';
    retval = sscanf(input, "%2d %2d", &opt.line->sport, &opt.line->dport);
    if (retval != 2) {
      return;
    }
    opt.parser=opt.parser|IPFW_PORTS;
  }
  if(opt.line->protocol != 0) {
    opt.parser=opt.parser|IPFW_PROTO;
  }
}

void ipfw_parse_ips(char *input, unsigned char mode)
{
  int retval;
  char src[16], dst[16], *pnt;

  if (mode == IPFW_OPT_PORTS) {
    pnt = strstr(input, ":");
    *pnt = ' ';
    pnt = strstr(input, ":");
    *pnt = ' ';
    retval = sscanf(input, "%16s %5d %16s %5d",
		    src, &opt.line->sport, dst, &opt.line->dport);
    if (retval != 4) {
      return;
    }
    opt.parser=opt.parser|IPFW_PORTS;
  } else if (mode == IPFW_OPT_NONE) {
    retval = sscanf(input, "%16s %16s", src, dst);
    if (retval != 2) {
      return;
    }
  }

  if(convert_ip(src, &opt.line->shost) == IN_ADDR_ERROR) return;
  if(convert_ip(dst, &opt.line->dhost) == IN_ADDR_ERROR) return;
  opt.parser=opt.parser|IPFW_IPS;
}

unsigned char flex_ipfw(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  ipfw_scan_string(input);
  ipfwlex();
  ipfw_delete_buffer(YY_CURRENT_BUFFER);

  opt.line->count = 1;

  if (opt.parser == (IPFW_DATE|IPFW_CHAIN|IPFW_BRANCH|IPFW_PROTO|IPFW_IPS|IPFW_PORTS|IPFW_IF)) {
    return PARSE_OK;
  }
  if(opt.verbose)
    fprintf(stderr, "ipfw parse error in line %d, ignoring.\n", linenum);
  if(opt.verbose == 2)
    fprintf(stderr, "input was: \"%s\"\n", input);
  return PARSE_WRONG_FORMAT;
}
