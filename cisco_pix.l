/* $Id: cisco_pix.l,v 1.8 2002/03/29 11:25:51 bwess Exp $ */

%option prefix="cisco_pix"
%option outfile="cisco_pix.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void cisco_pix_parse_date(char *input);
void cisco_pix_parse_src(char *input, unsigned char mode);
void cisco_pix_parse_dst(char *input, unsigned char mode);
void cisco_pix_parse_count(char *input);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
LOGHOST	[0-9.a-zA-Z_:-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
PIX	"%PIX-2-10"("6001"|"6006"|"6007"|"7001")":"

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}		cisco_pix_parse_date(cisco_pixtext);
{PIX}											/* ignore */
" Inbound TCP connection denied from "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}	cisco_pix_parse_src(cisco_pixtext, CP_OPT_ITCP);
" Deny TCP (no connection) from "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}		cisco_pix_parse_src(cisco_pixtext, CP_OPT_TCP);
" Deny inbound UDP from "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}			cisco_pix_parse_src(cisco_pixtext, CP_OPT_UDP);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" attempted to ping "				cisco_pix_parse_src(cisco_pixtext, CP_OPT_ICMP);
"to "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}					cisco_pix_parse_dst(cisco_pixtext, CP_OPT_TO);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}							cisco_pix_parse_dst(cisco_pixtext, CP_OPT_NONE);
"flags"											/* ignore */
"URG"											opt.line->flags = opt.line->flags | TCP_URG;
"ACK"											opt.line->flags = opt.line->flags | TCP_ACK;
"PSH"											opt.line->flags = opt.line->flags | TCP_PSH;
"RST"											opt.line->flags = opt.line->flags | TCP_RST;
"SYN"											opt.line->flags = opt.line->flags | TCP_SYN;
"FIN"											opt.line->flags = opt.line->flags | TCP_FIN;
"due to DNS "("Query"|"Response")							/* ignore */
"("{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}")"						/* ignore */
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", cisco_pixtext);
.		if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", cisco_pixtext);

%%

void cisco_pix_parse_date(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[3];
#ifdef IRIX
    char tmp[SHOSTLEN];
#endif
#ifdef LOGDOTS
  char *remove_dot;
#endif

  retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s",
	   smonth, &day, &hour, &minute, &second,
#ifndef IRIX
	   opt.line->hostname);
#else
	   tmp);
  if(retval != 6) return;
  if(tmp[2] == ':')
    xstrncpy(opt.line->hostname, tmp+3, SHOSTLEN);
#endif
#ifdef LOGDOTS
  remove_dot = strstr(opt.line->hostname, ".");
  if(remove_dot != NULL)
    *remove_dot = '\0';
#endif

  build_time(smonth, day, hour, minute, second);

  opt.parser=opt.parser|CISCO_PIX_DATE;
}

void cisco_pix_parse_src(char *input, unsigned char mode)
{
  char ip[IPLEN];
  int shost1, shost2, shost3, shost4;
  int retval;

  if (mode == CP_OPT_ITCP) {
#ifndef SHORT_NAMES
    retval = sscanf(input, " %30s TCP connection %30s from %3d.%3d.%3d.%3d/%5d",
#else
    retval = sscanf(input, " %10s TCP connection %10s from %3d.%3d.%3d.%3d/%5d",
#endif
		    opt.line->branchname,
		    opt.line->chainlabel,
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    opt.line->protocol = 6;
    if(retval != 7) return;
  } else if (mode == CP_OPT_TCP) {
#ifndef SHORT_NAMES
    retval = sscanf(input, " %30s TCP (no connection) from %3d.%3d.%3d.%3d/%5d",
#else
    retval = sscanf(input, " %10s TCP (no connection) from %3d.%3d.%3d.%3d/%5d",
#endif
		    opt.line->chainlabel,
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    xstrncpy(opt.line->branchname, "-", SHORTLEN);
    opt.line->protocol = 6;
    if(retval != 6) return;
  } else if (mode == CP_OPT_UDP) {
#ifndef SHORT_NAMES
    retval = sscanf(input, " %30s %30s UDP from %3d.%3d.%3d.%3d/%5d",
#else
    retval = sscanf(input, " %10s %10s UDP from %3d.%3d.%3d.%3d/%5d",
#endif
		    opt.line->chainlabel,
		    opt.line->branchname,
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    opt.line->protocol = 17;
    if(retval != 7) return;
  } else if (mode == CP_OPT_ICMP) {
#ifndef SHORT_NAMES
    retval = sscanf(input, "%3d.%3d.%3d.%3d %30s to ping",
#else
    retval = sscanf(input, "%3d.%3d.%3d.%3d %10s to ping",
#endif
		    &shost1, &shost2, &shost3, &shost4,
		    opt.line->chainlabel);
    xstrncpy(opt.line->branchname, "-", SHORTLEN);
    opt.line->protocol = 1;
    if(retval != 5) return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  if(convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_PIX_SRC;
}

void cisco_pix_parse_dst(char *input, unsigned char mode)
{
  char ip[IPLEN];
  int dhost1, dhost2, dhost3, dhost4;
  int retval;

  if (mode == CP_OPT_TO) {
    retval = sscanf(input, "to %3d.%3d.%3d.%3d/%5d",
		    &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if(retval != 5) return;
  } else if (mode == CP_OPT_NONE) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d",
		    &dhost1, &dhost2, &dhost3, &dhost4);
    if(retval != 4) return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
  if(convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_PIX_DST;
}

unsigned char flex_cisco_pix(char *input, int linenum)
{
  opt.parser = 0;

  init_line();

  cisco_pix_scan_string(input);
  cisco_pixlex();

  xstrncpy(opt.line->interface, "-", SHORTLEN);
  opt.line->count = 1;

  if (opt.parser == (CISCO_PIX_DATE|CISCO_PIX_SRC|CISCO_PIX_DST)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "cisco pix log parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
