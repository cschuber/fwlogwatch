/* $Id: cisco.l,v 1.1 2002/02/14 21:15:35 bwess Exp $ */

%option prefix="cisco"
%option outfile="cisco.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void cisco_parse_date(char *input, unsigned char mode);
void cisco_parse_src(char *input, unsigned char mode);
void cisco_parse_dst(char *input, unsigned char mode);
void cisco_parse_if(char *input);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
LOGHOST	[0-9.a-zA-Z_:-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
CISCO	"%SEC-6-IPACCESSLOG"("P"|"DP"|"RP"|"NP"|"S")":"
LIST	[a-zA-Z0-9._-]*
TARGET	"denied"|"permitted"
PROTO	"tcp"|"udp"|"icmp"|"igmp"|"gre"|"ospf"|"ipinip"|"pim"|{NUMBER}

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	cisco_parse_date(ciscotext, C_OPT_HOST);
{NUMBER}":"	/* ignore */
{DIGIT}"y"{DIGIT}{1,2}"w:"	/* ignore */
{DIGIT}{1,2}"w"{DIGIT}"d:"	/* ignore */
{DIGIT}"d"{DIGIT}{2}"h:"	/* ignore */
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}"."{DIGIT}{3}":"	cisco_parse_date(ciscotext, C_OPT_MSEC);
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}":"	cisco_parse_date(ciscotext, C_OPT_NONE);
{CISCO}		/* ignore */
"list "{LIST}[ ]{TARGET}[ ]{PROTO}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"("{PORT}")"	cisco_parse_src(ciscotext, C_OPT_PORT);
"list "{LIST}[ ]{TARGET}[ ]{PROTO}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	cisco_parse_src(ciscotext, C_OPT_NONE);
"list "{LIST}[ ]{TARGET}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	cisco_parse_src(ciscotext, C_OPT_MISSING);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"("{PORT}"),"	cisco_parse_dst(ciscotext, C_OPT_PORT);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" ("{NUMBER}"/"{NUMBER}"),"	cisco_parse_dst(ciscotext, C_OPT_TYPE);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","	cisco_parse_dst(ciscotext, C_OPT_NONE);
{NUMBER}" packet"("s")?	{ opt.line->count = atoi(ciscotext); opt.parser=opt.parser|CISCO_COUNT; }
"("[A-Za-z0-9 /\._\*-]*")"	cisco_parse_if(ciscotext);
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	fprintf(stderr, "Unrecognized token: %s\n", ciscotext);
.		fprintf(stderr, "Unrecognized character: %s\n", ciscotext);

%%

void cisco_parse_date(char *input, unsigned char mode)
{
  int retval, day, hour, minute, second, msec;
  char smonth[3];
#ifdef IRIX
    char tmp[SHOSTLEN];
#endif
#ifdef LOGDOTS
  char *remove_dot;
#endif

  if (mode == C_OPT_HOST) {
    retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s",
	   smonth, &day, &hour, &minute, &second,
#ifndef IRIX
	   opt.line->hostname);
#else
	   tmp);
    if(retval != 6) return;
    if(tmp[2] == ':')
      strncpy(opt.line->hostname, tmp+3, SHOSTLEN);
#endif
#ifdef LOGDOTS
    remove_dot = strstr(opt.line->hostname, ".");
    if(remove_dot != NULL)
      *remove_dot = '\0';
#endif
  } else if (mode == C_OPT_MSEC) {
    retval = sscanf(input, "%3s %2d %2d:%2d:%2d.%3d:",
		    smonth, &day, &hour, &minute, &second, &msec);
    if(retval != 6) return;
  } else if (mode == C_OPT_NONE) {
    retval = sscanf(input, "%3s %2d %2d:%2d:%2d:",
		    smonth, &day, &hour, &minute, &second);
    if(retval != 5) return;
  } else {
    return;
  }

  build_time(smonth, day, hour, minute, second);

  opt.parser=opt.parser|CISCO_DATE;
}

void cisco_parse_src(char *input, unsigned char mode)
{
  char proto[8], ip[IPLEN];
  int shost1, shost2, shost3, shost4;
  int retval;

  if (mode == C_OPT_PORT) {
#ifdef LONG_NAMES
    retval = sscanf(input, "list %30s %30s %5s %3d.%3d.%3d.%3d(%5d)",
#else
    retval = sscanf(input, "list %10s %10s %5s %3d.%3d.%3d.%3d(%5d)",
#endif
		    opt.line->chainlabel,
		    opt.line->branchname,
		    proto,
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    if(retval != 8) return;
  } else if (mode == C_OPT_NONE) {
#ifdef LONG_NAMES
    retval = sscanf(input, "list %30s %30s %8s %3d.%3d.%3d.%3d",
#else
    retval = sscanf(input, "list %10s %10s %8s %3d.%3d.%3d.%3d",
#endif
		    opt.line->chainlabel,
		    opt.line->branchname,
		    proto,
		    &shost1, &shost2, &shost3, &shost4);
    if(retval != 7) return;
  } else if (mode == C_OPT_MISSING) {
    return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  if(convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_SRC;

  if(strncmp(proto, "tcp", 3) == 0) opt.line->protocol = 6;
  else if(strncmp(proto, "udp", 3) == 0) opt.line->protocol = 17;
  else if(strncmp(proto, "icmp", 4) == 0) opt.line->protocol = 1;
  else if(strncmp(proto, "igmp", 4) == 0) opt.line->protocol = 2;
  else if(strncmp(proto, "gre", 3) == 0) opt.line->protocol = 47; /* RFC1701/1702 */
  else if(strncmp(proto, "ospf", 4) == 0) opt.line->protocol = 89;
  else if(strncmp(proto, "ipinip", 6) == 0) opt.line->protocol = 4;
  else if(strncmp(proto, "pim", 3) == 0) opt.line->protocol = 103;
  else if(isdigit((int)proto[0])) opt.line->protocol = atoi(proto);

  if (opt.line->protocol != 0)
    opt.parser=opt.parser|CISCO_PROTO;
}

void cisco_parse_dst(char *input, unsigned char mode)
{
  char ip[IPLEN];
  int dhost1, dhost2, dhost3, dhost4;
  int retval;

  if (mode == C_OPT_PORT) {
    retval = sscanf(input, "-> %3d.%3d.%3d.%3d(%5d),",
		    &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if(retval != 5) return;
  } else if (mode == C_OPT_TYPE) {
    retval = sscanf(input, "-> %3d.%3d.%3d.%3d (%2d/%2d),",
		    &dhost1, &dhost2, &dhost3, &dhost4,
		    &opt.line->sport, &opt.line->dport);
    if(retval != 6) return;
  } else if (mode == C_OPT_NONE) {
    retval = sscanf(input, "-> %3d.%3d.%3d.%3d,",
		    &dhost1, &dhost2, &dhost3, &dhost4);
    if(retval != 4) return;
  } else {
    return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
  if(convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_DST;
}

void cisco_parse_if(char *input)
{
#ifdef LONG_NAMES
  strncpy(opt.line->interface, input, SHORTLEN);
#else
  strncpy(opt.line->interface, "-", SHORTLEN);
#endif
}

unsigned char flex_cisco(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  cisco_scan_string(input);
  ciscolex();

  if (opt.parser == (CISCO_DATE|CISCO_SRC|CISCO_PROTO|CISCO_DST|CISCO_COUNT)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "cisco parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
