/* $Id: cisco_ios.l,v 1.10 2002/05/15 22:24:44 bwess Exp $ */

%option prefix="cisco_ios"
%option outfile="cisco_ios.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void cisco_ios_parse_date(char *input, unsigned char mode);
void cisco_ios_parse_src(char *input, unsigned char mode);
void cisco_ios_parse_dst(char *input, unsigned char mode);
void cisco_ios_parse_if(char *input);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
LOGHOST	[0-9.a-zA-Z()_:-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
CISCO	"%SEC-6-IPACCESSLOG"("P"|"DP"|"RP"|"NP"|"S")":"
LIST	[a-zA-Z0-9._>-]*
TARGET	"denied"|"permitted"
PROTO	"tcp"|"udp"|"icmp"|"igmp"|"gre"|"ospf"|"ipinip"|"pim"|{NUMBER}

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	cisco_ios_parse_date(cisco_iostext, CI_OPT_HOST);
{NUMBER}":"	/* ignore */
{DIGIT}"y"{DIGIT}{1,2}"w:"	/* ignore */
{DIGIT}{1,2}"w"{DIGIT}"d:"	/* ignore */
{DIGIT}"d"{DIGIT}{2}"h:"	/* ignore */
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}"."{DIGIT}{3}":"	cisco_ios_parse_date(cisco_iostext, CI_OPT_MSEC);
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}":"	cisco_ios_parse_date(cisco_iostext, CI_OPT_NONE);
{CISCO}		/* ignore */
"list "{LIST}[ ]{TARGET}[ ]{PROTO}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"("{PORT}")"	cisco_ios_parse_src(cisco_iostext, CI_OPT_PORT);
"list "{LIST}[ ]{TARGET}[ ]{PROTO}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	cisco_ios_parse_src(cisco_iostext, CI_OPT_NONE);
"list "{LIST}[ ]{TARGET}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	cisco_ios_parse_src(cisco_iostext, CI_OPT_MISSING);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"("{PORT}"),"	cisco_ios_parse_dst(cisco_iostext, CI_OPT_PORT);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" ("{NUMBER}"/"{NUMBER}"),"	cisco_ios_parse_dst(cisco_iostext, CI_OPT_TYPE);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","	cisco_ios_parse_dst(cisco_iostext, CI_OPT_NONE);
{NUMBER}" packet"("s")?	{ opt.line->count = atoi(cisco_iostext); opt.parser=opt.parser|CISCO_IOS_COUNT; }
"("[A-Za-z0-9 /\._\*-]*")"	cisco_ios_parse_if(cisco_iostext);
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", cisco_iostext);
.		if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", cisco_iostext);

%%

void cisco_ios_parse_date(char *input, unsigned char mode)
{
  int retval, day, hour, minute, second, msec;
  char smonth[3];
#ifdef IRIX
    char tmp[SHOSTLEN];
#endif
#ifdef LOGDOTS
  char *remove_dot;
#endif

  if (mode == CI_OPT_HOST) {
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
  } else if (mode == CI_OPT_MSEC) {
    retval = sscanf(input, "%3s %2d %2d:%2d:%2d.%3d:",
		    smonth, &day, &hour, &minute, &second, &msec);
    if(retval != 6) return;
  } else if (mode == CI_OPT_NONE) {
    retval = sscanf(input, "%3s %2d %2d:%2d:%2d:",
		    smonth, &day, &hour, &minute, &second);
    if(retval != 5) return;
  } else {
    return;
  }

  build_time(smonth, day, hour, minute, second);

  opt.parser=opt.parser|CISCO_IOS_DATE;
}

void cisco_ios_parse_src(char *input, unsigned char mode)
{
  char proto[8], ip[IPLEN];
  int shost1, shost2, shost3, shost4;
  int retval;

  if (mode == CI_OPT_PORT) {
    retval = sscanf(input, "list %" SSHORTLEN "s %" SSHORTLEN "s %5s %3d.%3d.%3d.%3d(%5d)",
		    opt.line->chainlabel,
		    opt.line->branchname,
		    proto,
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    if(retval != 8) return;
  } else if (mode == CI_OPT_NONE) {
    retval = sscanf(input, "list %" SSHORTLEN "s %" SSHORTLEN "s %8s %3d.%3d.%3d.%3d",
		    opt.line->chainlabel,
		    opt.line->branchname,
		    proto,
		    &shost1, &shost2, &shost3, &shost4);
    if(retval != 7) return;
  } else if (mode == CI_OPT_MISSING) {
    return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  if(convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_IOS_SRC;

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
    opt.parser=opt.parser|CISCO_IOS_PROTO;
}

void cisco_ios_parse_dst(char *input, unsigned char mode)
{
  char ip[IPLEN];
  int dhost1, dhost2, dhost3, dhost4;
  int retval;

  if (mode == CI_OPT_PORT) {
    retval = sscanf(input, "-> %3d.%3d.%3d.%3d(%5d),",
		    &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if(retval != 5) return;
  } else if (mode == CI_OPT_TYPE) {
    retval = sscanf(input, "-> %3d.%3d.%3d.%3d (%2d/%2d),",
		    &dhost1, &dhost2, &dhost3, &dhost4,
		    &opt.line->sport, &opt.line->dport);
    if(retval != 6) return;
  } else if (mode == CI_OPT_NONE) {
    retval = sscanf(input, "-> %3d.%3d.%3d.%3d,",
		    &dhost1, &dhost2, &dhost3, &dhost4);
    if(retval != 4) return;
  } else {
    return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
  if(convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_IOS_DST;
}

void cisco_ios_parse_if(char *input)
{
#ifndef SHORT_NAMES
  xstrncpy(opt.line->interface, input, SHORTLEN);
#else
  xstrncpy(opt.line->interface, "-", SHORTLEN);
#endif
}

unsigned char flex_cisco_ios(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  cisco_ios_scan_string(input);
  cisco_ioslex();

  if (opt.parser == (CISCO_IOS_DATE|CISCO_IOS_SRC|CISCO_IOS_PROTO|CISCO_IOS_DST|CISCO_IOS_COUNT)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "cisco parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
