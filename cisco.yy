/* $Id: cisco.yy,v 1.2 2002/02/14 20:45:42 bwess Exp $ */

%option prefix="cisco"
%option outfile="cisco.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void cisco_parse_date(char *input, unsigned char mode);
void cisco_parse_src(char *input, unsigned char mode);
void cisco_parse_dst(char *input, unsigned char mode);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
CISCO	"%SEC-6-IPACCESSLOG"("P"|"DP"|"RP"|"NP"|"S")":"
TARGET	"denied"|"permitted"
PROTO	"tcp"|"udp"|"icmp"|"igmp"|"gre"|{NUMBER}
LIST	[a-zA-Z0-9._-]*

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{STRING}	cisco_parse_date(ciscotext, C_OPT_HOST);
{NUMBER}":"	/* ignore */
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}":"	cisco_parse_date(ciscotext, C_OPT_NONE);
{CISCO}		/* ignore */
"list "{LIST}[ ]{TARGET}[ ]{PROTO}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"("{PORT}")"	cisco_parse_src(ciscotext, C_OPT_PORT);
"list "{LIST}[ ]{TARGET}[ ]{PROTO}[ ]{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	cisco_parse_src(ciscotext, C_OPT_NONE);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"("{PORT}"),"	cisco_parse_dst(ciscotext, C_OPT_PORT);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" ("{NUMBER}"/"{NUMBER}"),"	cisco_parse_dst(ciscotext, C_OPT_TYPE);
"-> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","	cisco_parse_dst(ciscotext, C_OPT_NONE);
{NUMBER}" packet"("s")?	{ opt.line->count = atoi(ciscotext); opt.cisco=opt.cisco|CISCO_COUNT; }
"("[A-Za-z0-9 /._-]*")"	/* ignore */
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	fprintf(stderr, "Unrecognized token: %s\n", ciscotext);
.		fprintf(stderr, "Unrecognized character: %s\n", ciscotext);

%%

void cisco_parse_date(char *input, unsigned char mode)
{
  char smonth[3];
#ifdef LOGDOTS
  char *remove_dot;
#endif
  int month = 0, day, hour, minute, second;
  struct tm *t;

  if (mode == C_OPT_HOST) {
    sscanf(input, "%3s %2d %2d:%2d:%2d %32s",
	   smonth, &day, &hour, &minute, &second,
	   opt.line->hostname);
#ifdef LOGDOTS
    remove_dot = strstr(opt.line->hostname, ".");
    if(remove_dot != NULL)
      *remove_dot = '\0';
#endif
  } else if (mode == C_OPT_NONE) {
    sscanf(input, "%3s %2d %2d:%2d:%2d:",
	   smonth, &day, &hour, &minute, &second);
  } else {
    return;
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

  opt.cisco=opt.cisco|CISCO_DATE;
}

void cisco_parse_src(char *input, unsigned char mode)
{
  char proto[5];
  int shost1, shost2, shost3, shost4;

  if (mode == C_OPT_PORT) {
    sscanf(input, "list %10s %10s %5s %3d.%3d.%3d.%3d(%5d)",
	   opt.line->chainlabel,
	   opt.line->branchname,
	   proto,
	   &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
  } else if (mode == C_OPT_NONE) {
    sscanf(input, "list %10s %10s %5s %3d.%3d.%3d.%3d",
	   opt.line->chainlabel,
	   opt.line->branchname,
	   proto,
	   &shost1, &shost2, &shost3, &shost4);
  }

  snprintf(opt.line->shost, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  opt.cisco=opt.cisco|CISCO_SRC;

  if(strncmp(proto, "tcp", 3) == 0) opt.line->protocol = 6;
  if(strncmp(proto, "udp", 3) == 0) opt.line->protocol = 17;
  if(strncmp(proto, "icmp", 4) == 0) opt.line->protocol = 1;
  if(strncmp(proto, "igmp", 4) == 0) opt.line->protocol = 2;
  if(strncmp(proto, "gre", 3) == 0) opt.line->protocol = 47; /* RFC1701/1702 */
  if(isdigit((int)proto[0])) opt.line->protocol = atoi(proto);

  if (opt.line->protocol != 0)
    opt.cisco=opt.cisco|CISCO_PROTO;
}

void cisco_parse_dst(char *input, unsigned char mode)
{
  int dhost1, dhost2, dhost3, dhost4;

  if (mode == C_OPT_PORT) {
    sscanf(input, "-> %3d.%3d.%3d.%3d(%5d),",
	   &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
  } else if (mode == C_OPT_TYPE) {
    sscanf(input, "-> %3d.%3d.%3d.%3d (%2d/%2d),",
	   &dhost1, &dhost2, &dhost3, &dhost4,
	   &opt.line->sport, &opt.line->dport);
  } else if (mode == C_OPT_NONE) {
    sscanf(input, "-> %3d.%3d.%3d.%3d,",
	   &dhost1, &dhost2, &dhost3, &dhost4);
  } else {
    return;
  }

  snprintf(opt.line->dhost, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
  opt.cisco=opt.cisco|CISCO_DST;
}

unsigned char flex_cisco(char *input, int linenum)
{
  opt.cisco = 0;
  init_line();
  cisco_scan_string(input);
  ciscolex();

  strncpy(opt.line->interface, "-", SHORTLEN);

  if (opt.cisco == (CISCO_DATE|CISCO_SRC|CISCO_PROTO|CISCO_DST|CISCO_COUNT)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "cisco parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
