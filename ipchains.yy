/* $Id: ipchains.yy,v 1.1 2002/02/14 20:48:49 bwess Exp $ */

%option prefix="ipchains"
%option outfile="ipchains.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void ipchains_parse_date(char *input);
void ipchains_parse_data(char *input);
void ipchains_parse_rdata(char *input);
void ipchains_parse_ips(char *input);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
LOGHOST	[0-9.a-zA-Z_-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
HEXDIGIT	[0-9a-fA-F]
HEXNUM	"0x"{HEXDIGIT}+
IPCHAINS	" kernel: Packet log: "

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	ipchains_parse_date(ipchainstext);
{IPCHAINS}	/* ignore */
{STRING}[ ]{STRING}[ ]{STRING}" PROTO="{NUMBER}	ipchains_parse_data(ipchainstext);
{STRING}" REDIRECT "{NUMBER}[ ]{STRING}" PROTO="{NUMBER}	ipchains_parse_rdata(ipchainstext);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}":"{PORT}" "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}":"{PORT}	ipchains_parse_ips(ipchainstext);
"L="{NUMBER}	/* ignore */
"S="{HEXNUM}	/* ignore */
"I="{NUMBER}	/* ignore */
"F="{HEXNUM}	/* ignore */
"T="{NUMBER}	/* ignore */
"O="{HEXNUM}	/* ignore */
"SYN"		opt.line->syn = 1;
"(#"{NUMBER}")"	/* ignore */
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	fprintf(stderr, "Unrecognized token: %s\n", ipchainstext);
.		fprintf(stderr, "Unrecognized character: %s\n", ipchainstext);

%%

void ipchains_parse_date(char *input)
{
  char smonth[3];
  int month = 0, day, hour, minute, second;
  struct tm *t;

  sscanf(input, "%3s %2d %2d:%2d:%2d %32s",
	 smonth, &day, &hour, &minute, &second,
	 opt.line->hostname);

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

  opt.parser=opt.parser|IPCHAINS_DATE;
}

void ipchains_parse_data(char *input)
{
  sscanf(input, "%10s %10s %10s PROTO=%3d",
	 opt.line->chainlabel,
	 opt.line->branchname,
	 opt.line->interface,
	 &opt.line->protocol);

  opt.parser=opt.parser|IPCHAINS_DATA;
}
 
void ipchains_parse_rdata(char *input)
{
  int port;

  sscanf(input, "%10s REDIRECT %5d %10s PROTO=%3d",
	 opt.line->chainlabel,
	 &port,
	 opt.line->interface,
	 &opt.line->protocol);

  snprintf(opt.line->branchname, SHORTLEN, "RD %d", port);

  opt.parser=opt.parser|IPCHAINS_DATA;
}
 
void ipchains_parse_ips(char *input)
{
  int shost1, shost2, shost3, shost4;
  int dhost1, dhost2, dhost3, dhost4;

  sscanf(input, "%3d.%3d.%3d.%3d:%5d %3d.%3d.%3d.%3d:%5d",
	 &shost1, &shost2, &shost3, &shost4, &opt.line->sport,
	 &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);

  snprintf(opt.line->shost, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  snprintf(opt.line->dhost, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);

  opt.parser=opt.parser|IPCHAINS_IPS;
}

unsigned char flex_ipchains(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  ipchains_scan_string(input);
  ipchainslex();

  opt.line->count = 1;

  if (opt.parser == (IPCHAINS_DATE|IPCHAINS_DATA|IPCHAINS_IPS)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "ipchains parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
