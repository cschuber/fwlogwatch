/* $Id: netscreen.l,v 1.3 2003/04/08 21:42:42 bwess Exp $ */

%option prefix="ns"
%option outfile="netscreen.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void ns_parse_date(char *input);
void ns_parse_ip(char *input, unsigned char mode);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
LOGHOST	[0-9.a-zA-Z()_:-]*
DIGIT	[0-9]
NUMBER	{DIGIT}{1,6}
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
SERVICE	[a-z/A-Z:0-9]+(" ("[a-zA-Z]+")")?

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	ns_parse_date(nstext);
{STRING}": NetScreen"	/* ignore */
"device_id="{STRING}	xstrncpy(opt.line->hostname,nstext+10,SHORTLEN);
"system-information-"{NUMBER}":"	/* ignore */
"system-notification-"{NUMBER}"(traffic):"	/* ignore */
"start_time=\""{DIGIT}{4}"-"{DIGIT}{2}"-"{DIGIT}{2}[ ]{DIGIT}{2}":"{DIGIT}{2}":"{DIGIT}{2}"\""	/* ignore */
"duration="{NUMBER}	/* ignore */
"policy_id="{NUMBER}	/* ignore */
"service="{SERVICE}	/* ignore */
"proto="{NUMBER}	{opt.line->protocol=atoi(nstext+6); opt.parser=opt.parser|NS_PROTO;}
"direction="{STRING}	/* ignore */
"src zone="{STRING}	/* ignore */
"dst zone="{STRING}	/* ignore */
"action="{STRING}	{xstrncpy(opt.line->branchname,nstext+7,SHORTLEN); opt.parser=opt.parser|NS_BN;}
"sent=0"		/* ignore */
"rcvd=0"		/* ignore */
"sent="[1-9]{NUMBER}	opt.line->datalen=atoi(nstext+5);
"rcvd="[1-9]{NUMBER}	opt.line->datalen=atoi(nstext+5);
"src="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	ns_parse_ip(nstext+4,NETSCREEN_OPT_SRC);
"dst="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	ns_parse_ip(nstext+4,NETSCREEN_OPT_DST);
"src_port="{PORT}	{opt.line->sport=atoi(nstext+9); opt.parser=opt.parser|NS_SPORT;}
"dst_port="{PORT}	{opt.line->dport=atoi(nstext+9); opt.parser=opt.parser|NS_DPORT;}
"icmp type="{NUMBER}	{opt.line->sport=atoi(nstext+10); opt.line->sport=0; opt.parser=opt.parser|NS_SPORT|NS_DPORT;}
"translated ip="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" port="{PORT}	/* ignore */
[ ]+			/* ignore whitespace */
[\n]			return 0;
{STRING}		if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", nstext);
.			if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", nstext);

%%


void ns_parse_date(char *input)
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

  opt.parser=opt.parser|NS_DATE;
}

void ns_parse_ip(char *input, unsigned char mode)
{
  if (mode == NETSCREEN_OPT_SRC) {
    if(convert_ip(input, &opt.line->shost) == IN_ADDR_ERROR) return;
    opt.parser=opt.parser|NS_SRC;
  } else {
    if(convert_ip(input, &opt.line->dhost) == IN_ADDR_ERROR) return;
    opt.parser=opt.parser|NS_DST;
  }
}

unsigned char flex_netscreen(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  ns_scan_string(input);
  nslex();

  xstrncpy(opt.line->chainlabel, "-", SHORTLEN);
  xstrncpy(opt.line->interface, "-", SHORTLEN);
  opt.line->count = 1;

  if (opt.parser == (NS_DATE|NS_SRC|NS_DST|NS_SPORT|NS_DPORT|NS_BN|NS_PROTO)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "netscreen parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
