/* $Id: netfilter.yy,v 1.2 2002/02/14 20:42:15 bwess Exp $ */

%option prefix="nf"
%option outfile="netfilter.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <string.h>
#include <time.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void nf_parse_start(char *input);
void nf_parse_proto(char *input);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9.-]*
ISTRING	[a-zA-HJ-Z0-9.-]*
DIGIT	[0-9]
HEXDIGIT	[0-9a-fA-F]
NUMBER	{DIGIT}+
HEXNUM	"0x"{HEXDIGIT}+
OCTET   {DIGIT}{1,3}

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{STRING}" kernel: "{ISTRING}	nf_parse_start(nftext);
"IN="{STRING}?	{ strncpy(opt.line->interface, nftext+3, SHORTLEN); opt.nf=opt.nf|NF_IN; }
"OUT="{STRING}?		/* ignore */
"MAC="({HEXDIGIT}{HEXDIGIT}:){13}{HEXDIGIT}{HEXDIGIT}	/* ignore */
"SRC="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET} { strncpy(opt.line->shost, nftext+4, IPLEN); opt.nf=opt.nf|NF_SRC; }
"DST="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET} { strncpy(opt.line->dhost, nftext+4, IPLEN); opt.nf=opt.nf|NF_DST; }
"LEN="{NUMBER}		/* ignore */
"TOS="{HEXNUM}		/* ignore */
"PREC="{HEXNUM}		/* ignore */
"TTL="{NUMBER}		/* ignore */
"ID="{NUMBER}		/* ignore */
"CE"			/* ignore */
"DF"			/* ignore */
"MF"			/* ignore */
"FRAG:"{NUMBER}		/* ignore */
"PROTO="{STRING}	nf_parse_proto(nftext+6);
"INCOMPLETE ["{NUMBER}" bytes]" /* ignore */
"TYPE="{NUMBER}		{ opt.line->sport = atoi(nftext+5); opt.nf=opt.nf|NF_TYPE; }
"CODE="{NUMBER}		/* ignore */
"SEQ="{NUMBER}		/* ignore */
"ACK="{NUMBER}		/* ignore */
"SPT="{NUMBER}		{ opt.line->sport = atoi(nftext+4); opt.nf=opt.nf|NF_SPT; }
"DPT="{NUMBER}		{ opt.line->dport = atoi(nftext+4); opt.nf=opt.nf|NF_DPT; }
"WINDOW="{NUMBER}	/* ignore */
"RES="{HEXNUM}		/* ignore */
"URG"			/* fixme */
"ACK"			/* fixme */
"PSH"			/* fixme */
"RST"			/* fixme */
"SYN"			opt.line->syn = 1;
"FIN"			/* fixme */
"URGP="{NUMBER}		/* ignore */
"OPT ("[0-9A-F]*")"	/* ignore */
"SPI="{HEXNUM}		/* ignore */
[ ]+			/* ignore whitespace */
[\n]			return 0;
{STRING}		fprintf(stderr, "Unrecognized token: %s\n", nftext);
.			fprintf(stderr, "Unrecognized character: %s\n", nftext);

%%

void nf_parse_start(char *input)
{
  int retval;
  char smonth[3];
  int month = 0, day, hour, minute, second;
  struct tm *t;

  retval = sscanf(input,
		  "%3s %2d %2d:%2d:%2d %32s kernel: %10s",
		  smonth, &day, &hour, &minute, &second,
		  opt.line->hostname,
		  opt.line->chainlabel);
  if (retval != 7) {
    if (retval == 6) {
      strncpy(opt.line->chainlabel, "-", SHORTLEN);
    } else {
      if(opt.verbose)
	fprintf(stderr, "netfilter format mismatch: %d args, ignoring.\n", retval);
      return;
    }
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

  opt.nf=opt.nf|NF_DATE;
}

void nf_parse_proto(char *input)
{
  if(strncmp(input, "TCP", 3) == 0) opt.line->protocol = 6;
  if(strncmp(input, "UDP", 3) == 0) opt.line->protocol = 17;
  if(strncmp(input, "ICMP", 4) == 0) opt.line->protocol = 1;

  if (opt.line->protocol != 0)
    opt.nf=opt.nf|NF_PROTO;
}

unsigned char flex_netfilter(char *input, int linenum)
{
  opt.nf = 0;
  init_line();
  nf_scan_string(input);
  nflex();

  strncpy(opt.line->branchname, "-", SHORTLEN);
  opt.line->count = 1;

  if (((opt.line->protocol == 6) || (opt.line->protocol == 17)) && (opt.nf == (NF_DATE|NF_PROTO|NF_IN|NF_SRC|NF_DST|NF_SPT|NF_DPT))) {
    return PARSE_OK;
  }
  if ((opt.line->protocol == 1) && (opt.nf == (NF_DATE|NF_PROTO|NF_IN|NF_SRC|NF_DST|NF_TYPE))) {
    return PARSE_OK;
  }
  if(opt.verbose)
    fprintf(stderr, "netfilter parse error in line %d, ignoring.\n", linenum);
  return PARSE_WRONG_FORMAT;
}
