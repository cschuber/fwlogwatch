/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: netfilter.l,v 1.21 2016/02/19 16:09:27 bwess Exp $ */

%option prefix="nf"
%option outfile="netfilter.c"
%option noyywrap

%{
#define YY_NO_INPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void nf_parse_start_hn(char *input);
void nf_parse_start(char *input);
void nf_parse_isostart_hn(char *input);
void nf_parse_rfc5424start_hn(char *input);
void nf_parse_prefix(char *input, unsigned char mode);
void nf_parse_ip(char *input, unsigned char mode);
void nf_parse_proto(char *input);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
PREFIX	[ -~¡-ÿ]*([ -RT-~¡-ÿ]|[ -XZ-~¡-ÿ]"S")"IN="
LOGHOST	[0-9.a-zA-Z()_:-]+
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
HEXDIGIT	[0-9a-fA-F]
HEXNUM	"0x"{HEXDIGIT}+
PROTO	"TCP"|"UDP"|"ICMP"|"ESP"|"AH"|"ICMPv6"|{NUMBER}
IPV6ADDR	([0-9a-f]{1,4}":"+){1,7}[0-9a-f]{1,4}

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	nf_parse_start_hn(nftext);
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}	nf_parse_start(nftext);
{DIGIT}{4}[ ]{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	nf_parse_start_hn(nftext+5);
{DIGIT}{4}[ ]{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}	nf_parse_start(nftext+5);
{DIGIT}{4}:{DIGIT}{2}:{DIGIT}{2}-{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	nf_parse_isostart_hn(nftext);
{DIGIT}{4}"-"{DIGIT}{2}"-"{DIGIT}{2}"T"{DIGIT}{2}":"{DIGIT}{2}":"{DIGIT}{2}"."{DIGIT}{6}("+"|"-"){DIGIT}{2}":"{DIGIT}{2}[ ]{LOGHOST}	nf_parse_rfc5424start_hn(nftext);
" kernel: ["[ ]{0,4}{NUMBER}"."{DIGIT}{6}"]"{PREFIX}{STRING}?	nf_parse_prefix(nftext+18, NF_OPT_PREFIX_KTIME);
" kernel: IN="{STRING}?					nf_parse_prefix(nftext+12, NF_OPT_NOPREFIX);
" kernel: "{PREFIX}{STRING}?				nf_parse_prefix(nftext+9, NF_OPT_PREFIX);
" [kernel] IN="{STRING}?				nf_parse_prefix(nftext+13, NF_OPT_NOPREFIX);
" [kernel] "{PREFIX}{STRING}?				nf_parse_prefix(nftext+10, NF_OPT_PREFIX);
" klogd: IN="{STRING}?					nf_parse_prefix(nftext+11, NF_OPT_NOPREFIX);
" klogd: "{PREFIX}{STRING}?				nf_parse_prefix(nftext+8, NF_OPT_PREFIX);
" "{PREFIX}{STRING}?					nf_parse_prefix(nftext+1, NF_OPT_PREFIX);
"IN="{STRING}?						nf_parse_prefix(nftext+3, NF_OPT_NOPREFIX);
"OUT="{STRING}?		/* ignore */
"PHYSIN="{STRING}?	/* ignore */
"PHYSOUT="{STRING}?	/* ignore */
"MAC="(({HEXDIGIT}{HEXDIGIT}:){21}{HEXDIGIT}{HEXDIGIT})?	/* ignore */
"MAC="(({HEXDIGIT}{HEXDIGIT}:){13}{HEXDIGIT}{HEXDIGIT})?	/* ignore */
"SRC="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	nf_parse_ip(nftext+4, NF_OPT_SRC);
"DST="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	nf_parse_ip(nftext+4, NF_OPT_DST);
"SRC="{IPV6ADDR}	nf_parse_ip(nftext+4, NF_OPT_SRC6);
"DST="{IPV6ADDR}	nf_parse_ip(nftext+4, NF_OPT_DST6);
"LEN="{NUMBER}		opt.line->datalen = atoi(nftext+4);
"TOS="({HEXNUM}|"00")	/* ignore */
"PREC="{HEXNUM}		/* ignore */
"TTL="{NUMBER}		/* ignore */
"ID="{NUMBER}		/* ignore */
"CE"			/* ignore */
"DF"			/* ignore */
"MF"			/* ignore */
"FRAG:"{NUMBER}		/* ignore */
"PROTO="{PROTO}		nf_parse_proto(nftext+6);
"INCOMPLETE ["{NUMBER}" bytes]"	/* ignore */
"TYPE="{NUMBER}		{ opt.line->sport = atoi(nftext+5); opt.parser=opt.parser|NF_TYPE; }
"CODE="{NUMBER}		{ opt.line->dport = atoi(nftext+5); opt.parser=opt.parser|NF_CODE; }
"PARAMETER="{NUMBER}	/* ignore */
"SEQ="{NUMBER}		/* ignore */
"MARK="{HEXNUM}		/* ignore */
"MARK=0"		/* ignore */
"ACK="{NUMBER}		/* ignore */
"SPT="{PORT}		{ opt.line->sport = atoi(nftext+4); opt.parser=opt.parser|NF_SPT; }
"DPT="{PORT}		{ opt.line->dport = atoi(nftext+4); opt.parser=opt.parser|NF_DPT; }
"WINDOW="{NUMBER}	/* ignore */
"RES="{HEXNUM}		/* ignore */
"URG"			opt.line->flags = opt.line->flags | TCP_URG;
"ACK"			opt.line->flags = opt.line->flags | TCP_ACK;
"PSH"			opt.line->flags = opt.line->flags | TCP_PSH;
"RST"			opt.line->flags = opt.line->flags | TCP_RST;
"SYN"			opt.line->flags = opt.line->flags | TCP_SYN;
"FIN"			opt.line->flags = opt.line->flags | TCP_FIN;
"ECE"			/* ignore */
"CWR"			/* ignore */
"URGP="{NUMBER}		/* ignore */
"OPT ("[0-9A-F]*")"	/* ignore */
"SPI="{HEXNUM}		/* ignore */
"GATEWAY="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	/* ignore */
"TC="{NUMBER}		/* ignore */
"HOPLIMIT="{NUMBER}	/* ignore */
"FLOWLBL="{NUMBER}	/* ignore */
"[".+"]"		/* ignore */
"MTU="{NUMBER}		/* ignore */
[ ]+			/* ignore whitespace */
[\n]			return 0;
{STRING}		if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", nftext);
.			if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", nftext);

%%

void nf_parse_start_hn(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[4];

  retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s", smonth, &day, &hour, &minute, &second, opt.line->hostname);
  if (retval != 6) {
    return;
  }

  build_time(smonth, day, hour, minute, second);

  opt.parser = opt.parser | NF_DATE;
}

void nf_parse_start(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[4];

  retval = sscanf(input, "%3s %2d %2d:%2d:%2d", smonth, &day, &hour, &minute, &second);
  if (retval != 5) {
    return;
  }

  build_time(smonth, day, hour, minute, second);
  xstrncpy(opt.line->hostname, "-", SHORTLEN);

  opt.parser = opt.parser | NF_DATE;
}

void nf_parse_isostart_hn(char *input)
{
  int retval, year, month, day, hour, minute, second;
  struct tm *t;

  retval = sscanf(input, "%4d:%2d:%2d-%2d:%2d:%2d %32s", &year, &month, &day, &hour, &minute, &second, opt.line->hostname);
  if (retval != 7) {
    return;
  }

  t = xmalloc(sizeof(struct tm));
  t->tm_year = year - 1900;
  t->tm_mon = month - 1;
  t->tm_mday = day;
  t->tm_hour = hour;
  t->tm_min = minute;
  t->tm_sec = second;
  t->tm_isdst = -1;
  opt.line->time = mktime(t);
  free(t);

  opt.parser = opt.parser | NF_DATE;
}

void nf_parse_rfc5424start_hn(char *input)
{
  int retval, year, month, day, hour, minute, second, fraction, tz_hour, tz_minute;
  struct tm *t;

  retval = sscanf(input, "%4d-%2d-%2dT%2d:%2d:%2d.%6d%3d:%2d %32s", &year, &month, &day, &hour, &minute, &second, &fraction, &tz_hour, &tz_minute, opt.line->hostname);
  if (retval != 10) {
    return;
  }

  t = xmalloc(sizeof(struct tm));
  t->tm_year = year - 1900;
  t->tm_mon = month - 1;
  t->tm_mday = day;
  t->tm_hour = hour;
  t->tm_min = minute;
  t->tm_sec = second;
  t->tm_isdst = -1;
  opt.line->time = mktime(t);
  free(t);

  opt.parser = opt.parser | NF_DATE;
}

void nf_parse_prefix(char *input, unsigned char mode)
{
  size_t i = 0;
  char *pnt;

  if (mode == NF_OPT_PREFIX_KTIME) {
    pnt = strchr(input, ']');
    pnt += 2;
  } else {
    pnt = input;
  }
  if (mode == NF_OPT_PREFIX || mode == NF_OPT_PREFIX_KTIME) {
    i = strlen(pnt);
    while (i > 0) {
      if (pnt[i] == '=') {
	if (pnt[i - 1] == 'N') {
	  if (pnt[i - 2] == 'I') {
	    pnt[i - 2] = '\0';
	    xstrncpy(opt.line->chainlabel, pnt, SHORTLEN);
	    xstrncpy(opt.line->interface, pnt + i + 1, SHORTLEN);
	    break;
	  }
	}
      }
      i--;
    }
  } else {
    xstrncpy(opt.line->chainlabel, "-", SHORTLEN);
    xstrncpy(opt.line->interface, pnt, SHORTLEN);
  }

  opt.parser = opt.parser | NF_IN;
}

void nf_parse_ip(char *input, unsigned char mode)
{
  if ((mode == NF_OPT_SRC) || (mode == NF_OPT_SRC6)) {
    if (convert_ip(input, &opt.line->shost) == IN_ADDR_ERROR)
      return;
    opt.parser = opt.parser | NF_SRC;
  } else {
    if (convert_ip(input, &opt.line->dhost) == IN_ADDR_ERROR)
      return;
    opt.parser = opt.parser | NF_DST;
  }
}

void nf_parse_proto(char *input)
{
  if (isdigit((int) input[0])) {
    opt.line->protocol = atoi(input);
  } else {
    if (strncmp(input, "TCP", 3) == 0)
      opt.line->protocol = 6;
    else if (strncmp(input, "UDP", 3) == 0)
      opt.line->protocol = 17;
    else if (strncmp(input, "ICMP", 4) == 0)
      opt.line->protocol = 1;
    else if (strncmp(input, "ESP", 3) == 0)
      opt.line->protocol = 50;
    else if (strncmp(input, "AH", 2) == 0)
      opt.line->protocol = 51;
    else if (strncmp(input, "ICMPv6", 6) == 0)
      opt.line->protocol = 58;
  }

  if (opt.line->protocol != 0)
    opt.parser = opt.parser | NF_PROTO;
}

unsigned char flex_netfilter(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  nf_scan_string(input);
  nflex();
  nf_delete_buffer(YY_CURRENT_BUFFER);

  xstrncpy(opt.line->branchname, "-", SHORTLEN);
  opt.line->count = 1;

  if (((opt.line->protocol == 6) || (opt.line->protocol == 17)) && (opt.parser == (NF_DATE | NF_PROTO | NF_IN | NF_SRC | NF_DST | NF_SPT | NF_DPT))) {
    return PARSE_OK;
  }
  if ((opt.line->protocol == 1) && (opt.parser == (NF_DATE | NF_PROTO | NF_IN | NF_SRC | NF_DST | NF_TYPE | NF_CODE))) {
    return PARSE_OK;
  }
  if (((opt.line->protocol == 2) || (opt.line->protocol == 9) || (opt.line->protocol == 41) || (opt.line->protocol == 46) || (opt.line->protocol == 47) || (opt.line->protocol == 50) || (opt.line->protocol == 54) || (opt.line->protocol == 103) || (opt.line->protocol == 139)) && (opt.parser == (NF_DATE | NF_PROTO | NF_IN | NF_SRC | NF_DST))) {
    return PARSE_OK;
  }
  if (opt.verbose)
    fprintf(stderr, "netfilter parse error in line %d, ignoring.\n", linenum);
  if (opt.verbose == 2)
    fprintf(stderr, "input was: \"%s\"\n", input);
  return PARSE_WRONG_FORMAT;
}
