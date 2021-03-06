/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: ipchains.l,v 1.21 2016/02/19 16:09:27 bwess Exp $ */

%option prefix="ipchains"
%option outfile="ipchains.c"
%option noyywrap

%{
#define YY_NO_INPUT

#include <unistd.h>
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
STRING	[a-zA-Z-][a-zA-Z0-9._-]*
LOGHOST	[0-9.a-zA-Z()_:-]*
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
"L="{NUMBER}	opt.line->datalen = atoi(ipchainstext+2);
"S="{HEXNUM}	/* ignore */
"I="{NUMBER}	/* ignore */
"F="{HEXNUM}	/* ignore */
"T="{NUMBER}	/* ignore */
"O="{HEXNUM}	/* ignore */
"SYN"		opt.line->flags = TCP_SYN;
"(#"{NUMBER}")"	/* ignore */
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", ipchainstext);
.		if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", ipchainstext);

%%

void ipchains_parse_date(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[4];

  retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s", smonth, &day, &hour, &minute, &second, opt.line->hostname);
  if (retval != 6)
    return;

  build_time(smonth, day, hour, minute, second);

  opt.parser = opt.parser | IPCHAINS_DATE;
}

void ipchains_parse_data(char *input)
{
  int retval;

  retval = sscanf(input, "%" SHORTLEN_S "s %" SHORTLEN_S "s %" SHORTLEN_S "s PROTO=%3d", opt.line->chainlabel, opt.line->branchname, opt.line->interface, &opt.line->protocol);
  if (retval != 4)
    return;

  opt.parser = opt.parser | IPCHAINS_DATA;
}

void ipchains_parse_rdata(char *input)
{
  int retval, port;

  retval = sscanf(input, "%" SHORTLEN_S "s REDIRECT %5d %" SHORTLEN_S "s PROTO=%3d", opt.line->chainlabel, &port, opt.line->interface, &opt.line->protocol);
  if (retval != 4)
    return;

  snprintf(opt.line->branchname, SHORTLEN, "RD %d", port);

  opt.parser = opt.parser | IPCHAINS_DATA;
}

void ipchains_parse_ips(char *input)
{
  int shost1, shost2, shost3, shost4;
  int dhost1, dhost2, dhost3, dhost4;
  int retval;
  char ip[IPLEN];

  retval = sscanf(input, "%3d.%3d.%3d.%3d:%5d %3d.%3d.%3d.%3d:%5d", &shost1, &shost2, &shost3, &shost4, &opt.line->sport, &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
  if (retval != 10)
    return;

  snprintf(ip, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  if (convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR)
    return;

  snprintf(ip, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
  if (convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR)
    return;

  opt.parser = opt.parser | IPCHAINS_IPS;
}

unsigned char flex_ipchains(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  ipchains_scan_string(input);
  ipchainslex();
  ipchains_delete_buffer(YY_CURRENT_BUFFER);

  opt.line->count = 1;

  if (opt.parser == (IPCHAINS_DATE | IPCHAINS_DATA | IPCHAINS_IPS)) {
    return PARSE_OK;
  } else {
    if (opt.verbose)
      fprintf(stderr, "ipchains parse error in line %d, ignoring.\n", linenum);
    if (opt.verbose == 2)
      fprintf(stderr, "input was: \"%s\"\n", input);
    return PARSE_WRONG_FORMAT;
  }
}
