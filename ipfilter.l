/* $Id: ipfilter.l,v 1.5 2002/02/14 21:36:53 bwess Exp $ */

%option prefix="ipf"
%option outfile="ipfilter.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void ipf_parse_date(char *input);
void ipf_parse_data(char *input, unsigned char mode);
void ipf_parse_ips(char *input, unsigned char mode);
void ipf_parse_proto(char *input);
void ipf_parse_flags(char *input);
%}

MONTH		"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING		[a-zA-Z-][a-zA-Z0-9.,_-]*
LOGHOST		[0-9.a-zA-Z_-]*
DIGIT		[0-9]
NUMBER		{DIGIT}+
HEXDIGIT	[0-9a-f]
OCTET		{DIGIT}{1,3}
PORT		{DIGIT}{1,5}
IPFILTER	"ipmon["{NUMBER}"]:"
FLAGS		"-"[SAFRPU]+
PROTO		[0-9a-z-]+
TARGET		[SpPbBnL]

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}				ipf_parse_date(ipftext);
{IPFILTER}												/* ignore */
("[ID "{NUMBER}" "{STRING}"]")?										/* ignore */
{DIGIT}{2}":"{DIGIT}{2}":"{DIGIT}{2}"."{DIGIT}{6}							/* ignore */
{STRING}[ ]"@"{NUMBER}":"{NUMBER}[ ]{TARGET}								ipf_parse_data(ipftext, IPF_OPT_NONE);
{NUMBER}"x"[ ]+{STRING}[ ]"@"{NUMBER}":"{NUMBER}[ ]{TARGET}						ipf_parse_data(ipftext, IPF_OPT_COUNT);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}" -> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}	ipf_parse_ips(ipftext, IPF_OPT_PORTS);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" -> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}			ipf_parse_ips(ipftext, IPF_OPT_NONE);
{STRING}" -> "{STRING}											opt.parser=opt.parser|IPF_NO_HIT;
"PR "{PROTO}												ipf_parse_proto(ipftext+3);
"len "{NUMBER}[ ][(]?{NUMBER}[)]?									opt.line->datalen = atoi(ipftext+4);
"frag "{NUMBER}"@"{NUMBER}										/* ignore */
"icmp "{DIGIT}{1,2}"/"{DIGIT}{1,2}									sscanf(ipftext, "icmp %d/%d", &opt.line->sport, &opt.line->dport);
"for "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}" - "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}" PR "{PROTO}" len "{NUMBER}[ ]{NUMBER}	/* ignore */
{FLAGS}													ipf_parse_flags(ipftext+1);
"K-S"													/* ignore */
"K-F"													/* ignore */
"IN"													/* ignore */
"OUT"													/* ignore */
{NUMBER}[ ]{NUMBER}[ ]{NUMBER}" IN"									/* ignore */
({HEXDIGIT}{HEXDIGIT}[ ]?)+[ ]+[ -~]+									opt.parser=opt.parser|IPF_NO_HIT;
[ \t]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", ipftext);
.		if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", ipftext);

%%

void ipf_parse_date(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[3];

  retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s",
		  smonth, &day, &hour, &minute, &second,
		  opt.line->hostname);
  if (retval != 6) return;

  build_time(smonth, day, hour, minute, second);

  opt.parser=opt.parser|IPF_DATE;
}

void ipf_parse_data(char *input, unsigned char mode)
{
  int retval;

  if (mode == IPF_OPT_COUNT) {
#ifndef SHORT_NAMES
    retval = sscanf(input, "%dx %30s @%30s %30s",
#else
    retval = sscanf(input, "%dx %10s @%10s %10s",
#endif
		    &opt.line->count,
		    opt.line->interface,
		    opt.line->chainlabel,
		    opt.line->branchname);
    if (retval != 4) return;
  } else {
#ifndef SHORT_NAMES
    retval = sscanf(input, "%30s @%30s %30s",
#else
    retval = sscanf(input, "%10s @%10s %10s",
#endif
		    opt.line->interface,
		    opt.line->chainlabel,
		    opt.line->branchname);
    if (retval != 3) return;

    opt.line->count = 1;
  }

  opt.parser=opt.parser|IPF_DATA;
}

void ipf_parse_ips(char *input, unsigned char mode)
{
  int shost1, shost2, shost3, shost4;
  int dhost1, dhost2, dhost3, dhost4;
  int retval;
  char ip[IPLEN];

  if (mode == IPF_OPT_PORTS) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d,%5d -> %3d.%3d.%3d.%3d,%5d",
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport,
		    &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if(retval != 10) return;
  } else {
    retval = sscanf(input, "%3d.%3d.%3d.%3d -> %3d.%3d.%3d.%3d",
		    &shost1, &shost2, &shost3, &shost4,
		    &dhost1, &dhost2, &dhost3, &dhost4);
    if(retval != 8) return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  if(convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR) return;

  snprintf(ip, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
  if(convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|IPF_IPS;
}

void ipf_parse_proto(char *input)
{
  if(isdigit((int)input[0])) {
    opt.line->protocol = atoi(input);
  } else {
    struct protoent *proto;

    proto = getprotobyname(input);
    if (proto != NULL)
      opt.line->protocol = proto->p_proto;
  }

  if (opt.line->protocol != 0) {
    opt.parser=opt.parser|IPF_PROTO;
  } else {
    fprintf(stderr, "Unknown protocol (not in /etc/protocols), ignoring: %s\n", input);
    opt.parser=opt.parser|IPF_NO_HIT;
  }
}

void ipf_parse_flags(char *input)
{
  while (*input != '\0') {
    if(*input == 'S') opt.line->flags = opt.line->flags | TCP_SYN;
    if(*input == 'A') opt.line->flags = opt.line->flags | TCP_ACK;
    if(*input == 'F') opt.line->flags = opt.line->flags | TCP_FIN;
    if(*input == 'R') opt.line->flags = opt.line->flags | TCP_RST;
    if(*input == 'P') opt.line->flags = opt.line->flags | TCP_PSH;
    if(*input == 'U') opt.line->flags = opt.line->flags | TCP_URG;
    input++;
  }
}

unsigned char flex_ipfilter(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  ipf_scan_string(input);
  ipflex();

  if (opt.parser & IPF_NO_HIT)
    return PARSE_NO_HIT;

  if (opt.parser == (IPF_DATE|IPF_DATA|IPF_PROTO|IPF_IPS)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "ipfilter parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
