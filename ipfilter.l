/* $Id: ipfilter.l,v 1.15 2003/06/23 15:26:53 bwess Exp $ */

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
STRING		[a-zA-Z0-9.,_-]*
LOGHOST		[0-9.a-zA-Z()_:-]*
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

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	ipf_parse_date(ipftext);
{IPFILTER}									/* ignore */
"[ID "{NUMBER}" "{STRING}"]"							/* ignore */
{DIGIT}{2}":"{DIGIT}{2}":"{DIGIT}{2}"."{DIGIT}{6}				/* ignore */
{STRING}[ ]"@"{NUMBER}":"{NUMBER}[ ]{TARGET}					ipf_parse_data(ipftext, IPF_OPT_NONE);
{NUMBER}"x"[ ]+{STRING}[ ]"@"{NUMBER}":"{NUMBER}[ ]{TARGET}			ipf_parse_data(ipftext, IPF_OPT_COUNT);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}						ipf_parse_ips(ipftext, IPF_OPT_SRC);
" -> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}					ipf_parse_ips(ipftext+4, IPF_OPT_DST);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}					ipf_parse_ips(ipftext, IPF_OPT_SRC|IPF_OPT_PORT);
" -> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}				ipf_parse_ips(ipftext+4, IPF_OPT_DST|IPF_OPT_PORT);
{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"]"				ipf_parse_ips(ipftext, IPF_OPT_SRC|IPF_OPT_RES);
" -> "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"]"			ipf_parse_ips(ipftext+4, IPF_OPT_DST|IPF_OPT_RES);
{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{PORT}			ipf_parse_ips(ipftext, IPF_OPT_SRC|IPF_OPT_RES|IPF_OPT_PORT);
" -> "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{PORT}		ipf_parse_ips(ipftext+4, IPF_OPT_DST|IPF_OPT_RES|IPF_OPT_PORT);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{STRING}				ipf_parse_ips(ipftext, IPF_OPT_SRC|IPF_OPT_RPORT);
" -> "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{STRING}				ipf_parse_ips(ipftext+4, IPF_OPT_DST|IPF_OPT_RPORT);
{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{STRING}			ipf_parse_ips(ipftext, IPF_OPT_SRC|IPF_OPT_RES|IPF_OPT_RPORT);
" -> "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{STRING}		ipf_parse_ips(ipftext+4, IPF_OPT_DST|IPF_OPT_RES|IPF_OPT_RPORT);
"PR "{PROTO}									ipf_parse_proto(ipftext+3);
"len "{NUMBER}[ ][(]?{NUMBER}[)]?						opt.line->datalen = atoi(ipftext+4);
"frag "{NUMBER}"@"{NUMBER}							/* ignore */
"icmp "{DIGIT}{1,2}"/"{DIGIT}{1,2}						sscanf(ipftext, "icmp %d/%d", &opt.line->sport, &opt.line->dport); opt.parser=opt.parser|IPF_SRC_PORT|IPF_DST_PORT;
"icmp echo/0"									opt.line->sport = 8; opt.line->dport = 0; opt.parser=opt.parser|IPF_SRC_PORT|IPF_DST_PORT;
"icmp sourcequench/0"								opt.line->sport = 4; opt.line->dport = 0; opt.parser=opt.parser|IPF_SRC_PORT|IPF_DST_PORT;
"icmp unreach/host"								opt.line->sport = 3; opt.line->dport = 1; opt.parser=opt.parser|IPF_SRC_PORT|IPF_DST_PORT;
"icmp unreach/port"								opt.line->sport = 3; opt.line->dport = 3; opt.parser=opt.parser|IPF_SRC_PORT|IPF_DST_PORT;
"icmp unreach/admin_prohibit"							opt.line->sport = 3; opt.line->dport = 10; opt.parser=opt.parser|IPF_SRC_PORT|IPF_DST_PORT;
"icmp timxceed/intrans"								opt.line->sport = 11; opt.line->dport = 1; opt.parser=opt.parser|IPF_SRC_PORT|IPF_DST_PORT;
"for "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}" - "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}" PR "{PROTO}" len "{NUMBER}[ ]{NUMBER}	/* ignore */
"for "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{STRING}" - "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{STRING}" PR "{PROTO}" len "{NUMBER}[ ]{NUMBER}	/* ignore */
"for "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{PORT}" - "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{PORT}" PR "{PROTO}" len "{NUMBER}[ ]{NUMBER}	/* ignore */
"for "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{PORT}" - "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}","{STRING}" PR "{PROTO}" len "{NUMBER}[ ]{NUMBER}	/* ignore */
"for "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"] - "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"] PR "{PROTO}" len "{NUMBER}" ("{NUMBER}")"	/* ignore */
"for "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{PORT}" - "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{PORT}" PR "{PROTO}" len "{NUMBER}[ ]{NUMBER}	/* ignore */
"for "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{PORT}" - "{STRING}"["{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"],"{STRING}" PR "{PROTO}" len "{NUMBER}[ ]{NUMBER}	/* ignore */
{FLAGS}										ipf_parse_flags(ipftext+1);
"K-S"										/* ignore */
"K-F"										/* ignore */
"IN"										/* ignore */
"OUT"										/* ignore */
{NUMBER}[ ]{NUMBER}[ ]{NUMBER}" IN"						/* ignore */
({HEXDIGIT}{HEXDIGIT}[ ]?)+[ ]+[ -~]+						opt.parser=opt.parser|IPF_NO_HIT;
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
    retval = sscanf(input, "%dx %" SHORTLEN_S "s @%" SHORTLEN_S "s %" SHORTLEN_S "s",
		    &opt.line->count,
		    opt.line->interface,
		    opt.line->chainlabel,
		    opt.line->branchname);
    if (retval != 4) return;
  } else {
    retval = sscanf(input, "%" SHORTLEN_S "s @%" SHORTLEN_S "s %" SHORTLEN_S "s",
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
  int host1, host2, host3, host4, port;
  int retval;
  char ip[IPLEN];

  if (mode == (IPF_OPT_SRC|IPF_OPT_RES|IPF_OPT_RPORT) || mode == (IPF_OPT_DST|IPF_OPT_RES|IPF_OPT_RPORT)) {
    char name[255], *ptr, portname[32];
    ptr = strchr(input, '['); *ptr = ' ';
    retval = sscanf(input, "%255s %3d.%3d.%3d.%3d],%32s",
		    name, &host1, &host2, &host3, &host4, portname);
    if(retval != 6) return;
  } else if (mode == (IPF_OPT_SRC|IPF_OPT_RES|IPF_OPT_PORT) || mode == (IPF_OPT_DST|IPF_OPT_RES|IPF_OPT_PORT)) {
    char name[255], *ptr;
    ptr = strchr(input, '['); *ptr = ' ';
    retval = sscanf(input, "%255s %3d.%3d.%3d.%3d],%5d",
		    name, &host1, &host2, &host3, &host4, &port);
    if(retval != 6) return;
  } else if (mode == (IPF_OPT_SRC|IPF_OPT_RES) || mode == (IPF_OPT_DST|IPF_OPT_RES)) {
    char name[255], *ptr;
    ptr = strchr(input, '['); *ptr = ' ';
    retval = sscanf(input, "%255s %3d.%3d.%3d.%3d]",
		    name, &host1, &host2, &host3, &host4);
    if(retval != 5) return;
  } else if (mode == (IPF_OPT_SRC|IPF_OPT_RPORT) || mode == (IPF_OPT_DST|IPF_OPT_RPORT)) {
    char portname[32];
    retval = sscanf(input, "%3d.%3d.%3d.%3d,%32s",
		    &host1, &host2, &host3, &host4, portname);
    if(retval != 5) return;
  } else if (mode == (IPF_OPT_SRC|IPF_OPT_PORT) || mode == (IPF_OPT_DST|IPF_OPT_PORT)) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d,%5d",
		    &host1, &host2, &host3, &host4, &port);
    if(retval != 5) return;
  } else if (mode == IPF_OPT_SRC || mode == IPF_OPT_DST) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d",
		    &host1, &host2, &host3, &host4);
    if(retval != 4) return;
  } else {
    return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", host1, host2, host3, host4);
  if(mode & IPF_OPT_SRC) {
    if(convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR) return;
    opt.parser=opt.parser|IPF_SRC_IP;
    if(mode & IPF_OPT_PORT) {
      opt.line->sport = port;
      opt.parser=opt.parser|IPF_SRC_PORT;
    }
  } else {
    if(convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR) return;
    opt.parser=opt.parser|IPF_DST_IP;
    if(mode & IPF_OPT_PORT) {
      opt.line->dport = port;
      opt.parser=opt.parser|IPF_DST_PORT;
    }
  }
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

  if (opt.parser == (IPF_DATE|IPF_DATA|IPF_PROTO|IPF_SRC_IP|IPF_DST_IP|IPF_SRC_PORT|IPF_DST_PORT)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "ipfilter parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
