/* $Id: cisco_pix.l,v 1.14 2003/06/23 15:26:53 bwess Exp $ */

%option prefix="cisco_pix"
%option outfile="cisco_pix.c"
%option noyywrap

%{
#define YY_NO_UNPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "utils.h"

extern struct options opt;

void cisco_pix_parse_date(char *input, unsigned char mode);
void cisco_pix_parse_src(char *input, unsigned char mode);
void cisco_pix_parse_dst(char *input, unsigned char mode);
void cisco_pix_parse_group(char *input);
%}

MONTH	"Jan"|"Feb"|"Mar"|"Apr"|"May"|"Jun"|"Jul"|"Aug"|"Sep"|"Oct"|"Nov"|"Dec"
STRING	[a-zA-Z][a-zA-Z0-9._-]*
LOGHOST	[0-9.a-zA-Z()_:-]*
DIGIT	[0-9]
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
PIX	"%PIX-"[1-6]"-"[0-9]{6}":"

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}		cisco_pix_parse_date(cisco_pixtext, CP_OPT_HOST);
{PIX}											/* ignore */
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{4}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}":"		cisco_pix_parse_date(cisco_pixtext, CP_OPT_NONE);
" Inbound TCP connection denied from "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}	cisco_pix_parse_src(cisco_pixtext+36, CP_OPT_TCP);
" Deny TCP (no connection) from "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}		cisco_pix_parse_src(cisco_pixtext+31, CP_OPT_TCP);
" Deny inbound UDP from "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}			cisco_pix_parse_src(cisco_pixtext+23, CP_OPT_UDP);
" Deny udp src "{STRING}":"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}		cisco_pix_parse_src(cisco_pixtext+14, CP_OPT_UDP_S);
" Deny tcp src "{STRING}":"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}		cisco_pix_parse_src(cisco_pixtext+14, CP_OPT_TCP_S);
" Deny inbound tcp src "{STRING}":"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}	cisco_pix_parse_src(cisco_pixtext+22, CP_OPT_TCP_S);
" Deny inbound (No xlate) tcp src "{STRING}":"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}	cisco_pix_parse_src(cisco_pixtext+33, CP_OPT_TCP_S);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" attempted to ping "				cisco_pix_parse_src(cisco_pixtext, CP_OPT_ICMP);
"to "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}					cisco_pix_parse_dst(cisco_pixtext+3, CP_OPT_DST);
"dst "{STRING}":"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"/"{PORT}				cisco_pix_parse_dst(cisco_pixtext+4, CP_OPT_DST_S);
{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}							cisco_pix_parse_dst(cisco_pixtext, CP_OPT_NONE);
"flags"											/* ignore */
"URG"											opt.line->flags = opt.line->flags | TCP_URG;
"ACK"											opt.line->flags = opt.line->flags | TCP_ACK;
"PSH"											opt.line->flags = opt.line->flags | TCP_PSH;
"RST"											opt.line->flags = opt.line->flags | TCP_RST;
"SYN"											opt.line->flags = opt.line->flags | TCP_SYN;
"FIN"											opt.line->flags = opt.line->flags | TCP_FIN;
"on interface "{STRING}									xstrncpy(opt.line->interface, cisco_pixtext+13, SHORTLEN);
"by access-group \""{STRING}"\""							cisco_pix_parse_group(cisco_pixtext+17);
"due to DNS "("Query"|"Response")							/* ignore */
"("{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}")"						/* ignore */
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", cisco_pixtext);
.		if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", cisco_pixtext);

%%

void cisco_pix_parse_date(char *input, unsigned char mode)
{
  int retval, day, hour, minute, second;
  char smonth[3];
#ifdef IRIX
  char tmp[SHOSTLEN];
#endif
#ifdef LOGDOTS
  char *remove_dot;
#endif

  if (mode == CP_OPT_HOST) {
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
  } else if (mode == CP_OPT_NONE) {
    int year;
    retval = sscanf(input, "%3s %2d %4d %2d:%2d:%2d:",
		    smonth, &day, &year, &hour, &minute, &second);
    if(retval != 5) return;
  }

  build_time(smonth, day, hour, minute, second);

  opt.parser=opt.parser|CISCO_PIX_DATE;
}

void cisco_pix_parse_src(char *input, unsigned char mode)
{
  char ip[IPLEN];
  int shost1, shost2, shost3, shost4;
  int retval;

  if ((mode == CP_OPT_TCP) || (mode == CP_OPT_UDP)) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d/%5d",
		    &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    if (mode == CP_OPT_TCP)
      opt.line->protocol = 6;
    else
      opt.line->protocol = 17;
    if(retval != 5) return;
  } else if ((mode == CP_OPT_TCP_S) || (mode == CP_OPT_UDP_S)) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, ":");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d/%5d",
		    buf, &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    if (mode == CP_OPT_TCP_S)
      opt.line->protocol = 6;
    else
      opt.line->protocol = 17;
    if(retval != 6) return;
  } else if (mode == CP_OPT_ICMP) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d attempted to ping",
		    &shost1, &shost2, &shost3, &shost4);
    opt.line->protocol = 1;
    if(retval != 4) return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
  if(convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_PIX_SRC;
}

void cisco_pix_parse_dst(char *input, unsigned char mode)
{
  char ip[IPLEN];
  int dhost1, dhost2, dhost3, dhost4;
  int retval;

  if (mode == CP_OPT_DST) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d/%5d",
		    &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if(retval != 5) return;
  } else if (mode == CP_OPT_DST_S) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, ":");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d/%5d",
		    buf, &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if(retval != 6) return;
  } else if (mode == CP_OPT_NONE) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d",
		    &dhost1, &dhost2, &dhost3, &dhost4);
    if(retval != 4) return;
  }

  snprintf(ip, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
  if(convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR) return;

  opt.parser=opt.parser|CISCO_PIX_DST;
}

void cisco_pix_parse_group(char *input)
{
  char *pnt;

  pnt = strstr(input, "\"");
  *pnt = '\0';
  xstrncpy(opt.line->chainlabel, input, SHORTLEN);
}

unsigned char flex_cisco_pix(char *input, int linenum)
{
  opt.parser = 0;

  init_line();

  xstrncpy(opt.line->interface, "-", SHORTLEN);
  xstrncpy(opt.line->chainlabel, "-", SHORTLEN);
  xstrncpy(opt.line->branchname, "Deny", SHORTLEN);
  opt.line->count = 1;

  cisco_pix_scan_string(input);
  cisco_pixlex();

  if (opt.parser == (CISCO_PIX_DATE|CISCO_PIX_SRC|CISCO_PIX_DST)) {
    return PARSE_OK;
  } else {
    if(opt.verbose)
      fprintf(stderr, "cisco pix log parse error in line %d, ignoring.\n", linenum);
    return PARSE_WRONG_FORMAT;
  }
}
