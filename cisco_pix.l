/* Copyright (C) 2000-2011 Boris Wesslowski */
/* $Id: cisco_pix.l,v 1.18 2011/11/14 12:53:52 bwess Exp $ */

%option prefix="cisco_pix"
%option outfile="cisco_pix.c"
%option noyywrap

%{
#define YY_NO_INPUT

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include "main.h"
#include "utils.h"
#include "resolve.h"

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
HEXDIGIT	[0-9a-fA-F]
HEXNUMBER	"0x"{HEXDIGIT}+
IP	{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}
IPPORT	{IP}"/"{PORT}
ZONEIP	{STRING}":"{IP}
ZONENAME	{STRING}":"{STRING}
ZONEIPPORT	{STRING}":"{IP}"/"{PORT}
ZONEIPPORT2	{STRING}"/"{IP}"("{PORT}")"
ZONENAMEPORT	{STRING}":"{STRING}"/"{PORT}
ZONENAMEPORT2	{STRING}"/"{STRING}"("{PORT}")"
SYSID	("%PIX"|"%FWSM"|"%ASA")"-"[1-7]"-"[0-9]{6}":"

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	cisco_pix_parse_date(cisco_pixtext, CP_OPT_HOST);
{SYSID}										/* ignore */
{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{4}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}(":")?	cisco_pix_parse_date(cisco_pixtext, CP_OPT_NONE);
{LOGHOST}[ ]+": "								/* ignore */
" Inbound TCP connection denied from "{IPPORT}					cisco_pix_parse_src(cisco_pixtext+36, CP_OPT_TCP);
" TCP access denied by ACL from "{IPPORT}					cisco_pix_parse_src(cisco_pixtext+31, CP_OPT_TCP);
" Deny"										xstrncpy(opt.line->branchname, "Deny", SHORTLEN);
" TCP (no connection) from "{IPPORT}						cisco_pix_parse_src(cisco_pixtext+26, CP_OPT_TCP);
" inbound UDP from "{IPPORT}							cisco_pix_parse_src(cisco_pixtext+18, CP_OPT_UDP);
" udp src "{ZONEIPPORT}								cisco_pix_parse_src(cisco_pixtext+9, CP_OPT_UDP_S);
" udp src "{ZONENAMEPORT}							cisco_pix_parse_src(cisco_pixtext+9, CP_OPT_UDP_N);
" tcp src "{ZONEIPPORT}								cisco_pix_parse_src(cisco_pixtext+9, CP_OPT_TCP_S);
" tcp src "{ZONENAMEPORT}							cisco_pix_parse_src(cisco_pixtext+9, CP_OPT_TCP_N);
" icmp src "{ZONEIP}								cisco_pix_parse_src(cisco_pixtext+10, CP_OPT_ICMP_S);
" inbound icmp src "{ZONEIP}							cisco_pix_parse_src(cisco_pixtext+18, CP_OPT_ICMP_S);
" inbound tcp src "{ZONEIPPORT}							cisco_pix_parse_src(cisco_pixtext+17, CP_OPT_TCP_S);
" inbound (No xlate) tcp src "{ZONEIPPORT}					cisco_pix_parse_src(cisco_pixtext+28, CP_OPT_TCP_S);
" inbound (No xlate) udp src "{ZONEIPPORT}					cisco_pix_parse_src(cisco_pixtext+28, CP_OPT_UDP_S);
" inbound (No xlate) icmp src "{ZONEIP}						cisco_pix_parse_src(cisco_pixtext+29, CP_OPT_ICMP_S);
" UDP reverse path check from "{IP}						cisco_pix_parse_src(cisco_pixtext+29, CP_OPT_UDP_NOPORT);
{IP}" attempted to ping "							cisco_pix_parse_src(cisco_pixtext, CP_OPT_ICMP);
"to "{ZONEIPPORT}								cisco_pix_parse_dst(cisco_pixtext+3, CP_OPT_DST_S);
"to "{IPPORT}									cisco_pix_parse_dst(cisco_pixtext+3, CP_OPT_DST);
"to "{IP}									cisco_pix_parse_dst(cisco_pixtext+3, CP_OPT_NONE);
"dst "{ZONEIPPORT}								cisco_pix_parse_dst(cisco_pixtext+4, CP_OPT_DST_S);
"dst "{ZONENAMEPORT}								cisco_pix_parse_dst(cisco_pixtext+4, CP_OPT_DST_N);
"dst "{ZONEIP}" (type "{PORT}", code "{PORT}")"					cisco_pix_parse_dst(cisco_pixtext+4, CP_OPT_DST_I);
{IP}										cisco_pix_parse_dst(cisco_pixtext, CP_OPT_NONE);
"flags"										/* ignore */
"URG"										opt.line->flags = opt.line->flags | TCP_URG;
"ACK"										opt.line->flags = opt.line->flags | TCP_ACK;
"PSH"										opt.line->flags = opt.line->flags | TCP_PSH;
"RST"										opt.line->flags = opt.line->flags | TCP_RST;
"SYN"										opt.line->flags = opt.line->flags | TCP_SYN;
"FIN"										opt.line->flags = opt.line->flags | TCP_FIN;
"on interface "{STRING}								xstrncpy(opt.line->interface, cisco_pixtext+13, SHORTLEN);
"by access-group \""{STRING}"\""						cisco_pix_parse_group(cisco_pixtext+17);
"due to DNS "("Query"|"Response")						/* ignore */
"("{IP}")"									/* ignore */
" access-list "{STRING}								xstrncpy(opt.line->chainlabel, cisco_pixtext+13, SHORTLEN);
" permitted"									xstrncpy(opt.line->branchname, "permitted", SHORTLEN);
" denied"									xstrncpy(opt.line->branchname, "denied", SHORTLEN);
" tcp "{ZONEIPPORT2}								cisco_pix_parse_src(cisco_pixtext+5, CP_OPT_TCP_S2);
" udp "{ZONEIPPORT2}								cisco_pix_parse_src(cisco_pixtext+5, CP_OPT_UDP_S2);
" icmp "{ZONEIPPORT2}								cisco_pix_parse_src(cisco_pixtext+6, CP_OPT_ICMP_S2);
" tcp "{ZONENAMEPORT2}								cisco_pix_parse_src(cisco_pixtext+5, CP_OPT_TCP_N2);
" udp "{ZONENAMEPORT2}								cisco_pix_parse_src(cisco_pixtext+5, CP_OPT_UDP_N2);
" icmp "{ZONENAMEPORT2}								cisco_pix_parse_src(cisco_pixtext+6, CP_OPT_ICMP_N2);
" -> "{ZONEIPPORT2}								cisco_pix_parse_dst(cisco_pixtext+4, CP_OPT_DST_S2);
" -> "{ZONENAMEPORT2}								cisco_pix_parse_dst(cisco_pixtext+4, CP_OPT_DST_N2);
"hit-cnt "{NUMBER}								/* ignore */
" first hit"									/* ignore */
" "{NUMBER}"-second interval"							/* ignore */
" Built dynamic "("TCP"|"UDP"|"ICMP")" translation from "{ZONEIPPORT}" to "{ZONEIPPORT}	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Built "("inbound"|"outbound")" "("TCP"|"UDP")" connection "{NUMBER}" for "{ZONEIPPORT}" ("{IPPORT}") to "{ZONEIPPORT}" ("{IPPORT}")"	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Built static translation from "{ZONEIP}" to "{ZONEIP}				opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Built local-host "{ZONEIP}							opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Teardown dynamic "("TCP"|"UDP"|"ICMP")" translation from "{ZONEIPPORT}" to "{ZONEIPPORT}" duration "[0-9:]+	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Teardown "("TCP"|"UDP")" connection "{NUMBER}" for "{ZONEIPPORT}" to "{ZONEIPPORT}" duration "[0-9:]+" bytes "{NUMBER}(" TCP "("Reset-"("I"|"O")|"FINs")|" "("SYN"|"FIN")" Timeout")?	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" No translation group found for icmp src "({ZONEIP}|{ZONENAME})" dst "({ZONEIP}|{ZONENAME})" (type "{PORT}", code "{PORT}")"	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Teardown local-host "{ZONEIP}" duration "[0-9:]+				opt.parser=opt.parser|CISCO_PIX_NO_HIT;
{IP}" Accessed URL ".+								opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" IGRP request discarded from "{IP}" to "{ZONEIP}				opt.parser=opt.parser|CISCO_PIX_NO_HIT;
{NUMBER}" in use, "{NUMBER}" most used"						opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" No matching connection for ICMP error message: icmp src "({ZONEIP}|{ZONENAME})" dst "({ZONEIP}|{ZONENAME})" (type "{NUMBER}", code "{NUMBER}") on "{STRING}" interface.  Original IP payload: "(("udp"|"tcp"|"icmp"|"protocol "{NUMBER})" src "({IPPORT}|{STRING}"/"{PORT}|{IP}|{STRING})" dst "({IPPORT}|{STRING}"/"{PORT}|{IP}|{STRING})|"<unknown>")(" (type "{NUMBER}", code "{NUMBER}")")?"."	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" [".*"] drop rate-"{DIGIT}" exceeded. Current burst rate is "{NUMBER}" per second, max configured rate is "{NUMBER}"; Current average rate is "{NUMBER}" per second, max configured rate is "{NUMBER}"; Cumulative total count is "{NUMBER}	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Begin configuration: "({IP}|{STRING})" reading from http [POST]"		opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Group = "{STRING}", Username = "{STRING}", IP = "({IP}|{STRING})", ".*	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" Bad TCP hdr length (hdrlen=".*						opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" User '"{STRING}"', running '"("CLI"|"N/A")"' from IP "({IP}|{STRING})", executed '".*"'"	opt.parser=opt.parser|CISCO_PIX_NO_HIT;
" User '"{STRING}"' executed the '".*"' command."				opt.parser=opt.parser|CISCO_PIX_NO_HIT;
"["{HEXNUMBER}", "{HEXNUMBER}"]"						/* ignore */
[ ]+		/* ignore whitespace */
[\n]		/* ignore */
{STRING}	if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", cisco_pixtext);
.		if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", cisco_pixtext);

%%

void cisco_pix_parse_date(char *input, unsigned char mode)
{
  int retval, day, hour, minute, second;
  char smonth[4];
#ifdef IRIX
  char tmp[SHOSTLEN];
#endif
#ifdef LOGDOTS
  char *remove_dot;
#endif

  if (mode == CP_OPT_HOST) {
    retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s", smonth, &day, &hour, &minute, &second,
#ifndef IRIX
		    opt.line->hostname);
#else
		    tmp);
    if (retval != 6)
      return;
    if (tmp[2] == ':')
      xstrncpy(opt.line->hostname, tmp + 3, SHOSTLEN);
#endif
#ifdef LOGDOTS
    remove_dot = strstr(opt.line->hostname, ".");
    if (remove_dot != NULL)
      *remove_dot = '\0';
#endif
  } else if (mode == CP_OPT_NONE) {
    int year;
    retval = sscanf(input, "%3s %2d %4d %2d:%2d:%2d", smonth, &day, &year, &hour, &minute, &second);
    if (retval != 6)
      return;
  }

  build_time(smonth, day, hour, minute, second);

  opt.parser = opt.parser | CISCO_PIX_DATE;
}

void cisco_pix_parse_src(char *input, unsigned char mode)
{
  char ip[IPLEN], resolved = 0;
  int shost1, shost2, shost3, shost4;
  int retval;

  if ((mode == CP_OPT_TCP) || (mode == CP_OPT_UDP)) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d/%5d", &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    if (mode == CP_OPT_TCP)
      opt.line->protocol = 6;
    else
      opt.line->protocol = 17;
    if (retval != 5)
      return;
  } else if ((mode == CP_OPT_TCP_S) || (mode == CP_OPT_UDP_S)) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, ":");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d/%5d", buf, &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    if (mode == CP_OPT_TCP_S)
      opt.line->protocol = 6;
    else
      opt.line->protocol = 17;
    if (retval != 6)
      return;
  } else if ((mode == CP_OPT_TCP_S2) || (mode == CP_OPT_UDP_S2) || (mode == CP_OPT_ICMP_S2)) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, "/");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d(%5d)", buf, &shost1, &shost2, &shost3, &shost4, &opt.line->sport);
    if (mode == CP_OPT_TCP_S2)
      opt.line->protocol = 6;
    else if (mode == CP_OPT_UDP_S2)
      opt.line->protocol = 17;
    else
      opt.line->protocol = 1;
    if (retval != 6)
      return;
  } else if ((mode == CP_OPT_TCP_N) || (mode == CP_OPT_UDP_N)) {
    char buf[BUFSIZE], *pnt;
    struct in6_addr *ip;
    pnt = strstr(input, ":");
    *pnt = ' ';
    pnt = strstr(input, "/");
    *pnt = ' ';
    retval = sscanf(input, "%*s %" BUFSIZE_S "s %5d", buf, &opt.line->sport);
    if (mode == CP_OPT_TCP_N)
      opt.line->protocol = 6;
    else
      opt.line->protocol = 17;
    if (retval != 2)
      return;
    ip = resolve_hostname_from_cache(buf);
    if (ip != NULL) {
      memcpy(&opt.line->shost, ip, sizeof(struct in6_addr));
      resolved = 1;
    } else {
      if (opt.verbose)
	fprintf(stderr, "cisco_pix host '%s' could not be resolved, ignoring.\n", buf);
      return;
    }
  } else if ((mode == CP_OPT_TCP_N2) || (mode == CP_OPT_UDP_N2) || (mode == CP_OPT_ICMP_N2)) {
    char buf[BUFSIZE], *pnt;
    struct in6_addr *ip;
    pnt = strstr(input, "/");
    *pnt = ' ';
    pnt = strstr(input, "(");
    *pnt = ' ';
    pnt = strstr(input, ")");
    *pnt = 0;
    retval = sscanf(input, "%*s %" BUFSIZE_S "s %5d", buf, &opt.line->sport);
    if (mode == CP_OPT_TCP_N2)
      opt.line->protocol = 6;
    else if (mode == CP_OPT_UDP_N2)
      opt.line->protocol = 17;
    else
      opt.line->protocol = 1;
    if (retval != 2)
      return;
    ip = resolve_hostname_from_cache(buf);
    if (ip != NULL) {
      memcpy(&opt.line->shost, ip, sizeof(struct in6_addr));
      resolved = 1;
    } else {
      if (opt.verbose)
	fprintf(stderr, "cisco_pix host '%s' could not be resolved, ignoring.\n", buf);
      return;
    }
  } else if (mode == CP_OPT_ICMP_S) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, ":");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d", buf, &shost1, &shost2, &shost3, &shost4);
    opt.line->protocol = 1;
    if (retval != 5)
      return;
  } else if (mode == CP_OPT_ICMP) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d attempted to ping", &shost1, &shost2, &shost3, &shost4);
    opt.line->protocol = 1;
    if (retval != 4)
      return;
  } else if (mode == CP_OPT_UDP_NOPORT) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d", &shost1, &shost2, &shost3, &shost4);
    opt.line->protocol = 17;
    if (retval != 4)
      return;
  }

  if (resolved == 0) {
    snprintf(ip, IPLEN, "%d.%d.%d.%d", shost1, shost2, shost3, shost4);
    if (convert_ip(ip, &opt.line->shost) == IN_ADDR_ERROR)
      return;
  }

  opt.parser = opt.parser | CISCO_PIX_SRC;
}

void cisco_pix_parse_dst(char *input, unsigned char mode)
{
  char ip[IPLEN], resolved = 0;
  int dhost1, dhost2, dhost3, dhost4;
  int retval;

  if (mode == CP_OPT_DST) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d/%5d", &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if (retval != 5)
      return;
  } else if (mode == CP_OPT_DST_S) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, ":");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d/%5d", buf, &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if (retval != 6)
      return;
  } else if (mode == CP_OPT_DST_S2) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, "/");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d(%5d)", buf, &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->dport);
    if (retval != 6)
      return;
  } else if (mode == CP_OPT_DST_N) {
    char buf[BUFSIZE], *pnt;
    struct in6_addr *ip;
    pnt = strstr(input, ":");
    *pnt = ' ';
    pnt = strstr(input, "/");
    *pnt = ' ';
    retval = sscanf(input, "%*s %" BUFSIZE_S "s %5d", buf, &opt.line->dport);
    if (retval != 2)
      return;
    ip = resolve_hostname_from_cache(buf);
    if (ip != NULL) {
      memcpy(&opt.line->dhost, ip, sizeof(struct in6_addr));
      resolved = 1;
    } else {
      if (opt.verbose)
	fprintf(stderr, "cisco_pix host '%s' could not be resolved, ignoring.\n", buf);
      return;
    }
  } else if (mode == CP_OPT_DST_N2) {
    char buf[BUFSIZE], *pnt;
    struct in6_addr *ip;
    pnt = strstr(input, "/");
    *pnt = ' ';
    pnt = strstr(input, "(");
    *pnt = ' ';
    pnt = strstr(input, ")");
    *pnt = 0;
    retval = sscanf(input, "%*s %" BUFSIZE_S "s %5d", buf, &opt.line->dport);
    if (retval != 2)
      return;
    ip = resolve_hostname_from_cache(buf);
    if (ip != NULL) {
      memcpy(&opt.line->dhost, ip, sizeof(struct in6_addr));
      resolved = 1;
    } else {
      if (opt.verbose)
	fprintf(stderr, "cisco_pix host '%s' could not be resolved, ignoring.\n", buf);
      return;
    }
  } else if (mode == CP_OPT_DST_I) {
    char buf[BUFSIZE], *pnt;
    pnt = strstr(input, ":");
    *pnt = ' ';
    retval = sscanf(input, "%" BUFSIZE_S "s %3d.%3d.%3d.%3d (type %5d, code %5d)", buf, &dhost1, &dhost2, &dhost3, &dhost4, &opt.line->sport, &opt.line->dport);
    if (retval != 7)
      return;
  } else if (mode == CP_OPT_NONE) {
    retval = sscanf(input, "%3d.%3d.%3d.%3d", &dhost1, &dhost2, &dhost3, &dhost4);
    if (retval != 4)
      return;
  }

  if (resolved == 0) {
    snprintf(ip, IPLEN, "%d.%d.%d.%d", dhost1, dhost2, dhost3, dhost4);
    if (convert_ip(ip, &opt.line->dhost) == IN_ADDR_ERROR)
      return;
  }

  opt.parser = opt.parser | CISCO_PIX_DST;
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
  xstrncpy(opt.line->branchname, "-", SHORTLEN);
  opt.line->count = 1;

  cisco_pix_scan_string(input);
  cisco_pixlex();
  cisco_pix_delete_buffer(YY_CURRENT_BUFFER);

  if (opt.parser & CISCO_PIX_NO_HIT)
    return PARSE_NO_HIT;

  if (opt.parser == (CISCO_PIX_DATE | CISCO_PIX_SRC | CISCO_PIX_DST)) {
    return PARSE_OK;
  } else {
    if (opt.verbose)
      fprintf(stderr, "cisco_pix parse error in line %d, ignoring.\n", linenum);
    if (opt.verbose == 2)
      fprintf(stderr, "input was: \"%s\"\n", input);
    return PARSE_WRONG_FORMAT;
  }
}
