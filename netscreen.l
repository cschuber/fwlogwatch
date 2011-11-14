/* Copyright (C) 2000-2011 Boris Wesslowski */
/* $Id: netscreen.l,v 1.8 2011/11/14 12:53:52 bwess Exp $ */

%option prefix="ns"
%option outfile="netscreen.c"
%option noyywrap

%{
#define YY_NO_INPUT

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
NUMBER	{DIGIT}+
OCTET	{DIGIT}{1,3}
PORT	{DIGIT}{1,5}
PARAM	[A-Za-z0-9/:-]+(" ("[A-Za-z ]+")")?

%%

{MONTH}[ ]{1,2}{DIGIT}{1,2}[ ]{DIGIT}{2}:{DIGIT}{2}:{DIGIT}{2}[ ]{LOGHOST}	ns_parse_date(nstext);
{STRING}": NetScreen"	/* ignore */
"device_id="{STRING}	/* ignore */
("["[a-zA-Z0-9 ]*"]")?"system-information-"{NUMBER}":"	/* ignore */
("["[a-zA-Z0-9 ]*"]")?"system-notification-"{NUMBER}("(traffic)")?":"	/* ignore */
("["[a-zA-Z0-9 ]*"]")?"system-warning-"{NUMBER}":"	/* ignore */
"start_time=\""{DIGIT}{4}"-"{DIGIT}{2}"-"{DIGIT}{2}[ ]{DIGIT}{2}":"{DIGIT}{2}":"{DIGIT}{2}"\""	/* ignore */
"duration="{NUMBER}	/* ignore */
"policy_id="{NUMBER}	/* ignore */
"service="({PARAM}|"Network Time"|"VDO Live (tcp)")	/* ignore */
"proto="{NUMBER}	{opt.line->protocol=atoi(nstext+6); opt.parser=opt.parser|NS_PROTO;}
"direction="{STRING}	/* ignore */
"src zone="{STRING}	/* ignore */
"dst zone="{STRING}	/* ignore */
"action="{PARAM}	{xstrncpy(opt.line->branchname,nstext+7,SHORTLEN); opt.parser=opt.parser|NS_BN;}
"sent="{NUMBER}		opt.line->datalen=opt.line->datalen+atoi(nstext+5);
"rcvd="{NUMBER}		opt.line->datalen=opt.line->datalen+atoi(nstext+5);
"src="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	ns_parse_ip(nstext+4,NETSCREEN_OPT_SRC);
"dst="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}	ns_parse_ip(nstext+4,NETSCREEN_OPT_DST);
"src_port="{PORT}	{opt.line->sport=atoi(nstext+9); opt.parser=opt.parser|NS_SPORT;}
"dst_port="{PORT}	{opt.line->dport=atoi(nstext+9); opt.parser=opt.parser|NS_DPORT;}
"icmp type="{NUMBER}	{opt.line->sport=atoi(nstext+10); opt.line->sport=0; opt.parser=opt.parser|NS_SPORT|NS_DPORT;}
"translated ip="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" port="{PORT}	/* ignore */
"src-xlated ip="{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" port="{PORT}	/* ignore */
"IKE<"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}">"	opt.parser=opt.parser|NS_NO_HIT;
": XAuth login expired and was terminated for username <"[A-Za-z0-9@\.]*"> at <"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}">."	/* ignore */
": XAuth login "("failed"|"was aborted")" for gateway <"[A-Za-z0-9 _-]*">, username <"[A-Za-z0-9@\.]*">, retry: "{NUMBER}(", timeout: "{NUMBER})?"."	/* ignore */
">> <"{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}"> Phase 1: Initiated negotiations in main mode." /* ignore */
"Phase 1: Aborted negotiations because the time limit has elapsed."(" ("[0-9a-f/]*")")?	/* ignore */
"Phase 1: Completed "("Aggressive"|"Main")" mode negotiations with a <"{NUMBER}">-second lifetime."	/* ignore */
"Phase 1: Completed for user <"[A-Za-z0-9 _-]*">."	/* ignore */
"Phase 1: IKE responder has detected NAT in front of the remote device."	/* ignore */
"Phase 1: Responder starts "("AGGRESSIVE"|"MAIN")" mode negotiations."	/* ignore */
"Phase 2: Initiated negotiations."	/* ignore */
"Phase 2 msg"(" ID"|"-id")" <"[0-9a-f]*">: Completed negotiations with SPI <"[0-9a-f]*">, tunnel ID <"{NUMBER}">, and lifetime <"{NUMBER}"> seconds/<"{NUMBER}"> KB."	/* ignore */
"Phase 2 msg"(" ID"|"-id")" <"[0-9a-f]*">: Responded to the"(" peer's")?" first"(" peer")?" message."	/* ignore */
": Received a notification message for ".*	/* ignore */
"last message repeated "{NUMBER}" time"("s")?	opt.parser=opt.parser|NS_NO_HIT; /* only enters parser when last entry was IKE */
"The system clock has been updated through NTP."	opt.parser=opt.parser|NS_NO_HIT;
"Admin user "[A-Za-z0-9\"]+" "("has ")?"log"("in attempt"|"ged "[io]"n"|"ged out")" "("for Web(http) management (port 80)"|"via Telnet")" from "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}":"{PORT}(" failed.")?	opt.parser=opt.parser|NS_NO_HIT;
"Save configuration to IP address "{OCTET}"."{OCTET}"."{OCTET}"."{OCTET}" under filename "[A-Za-z0-9@\.]+" by administrator by admin "[A-Za-z0-9]+	opt.parser=opt.parser|NS_NO_HIT;
"Lock configuration ended by task "[A-Za-z0-9:-]+	opt.parser=opt.parser|NS_NO_HIT;
"("[0-9: -]{19}")"	/* ignore */
[ ]+			/* ignore whitespace */
[\n]			return 0;
{STRING}		if(opt.verbose) fprintf(stderr, "Unrecognized token: %s\n", nstext);
.			if(opt.verbose) fprintf(stderr, "Unrecognized character: %s\n", nstext);

%%

void ns_parse_date(char *input)
{
  int retval, day, hour, minute, second;
  char smonth[4];

  retval = sscanf(input, "%3s %2d %2d:%2d:%2d %32s", smonth, &day, &hour, &minute, &second, opt.line->hostname);
  if (retval != 6) {
    return;
  }

  build_time(smonth, day, hour, minute, second);

  opt.parser = opt.parser | NS_DATE;
}

void ns_parse_ip(char *input, unsigned char mode)
{
  if (mode == NETSCREEN_OPT_SRC) {
    if (convert_ip(input, &opt.line->shost) == IN_ADDR_ERROR)
      return;
    opt.parser = opt.parser | NS_SRC;
  } else {
    if (convert_ip(input, &opt.line->dhost) == IN_ADDR_ERROR)
      return;
    opt.parser = opt.parser | NS_DST;
  }
}

unsigned char flex_netscreen(char *input, int linenum)
{
  opt.parser = 0;
  init_line();
  ns_scan_string(input);
  nslex();
  ns_delete_buffer(YY_CURRENT_BUFFER);

  xstrncpy(opt.line->chainlabel, "-", SHORTLEN);
  xstrncpy(opt.line->interface, "-", SHORTLEN);
  opt.line->count = 1;

  if (opt.parser & NS_NO_HIT)
    return PARSE_NO_HIT;

  if (opt.parser == (NS_DATE | NS_SRC | NS_DST | NS_SPORT | NS_DPORT | NS_BN | NS_PROTO)) {
    return PARSE_OK;
  } else {
    if (opt.verbose)
      fprintf(stderr, "netscreen parse error in line %d, ignoring.\n", linenum);
    if (opt.verbose == 2)
      fprintf(stderr, "input was: \"%s\"\n", input);
    return PARSE_WRONG_FORMAT;
  }
}
