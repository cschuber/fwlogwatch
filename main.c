/* $Id: main.c,v 1.16 2002/02/14 21:26:30 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "main.h"
#include "rcfile.h"
#include "parser.h"
#include "modes.h"
#include "utils.h"

struct options opt;
extern char *optarg;

void usage(char *me, unsigned char exitcode)
{
  printf("%s %s (C) %s\n", PACKAGE, VERSION, COPYRIGHT);
  printf("Usage: %s [options]\n", me);
  printf("Global options:\n");
  printf("         -c <file>   specify config file (defaults to %s)\n", RCFILE);
  printf("         -D          do not differentiate destination IP addresses\n");
  printf("         -d          differentiate destination ports\n");
  printf("         -f <file>   specify input file (defaults to %s)\n", INFILE);
  printf("         -h          this help\n");
  printf("         -L <file>   show time of first and last log entry in file\n");
  printf("         -l <time>   process recent events only (defaults to off)\n");
  printf("         -n          resolve host names\n");
  printf("         -P <format> use only parsers for specific formats\n");
  printf("         -p          differentiate protocols\n");
  printf("         -S          do not differentiate source IP addresses\n");
  printf("         -s          differentiate source ports\n");
  printf("         -t          show start and end times\n");
  printf("         -V          show version and copyright info\n");
  printf("         -v          verbose, specify twice for more info\n");
  printf("         -y          differentiate TCP options\n");
  printf("         -z          show time interval\n");
  printf("\n");

  printf("Log summary mode (default):\n");
  printf("         -b          show amount of data (sum of total packet lengths)\n");
  printf("         -m <count>  only show entries with at least so many incidents\n");
  printf("         -o <file>   specify output file\n");
  printf("         -O <order>  define the sort order (see the man page for details)\n");
  printf("         -w          HTML output\n");
  printf("\n");

  printf("Interactive report mode:\n");
  printf("         -i <count>  interactive mode with report threshold\n");
  printf("         -F <email>  report sender address\n");
  printf("                     (defaults to '%s')\n", opt.sender);
  printf("         -T <email>  address of CERT or abuse contact to send report to\n");
  printf("         -C <email>  carbon copy recipients\n");
  printf("         -I <file>   template file for report\n");
  printf("                     (defaults to %s)\n", TEMPLATE);
  printf("\n");

  printf("Realtime response mode:\n");
  printf("         -R          realtime response as daemon (default action: log only)\n");
  printf("         -a <count>  alert threshold (defaults to %d entries)\n", ALERT);
  printf("         -l <time>   forget events this old (defaults to %d hours)\n", FORGET/3600);
  printf("         -k <IP/net> add this IP address or net to the list of known hosts\n");
  printf("         -A          invoke notification script if threshold is reached\n");
  printf("         -B          invoke response action script (e.g. block host)\n");
  printf("         -X          activate internal status information web server\n");
  printf("\n");

  exit(exitcode);
}

void info()
{
  /* GNU standards compatible program info */
  printf("%s %s\n", PACKAGE, VERSION);
  puts("Copyright (C) 2000,2001 Boris Wesslowski, RUS-CERT");
  puts("");
  puts("This program is free software; you can redistribute it and/or modify");
  puts("it under the terms of the GNU General Public License as published by");
  puts("the Free Software Foundation; either version 2 of the License, or");
  puts("(at your option) any later version.");
  puts("");
  puts("This program is distributed in the hope that it will be useful,");
  puts("but WITHOUT ANY WARRANTY; without even the implied warranty of");
  puts("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the");
  puts("GNU General Public License for more details.");
  puts("");
  puts("You should have received a copy of the GNU General Public License");
  puts("along with this program; if not, write to the Free Software");
  puts("Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA");
  puts("");
  puts("You can contact the author at <Boris.Wesslowski@RUS.Uni-Stuttgart.DE>.");

  exit(EXIT_SUCCESS);
}

void init_options()
{
  char *user, host[SHOSTLEN];
#ifndef SOLARIS
  char domain[SHOSTLEN];
#endif
  int retval;

  opt.mode = LOG_SUMMARY;

  opt.verbose = 0;
  opt.resolve = 0;
  strncpy(opt.inputfile, INFILE, FILESIZE);

  opt.line = NULL;
  opt.format_sel[0] = '\0';
  opt.format = PARSER_IPCHAINS|PARSER_NETFILTER|PARSER_CISCO_IOS|PARSER_CISCO_PIX|PARSER_IPFILTER;
  opt.parser = 0;
  opt.repeated = 0;
  opt.orig_count = 0;

  opt.src_ip = 1;
  opt.dst_ip = 1;
  opt.proto = 0;
  opt.src_port = 0;
  opt.dst_port = 0;
  opt.opts = 0;

  opt.datalen = 0;
  opt.times = 0;
  opt.duration = 0;

  strncpy(opt.sort_order, SORTORDER, MAXSORTSIZE);
  opt.sortfield = 0;
  opt.sortmode = 0;

  opt.html = 0;
  opt.use_out = 0;
  opt.outputfile[0] = '\0';
  strncpy(opt.textcol, TEXTCOLOR, COLORSIZE);
  strncpy(opt.bgcol, BGCOLOR, COLORSIZE);
  strncpy(opt.rowcol1, ROWCOLOR1, COLORSIZE);
  strncpy(opt.rowcol2, ROWCOLOR2, COLORSIZE);

  opt.loghost = 0;
  opt.hostname[0] = '\0';

  opt.chains = 0;
  opt.chainlabel[0] = '\0';

  opt.branches = 0;
  opt.branchname[0] = '\0';

  opt.ifs = 0;
  opt.interface[0] = '\0';

  opt.now = time(NULL);
  opt.recent = 0;

  opt.threshold = 0;
  opt.least = 0;
  opt.sender[0] = '\0';
  strncpy(opt.recipient, CERT, EMAILSIZE);
  opt.cc[0] = '\0';
  strncpy(opt.templatefile, TEMPLATE, FILESIZE);

  opt.response = OPT_LOG;
  opt.status = 0;
  strncpy(opt.listenhost, LISTENHOST, IPLEN);
  opt.listenport = LISTENPORT;
  strncpy(opt.user, DEFAULT_USER, USERSIZE);
  strncpy(opt.password, DEFAULT_PASSWORD, PASSWORDSIZE);

  user = getenv("USER");
  if (user == NULL) {
    return;
  }
  retval = gethostname(host, SHOSTLEN);
  if (retval == -1) {
    perror("gethostname");
    return;
  }
#ifndef SOLARIS
  retval = getdomainname(domain, SHOSTLEN);
  if (retval == -1) {
    perror("getdomainname");
    return;
  }
  if (strlen(domain) > 0) {
    snprintf(opt.sender, EMAILSIZE, "%s@%s.%s", user, host, domain);
  } else {
#endif
    snprintf(opt.sender, EMAILSIZE, "%s@%s", user, host);
#ifndef SOLARIS
  }
#endif
}

int main(int argc, char **argv)
{
  char rcfile[FILESIZE];
  unsigned char alt_rcfile = 0;
  int iopt;

  init_options();

  strncpy(rcfile, RCFILE, FILESIZE);
  read_rcfile(rcfile);

  while ((iopt = getopt(argc, argv, "a:AbBc:C:dDf:F:hi:I:k:l:L:m:no:O:pP:RsStT:vVwXyz")) != EOF) {
    switch (iopt) {
    case 'a':
      opt.threshold = atoi(optarg);
      break;
    case 'A':
      opt.response = opt.response | OPT_NOTIFY;
      break;
    case 'b':
      opt.datalen = 1;
      break;
    case 'B':
      opt.response = opt.response | OPT_RESPOND;
      break;
    case 'c':
      strncpy(rcfile, optarg, FILESIZE);
      alt_rcfile = 1;
      break;
    case 'C':
      strncpy(opt.cc, optarg, EMAILSIZE);
      break;
    case 'd':
      opt.dst_port = 1;
      break;
    case 'D':
      opt.dst_ip = 0;
      break;
    case 'f':
      strncpy(opt.inputfile, optarg, FILESIZE);
      break;
    case 'F':
      strncpy(opt.sender, optarg, EMAILSIZE);
      break;
    case 'h':
      usage(argv[0], EXIT_SUCCESS);
      break;
    case 'i':
      if (opt.mode != LOG_SUMMARY) {
	mode_error();
      }
      opt.mode = INTERACTIVE_REPORT;
      opt.threshold = atoi(optarg);
      break;
    case 'I':
      strncpy(opt.templatefile, optarg, FILESIZE);
      break;
    case 'k':
      add_known_host(optarg);
      break;
    case 'l':
      opt.recent = parse_time(optarg);
      break;
    case 'L':
      if (opt.mode != LOG_SUMMARY) {
	mode_error();
      }
      opt.mode = SHOW_LOG_TIMES;
      strncpy(opt.inputfile, optarg, FILESIZE);
      break;
    case 'm':
      opt.least = atoi(optarg);
      break;
    case 'n':
      opt.resolve = 1;
      break;
    case 'o':
      strncpy(opt.outputfile, optarg, FILESIZE);
      opt.use_out = 1;
      break;
    case 'O':
      strncpy(opt.sort_order, optarg, MAXSORTSIZE);
      break;
    case 'p':
      opt.proto = 1;
      break;
    case 'P':
      strncpy(opt.format_sel, optarg, SHORTLEN);
      break;
    case 'R':
      if (opt.mode != LOG_SUMMARY) {
	mode_error();
      }
      opt.mode = REALTIME_RESPONSE;
      break;
    case 's':
      opt.src_port = 1;
      break;
    case 'S':
      opt.src_ip = 0;
      break;
    case 't':
      opt.times = 1;
      break;
    case 'T':
      strncpy(opt.recipient, optarg, EMAILSIZE);
      break;
    case 'v':
      opt.verbose++;
      break;
    case 'V':
      info();
      break;
    case 'w':
      opt.html = 1;
      break;
    case 'X':
      opt.status = 1;
      break;
    case 'y':
      opt.opts = 1;
      break;
    case 'z':
      opt.duration = 1;
      break;
    default:
      usage(argv[0], EXIT_FAILURE);
    }
  }

  if(alt_rcfile)
    read_rcfile(rcfile);

  select_parsers();

  /* Consistency checks */
  if ((opt.src_port == 1) || (opt.dst_port == 1))
    opt.proto = 1;

  if (opt.mode != LOG_SUMMARY) {
    opt.html = 0;
    opt.use_out = 0;
  }

  switch (opt.mode) {
  case LOG_SUMMARY:
  case INTERACTIVE_REPORT:
    mode_summary();
    break;
  case REALTIME_RESPONSE:
    if (opt.src_ip == 0)
      opt.src_ip = 1;
    if (opt.threshold == 0)
      opt.threshold = ALERT;
    if (opt.recent == 0)
      opt.recent = FORGET;
    mode_rt_response();
    break;
  case SHOW_LOG_TIMES:
    mode_show_log_times();
    break;
  }

  if (opt.verbose)
    fprintf(stderr, "Exiting\n");

  return EXIT_SUCCESS;
}
