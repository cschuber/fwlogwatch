/* $Id: main.c,v 1.27 2003/04/08 21:42:39 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef HAVE_GETTEXT
#include <locale.h>
#endif

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
  printf(_("Usage: %s [options] [input_files]\n"), me);
  printf(_("General options:\n"));
  printf(_("  -h           this help\n"));
  printf(_("  -L           show time of first and last log entry\n"));
  printf(_("  -V           show version and copyright info\n"));
  printf("\n");

  printf(_("Global options:\n"));
  printf(_("  -c <file>    specify config file (defaults to %s)\n"), RCFILE);
  printf(_("  -D           do not differentiate destination IP addresses\n"));
  printf(_("  -d           differentiate destination ports\n"));
  printf(_("  -m <count>   only show entries with at least so many incidents\n"));
  printf(_("  -M <number>  only show this amount of entries\n"));
  printf(_("  -N           resolve service names\n"));
  printf(_("  -n           resolve host names\n"));
  printf(_("  -O <order>   define the sort order (see the man page for details)\n"));
  printf(_("  -P <format>  use only parsers for specific formats\n"));
  printf(_("  -p           differentiate protocols\n"));
  printf(_("  -s           differentiate source ports\n"));
  printf(_("  -v           verbose, specify twice for more info\n"));
  printf(_("  -y           differentiate TCP options\n"));
  printf("\n");

  printf(_("Log summary mode (default):\n"));
  printf(_("  -b           show amount of data (sum of total packet lengths)\n"));
  printf(_("  -e           show end times\n"));
  printf(_("  -l <time>    process recent events only (defaults to off)\n"));
  printf(_("  -o <file>    specify output file\n"));
  printf(_("  -S           do not differentiate source IP addresses\n"));
  printf(_("  -T <email>   send report by email to this address\n"));
  printf(_("  -t           show start times\n"));
  printf(_("  -W           activate whois lookups for source addresses\n"));
  printf(_("  -w           HTML output\n"));
  printf(_("  -z           show time interval\n"));
  printf("\n");

  printf(_("Interactive report mode (summary mode extension):\n"));
  printf(_("  -i <count>   interactive mode with report threshold\n"));
  printf(_("  -F <email>   report sender address (defaults to '%s')\n"), opt.sender);
  printf(_("  -T <email>   address of CERT or abuse contact to send report to\n"));
  printf(_("  -C <email>   carbon copy recipients\n"));
  printf(_("  -I <file>    template file for report (defaults to %s)\n"), TEMPLATE);
  printf("\n");

  printf(_("Realtime response mode:\n"));
  printf(_("  -R           realtime response as daemon (default action: log only)\n"));
  printf(_("  -a <count>   alert threshold (defaults to %d entries)\n"), ALERT);
  printf(_("  -l <time>    forget events this old (defaults to %d hours)\n"), FORGET/3600);
  printf(_("  -k <IP/net>  add this IP address or net to the list of known hosts\n"));
  printf(_("  -A           invoke notification script if threshold is reached\n"));
  printf(_("  -B           invoke response action script (e.g. block host)\n"));
  printf(_("  -X           activate internal status information web server\n"));
  printf("\n");

  exit(exitcode);
}

void info()
{
  /* GNU standards compatible program info */
  printf("%s %s\n", PACKAGE, VERSION);
  puts("Copyright (C) 2000-2003 Boris Wesslowski, RUS-CERT");
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
  puts("\n");
  puts(_("You can contact the author at <Wesslowski@CERT.Uni-Stuttgart.DE>."));
  puts("\n");
  puts(_("Compile-time options of this version:"));
  printf(_("Short name limit "));
#ifdef SHORT_NAMES
  puts(_("enabled"));
#else
  puts(_("disabled"));
#endif
  printf(_("Zlib support "));
#ifdef HAVE_ZLIB
  puts(_("enabled"));
#else
  puts(_("disabled"));
#endif
  printf(_("Gettext (i18n) support "));
#ifdef HAVE_GETTEXT
  puts(_("enabled"));
#else
  puts(_("disabled"));
#endif
  printf(_("IPv6 support "));
#ifdef HAVE_IPV6
  puts(_("enabled"));
#else
  puts(_("disabled"));
#endif

  exit(EXIT_SUCCESS);
}

void init_options()
{
  char *user, host[SHOSTLEN];
  int retval;

  opt.mode = LOG_SUMMARY;
  opt.inputfd = NULL;
  opt.std_in = 0;

  opt.verbose = 0;
  opt.resolve = 0;
  opt.sresolve = 0;
  opt.whois_lookup = 0;
  opt.whois_sock = -1;
  xstrncpy(opt.rcfile, RCFILE, FILESIZE);

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
  opt.stimes = 0;
  opt.etimes = 0;
  opt.duration = 0;

  xstrncpy(opt.sort_order, SORTORDER, MAXSORTSIZE);
  opt.sortfield = 0;
  opt.sortmode = 0;

  opt.html = 0;
  opt.use_out = 0;
  opt.outputfile[0] = '\0';
  opt.title[0] = '\0';
  opt.stylesheet[0] = '\0';
  xstrncpy(opt.textcol, TEXTCOLOR, COLORSIZE);
  xstrncpy(opt.bgcol, BGCOLOR, COLORSIZE);
  xstrncpy(opt.rowcol1, ROWCOLOR1, COLORSIZE);
  xstrncpy(opt.rowcol2, ROWCOLOR2, COLORSIZE);

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
  opt.max = 0;
  opt.sender[0] = '\0';
  opt.recipient[0] = '\0';
  opt.cc[0] = '\0';
  xstrncpy(opt.templatefile, TEMPLATE, FILESIZE);

  opt.response = OPT_LOG;
  opt.ipchains_check = 0;
  opt.pidfile[0] = '\0';
  xstrncpy(opt.notify_script, FWLW_NOTIFY, FILESIZE);
  xstrncpy(opt.respond_script, FWLW_RESPOND, FILESIZE);
  opt.run_as[0] = '\0';
  opt.status = STATUS_OFF;
  opt.sock = 0;
  xstrncpy(opt.listenif, LISTENIF, IPLEN);
  opt.listenport = LISTENPORT;
  opt.listento[0] = '\0';
  xstrncpy(opt.user, DEFAULT_USER, USERSIZE);
  xstrncpy(opt.password, DEFAULT_PASSWORD, PASSWORDSIZE);
  opt.refresh = 0;

  user = getenv("USER");
  if (user == NULL) {
    return;
  }
  retval = gethostname(host, SHOSTLEN);
  if (retval == -1) {
    perror("gethostname");
    return;
  }
  snprintf(opt.sender, EMAILSIZE, "%s@%s", user, host);
}

int main(int argc, char **argv)
{
  unsigned char alt_rcfile = 0;
  int iopt;

  init_options();

#ifdef HAVE_GETTEXT
  setlocale(LC_MESSAGES,"");
  setlocale(LC_TIME,"");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  while ((iopt = getopt(argc, argv, "a:AbBc:C:dDeF:hi:I:k:l:Lm:M:nNo:O:pP:RsStT:vVwWXyz")) != EOF) {
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
      xstrncpy(opt.rcfile, optarg, FILESIZE);
      alt_rcfile = 1;
      break;
    case 'C':
      xstrncpy(opt.cc, optarg, EMAILSIZE);
      break;
    case 'd':
      opt.dst_port = 1;
      break;
    case 'D':
      opt.dst_ip = 0;
      break;
    case 'e':
      opt.etimes = 1;
      break;
    case 'F':
      xstrncpy(opt.sender, optarg, EMAILSIZE);
      break;
    case 'h':
      usage(argv[0], EXIT_SUCCESS);
      break;
    case 'i':
      if ((opt.mode != LOG_SUMMARY) && (opt.mode != INTERACTIVE_REPORT)) {
	mode_error();
      }
      opt.mode = INTERACTIVE_REPORT;
      opt.threshold = atoi(optarg);
      break;
    case 'I':
      xstrncpy(opt.templatefile, optarg, FILESIZE);
      break;
    case 'k':
      add_known_host(optarg);
      break;
    case 'l':
      opt.recent = parse_time(optarg);
      break;
    case 'L':
      if ((opt.mode != LOG_SUMMARY) && (opt.mode != SHOW_LOG_TIMES)) {
	mode_error();
      }
      opt.mode = SHOW_LOG_TIMES;
      break;
    case 'm':
      opt.least = atoi(optarg);
      break;
    case 'M':
      opt.max = atoi(optarg);
      break;
    case 'n':
      opt.resolve = 1;
      break;
    case 'N':
      opt.sresolve = 1;
      break;
    case 'o':
      xstrncpy(opt.outputfile, optarg, FILESIZE);
      opt.use_out = 1;
      break;
    case 'O':
      xstrncpy(opt.sort_order, optarg, MAXSORTSIZE);
      break;
    case 'p':
      opt.proto = 1;
      break;
    case 'P':
      xstrncpy(opt.format_sel, optarg, SHORTLEN);
      break;
    case 'R':
      if ((opt.mode != LOG_SUMMARY) && (opt.mode != REALTIME_RESPONSE)) {
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
      opt.stimes = 1;
      break;
    case 'T':
      xstrncpy(opt.recipient, optarg, EMAILSIZE);
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
    case 'W':
      opt.whois_lookup = 1;
      break;
    case 'X':
      opt.status = STATUS_OK;
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

  if(!alt_rcfile) {
    read_rcfile(opt.rcfile, MAY_NOT_EXIST);
  } else {
    read_rcfile(opt.rcfile, MUST_EXIST);
  }

  while (optind < argc)
    add_input_file(argv[optind++]);

  if (opt.filecount == 0)
    add_input_file(INFILE);

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
    if (opt.title[0] == '\0')
      xstrncpy(opt.title, SUMMARY_TITLE, TITLESIZE);
    mode_summary();
    break;
  case INTERACTIVE_REPORT:
    if (opt.title[0] == '\0')
      xstrncpy(opt.title, SUMMARY_TITLE, TITLESIZE);
    if (opt.recipient[0] == '\0')
      xstrncpy(opt.recipient, CERT, EMAILSIZE);
    mode_summary();
    break;
  case REALTIME_RESPONSE:
    if (opt.src_ip == 0)
      opt.src_ip = 1;
    if (opt.threshold == 0)
      opt.threshold = ALERT;
    if (opt.recent == 0)
      opt.recent = FORGET;
    if (opt.title[0] == '\0')
      xstrncpy(opt.title, STATUS_TITLE, TITLESIZE);
    mode_rt_response();
    break;
  case SHOW_LOG_TIMES:
    mode_show_log_times();
    break;
  }

  if (opt.verbose)
    fprintf(stderr, _("Exiting\n"));

  return EXIT_SUCCESS;
}
