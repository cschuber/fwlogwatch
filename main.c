/* $Id: main.c,v 1.1 2002/02/14 19:43:03 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "main.h"
#include "rcfile.h"
#include "parser.h"
#include "modes.h"

struct options opt;
extern char *optarg;

void usage(char *me, char exitcode)
{
  printf("%s %s (C) %s\n", PACKAGE, VERSION, COPYRIGHT);
  printf("Usage: %s [options]\n", me);
  printf("Global options:\n");
  printf("         -c <file>   specify config file (defaults to %s)\n", RCFILE);
  printf("         -D          do not differentiate destination IP addresses\n");
  printf("         -d          differentiate destination ports\n");
  printf("         -f <file>   specify input file (defaults to %s)\n", INFILE);
  printf("         -h          this help\n");
  printf("         -L          show time of first and last log entry in file\n");
  printf("         -l <time>   process recent events only (defaults to off)\n");
  printf("         -n          resolve host names\n");
  printf("         -p          differentiate protocols\n");
  printf("         -S          do not differentiate source IP addresses\n");
  printf("         -s          differentiate source ports\n");
  printf("         -t          show start and end times\n");
  printf("         -V          show version and copyright info\n");
  printf("         -v          verbose, specify twice for more info\n");
  printf("         -y          differentiate tcp options (syn/ack)\n");
  printf("         -z          show time interval\n");
  printf("\n");

  printf("Log summary mode (default):\n");
  printf("         -o <file>   specify output file\n");
  printf("         -w          html output\n");
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
  printf("         -a <count>  alert threshold (defaults to %d)\n", ALERT);
  printf("         -l <time>   forget events this old (defaults to %d)\n", FORGET);
  printf("         -B          block host completely with new firewall rule\n");
  printf("         -W <host>   send a winpopup alert message to host\n");
  printf("         -A <action> custom action to take when threshold is reached\n");
  printf("\n");

  if (exitcode == EXIT_SUCCESS)
    exit(EXIT_SUCCESS);
  else
    exit(EXIT_FAILURE);
}

void info()
{
  /* GNU standards compatible program info */
  printf("%s %s\n", PACKAGE, VERSION);
  puts("Copyright (C) 2000 Boris Wesslowski, RUS-CERT");
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
  char *user, host[SHOSTLEN], domain[SHOSTLEN];
  int retval;

  opt.mode = LOG_SUMMARY;

  opt.verbose = 0;
  opt.resolve = 0;
  strncpy(opt.inputfile, INFILE, FILESIZE);

  opt.src_ip = 1;
  opt.dst_ip = 1;
  opt.proto = 0;
  opt.src_port = 0;
  opt.dst_port = 0;
  opt.opts = 0;

  opt.times = 0;
  opt.duration = 0;
  opt.html = 0;
  opt.use_out = 0;
  opt.outputfile[0] = '\0';

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
  opt.sender[0] = '\0';
  strncpy(opt.recipient, CERT, EMAILSIZE);
  opt.cc[0] = '\0';
  strncpy(opt.templatefile, TEMPLATE, FILESIZE);

  opt.response = 0;
  opt.action[0] = '\0';


  user = getenv("USER");
  if (user == NULL) {
    return;
  }
  retval = gethostname(host, SHOSTLEN);
  if (retval == -1) {
    perror("gethostname");
    return;
  }
  retval = getdomainname(domain, SHOSTLEN);
  if (retval == -1) {
    perror("getdomainname");
    return;
  }
  if (strlen(domain) > 0) {
    snprintf(opt.sender, EMAILSIZE, "%s@%s.%s", user, host, domain);
  } else {
    snprintf(opt.sender, EMAILSIZE, "%s@%s", user, host);
  }
}

int main(int argc, char **argv)
{
  char rcfile[FILESIZE];
  unsigned char alt_rcfile = 0;
  int iopt;

  init_options();

  strncpy(rcfile, RCFILE, FILESIZE);
  read_rcfile(rcfile);

  while ((iopt = getopt(argc, argv, "a:A:Bc:C:dDf:F:hi:I:l:Lno:pRsStT:vVwW:yz")) != EOF) {
    switch (iopt) {
    case 'a':
      opt.threshold = atoi(optarg);
      break;
    case 'A':
      opt.response = CUSTOM_ACTION;
      strncpy(opt.action, optarg, ACTIONSIZE);
      break;
    case 'B':
      opt.response = BLOCK;
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
      opt.mode = INTERACTIVE_REPORT;
      opt.threshold = atoi(optarg);
      break;
    case 'I':
      strncpy(opt.templatefile, optarg, FILESIZE);
      break;
    case 'l':
      opt.recent = parse_time(optarg);
      break;
    case 'L':
      opt.mode = SHOW_LOG_TIMES;
      break;
    case 'n':
      opt.resolve = 1;
      break;
    case 'o':
      strncpy(opt.outputfile, optarg, FILESIZE);
      opt.use_out = 1;
      break;
    case 'p':
      opt.proto = 1;
      break;
    case 'R':
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
    case 'W':
      opt.response = NOTIFY_SMB;
      strncpy(opt.action, optarg, ACTIONSIZE);
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

  /* Consistency checks */
  if ((opt.src_port == 1) || (opt.dst_port == 1))
    opt.proto = 1;

  if (opt.threshold > 0)
    opt.html = 0;

  if (opt.mode != LOG_SUMMARY)
    opt.use_out = 0;

  switch (opt.mode) {
  case LOG_SUMMARY:
  case INTERACTIVE_REPORT:
    mode_summary();
    break;
  case REALTIME_RESPONSE:
    if (opt.threshold == 0)
      opt.threshold = ALERT;
    if (opt.response == 0)
      opt.recent = FORGET;
    mode_rt_response();
    break;
  case SHOW_LOG_TIMES:
    mode_show_log_times();
    break;
  }

  if (opt.verbose)
    fprintf(stderr, "Exiting.\n");

  return 0;
}
