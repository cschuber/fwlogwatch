/* $Id: modes.c,v 1.12 2002/02/14 21:06:11 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include "main.h"
#include "parser.h"
#include "output.h"
#include "compare.h"
#include "report.h"
#include "response.h"
#include "utils.h"
#include "net.h"

extern struct options opt;

void mode_summary()
{
  char buf[BUFSIZE], nows[TIMESIZE], log_begin[TIMESIZE], log_end[TIMESIZE];
  FILE *input, *output = NULL;
  unsigned char valid_times = 0;
  int retval, linenum = 0, hitnum = 0, hit = 0, errnum = 0, oldnum = 0;
  time_t now;
  struct passwd *gen_user;

  if (opt.verbose)
    fprintf(stderr, "Opening input file '%s'\n", opt.inputfile);

  input = fopen(opt.inputfile, "r");
  if (input == NULL) {
    fprintf(stderr, "fopen %s: %s\n", opt.inputfile, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (opt.verbose)
    fprintf(stderr, "Processing\n");

  opt.line = xmalloc(sizeof(struct log_line));

  while (fgets(buf, BUFSIZE, input)) {
    ++linenum;
    hit = PARSE_NO_HIT;
    hit = parse_line(buf, linenum);
    if (hit == PARSE_OK) { ++hitnum; }
    if (hit == PARSE_WRONG_FORMAT) { ++errnum; }
    if (hit == PARSE_TOO_OLD) { ++oldnum; }
  }

  valid_times = get_times(input, log_begin, log_end);

  if (opt.verbose == 2)
    fprintf(stderr, "\n");
  if (opt.verbose)
    fprintf(stderr, "Closing '%s'\n", opt.inputfile);

  retval = fclose(input);
  if (retval == EOF) {
    perror("fclose");
    exit(EXIT_FAILURE);
  }

  free(opt.line);

  if (opt.verbose)
    fprintf(stderr, "Sorting data\n");

  sort_data();

  if (opt.verbose == 2)
    fprintf(stderr, "\n");

  if (opt.use_out) {
    if (opt.verbose)
      fprintf(stderr, "Opening output file '%s'\n", opt.outputfile);

    fflush(stdout);
    output = freopen(opt.outputfile, "w", stdout);
    if (output == NULL) {
      fprintf(stderr, "freopen %s: %s\n", opt.outputfile, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  if (opt.html)
    output_html_header();

  now = time(NULL);
  strftime(nows, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&now));
  printf("Generated %s by ", nows);

  gen_user = getpwuid(getuid());
  if (gen_user != NULL) {
    if (gen_user->pw_gecos != '\0') {
      printf("%s.\n", gen_user->pw_gecos);
    } else {
      printf("%s.\n", gen_user->pw_name);
    }
  } else {
    printf("unknown user.\n");
  }

  if (opt.html)
    printf("<br>\n");

  printf("%d ", hitnum);
  if (oldnum > 0) {
    printf("(and %d older than %d seconds) ", oldnum, opt.recent);
  }
  if (errnum > 0) {
    printf("(and %d malformed) ", errnum);
  }
  printf("of %d entries in the file ", linenum);
  printf("\"%s\" are packet logs, ", opt.inputfile);
  retval = list_stats();
  printf("%d %s unique connection characteristics.\n", retval, (retval==1)?"has":"have");

  if (opt.html)
    printf("<br>\n");

  if (valid_times == PARSE_OK) {
    printf("First entry: %s. Last entry: %s.\n", log_begin, log_end);
  } else {
    printf("No valid time entries found.\n");
  }

  if(!opt.loghost) {
    if(opt.html)
      printf("<br>\n");

    printf("All entries were logged by the same host: \"%s\".\n", opt.hostname);
  }

  if(!opt.chains) {
    if(opt.html)
      printf("<br>\n");

    printf("All entries are from the same chain: \"%s\".\n", opt.chainlabel);
  }

  if(!opt.branches) {
    if(opt.html)
      printf("<br>\n");

    printf("All entries have the same target: \"%s\".\n", opt.branchname);
  }

  if(!opt.ifs) {
    if(opt.html)
      printf("<br>\n");

    printf("All entries are from the same interface: \"%s\".\n", opt.interface);
  }

  if(opt.least > 0) {
    if(opt.html)
      printf("<br>\n");

    printf("Only entries with a count larger than %d are shown.\n", opt.least);
  }

  if (opt.html)
    output_html_table();
  else
    printf("\n");

  if(opt.mode == INTERACTIVE_REPORT)
    printf("Reporting threshold: %d\n\n", opt.threshold);

  show_list();

  if(opt.mode == INTERACTIVE_REPORT)
    report();

  if (opt.html)
    output_html_footer();

  free_conn_data();
  free_dns_cache();

  if (opt.use_out) {
    if (opt.verbose)
      fprintf(stderr, "Closing '%s'\n", opt.outputfile);

    retval = fclose(output);
    if (retval == EOF) {
      perror("fclose");
      exit(EXIT_FAILURE);
    }
  }
}

void terminate()
{
  syslog(LOG_NOTICE, "SIGTERM caught, cleaning up");
  free_hosts();
  if(opt.response & OPT_BLOCK)
    modify_firewall(REMOVE_CHAIN);
  log_exit();
}

void mode_rt_response()
{
  char buf[BUFSIZE];
  FILE *input;
  int retval, sock = 0;
  struct stat info;
  unsigned long size;
  fd_set rfds;
  struct timeval tv;
#ifndef RR_DEBUG
  pid_t pid;

  pid = fork();
  if (pid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (pid != 0) {
    _exit(EXIT_SUCCESS);
  }
  pid = setsid();
  if (pid == -1) {
    perror("setsid");
    exit(EXIT_FAILURE);
  }
  pid = fork();
  if (pid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (pid != 0) {
    _exit(EXIT_SUCCESS);
  }
  retval = chdir("/");
  if (retval == -1) {
    perror("chdir");
    exit(EXIT_FAILURE);
  }
  /* umask() */
  retval = close(2);
  if (retval == -1) {
    perror("close");
    exit(EXIT_FAILURE);
  }
  retval = close(1);
  if (retval == -1) {
    perror("close");
    exit(EXIT_FAILURE);
  }
  retval = close(0);
  if (retval == -1) {
    perror("close");
    exit(EXIT_FAILURE);
  }
  retval = open("/dev/null",O_RDWR);
  if (retval == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }
  retval = dup(0);
  if (retval == -1) {
    perror("dup");
    exit(EXIT_FAILURE);
  }
  retval = dup(0);
  if (retval == -1) {
    perror("dup");
    exit(EXIT_FAILURE);
  }
  openlog("fwlogwatch", LOG_CONS, LOG_DAEMON);
#else
  openlog("fwlogwatch", LOG_CONS|LOG_PERROR, LOG_DAEMON);
#endif
  syslog(LOG_NOTICE, "Starting (pid %d)", getpid());

  signal(SIGTERM, terminate);

  input = fopen(PIDFILE, "w");
  if (input == NULL) {
    syslog(LOG_NOTICE, "fopen %s: %s\n", PIDFILE, strerror(errno));
  } else {
    fprintf(input, "%d\n", (int)getpid());
    retval = fclose(input);
    if (retval == EOF) {
      syslog(LOG_NOTICE, "fclose %s: %s\n", PIDFILE, strerror(errno));
    }
  }

  if(opt.status)
    sock = prepare_socket();

  look_for_log_rules();

  syslog(LOG_NOTICE, "Alert threshold is %d attempt%s", opt.threshold, (opt.threshold == 1)?"":"s");

  syslog(LOG_NOTICE, "Events older than %d %s%s are discarded",
	 (opt.recent < 3600)?opt.recent:opt.recent/3600,
	 (opt.recent < 3600)?"second":"hour",
	 ((opt.recent == 1) || (opt.recent == 3600))?"":"s");

  show_mode_opts(buf);
  syslog(LOG_NOTICE, "Response mode: %s", buf);

  if(opt.response & OPT_BLOCK)
    modify_firewall(ADD_CHAIN);

  input = fopen(opt.inputfile, "r");
  if (input == NULL) {
    syslog(LOG_NOTICE, "fopen %s: %s", opt.inputfile, strerror(errno));
    log_exit();
  }

  retval = fseek(input, 0, SEEK_END);
  if (retval == -1) {
    syslog(LOG_NOTICE, "fseek %s: %s", opt.inputfile, strerror(errno));
    log_exit();
  }

  retval = fstat(fileno(input), &info);
  if (retval == -1) {
    syslog(LOG_NOTICE, "fstat %s: %s", opt.inputfile, strerror(errno));
    log_exit();
  }
  size = info.st_size;

  while (1) {
    if(opt.status) {
      FD_ZERO(&rfds);
      FD_SET(sock, &rfds);
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      retval = select(sock+1, &rfds, NULL, NULL, &tv);
      if (retval) {
	handshake(sock);
      }
    } else {
      sleep(1);
    }

    retval = fstat(fileno(input), &info);
    if (retval == -1) {
      syslog(LOG_NOTICE, "fstat %s: %s", opt.inputfile, strerror(errno));
      log_exit();
    }
    remove_old();
    if(size != info.st_size) {
      size = info.st_size;
      while (fgets(buf, BUFSIZE, input)) {
	opt.line = xmalloc(sizeof(struct log_line));
	parse_line(buf, 0);
	free(opt.line);
      }
      look_for_alert();
    }
  }
}

void mode_show_log_times()
{
  char log_begin[TIMESIZE], log_end[TIMESIZE];
  unsigned char valid_times = 0;
  FILE *input;
  int retval;

  input = fopen(opt.inputfile, "r");
  if (input == NULL) {
    fprintf(stderr, "fopen %s: %s\n", opt.inputfile, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (opt.verbose)
    fprintf(stderr, "Reading '%s'\n", opt.inputfile);

  valid_times = get_times(input, log_begin, log_end);

  if (valid_times) {
    printf("First entry: %s\nLast entry : %s\n", log_begin, log_end);
  } else {
    printf("No valid time entries found.\n");
  }

  if (opt.verbose)
    fprintf(stderr, "Closing '%s'\n", opt.inputfile);

  retval = fclose(input);
  if (retval == EOF) {
    perror("fclose");
    exit(EXIT_FAILURE);
  }
}
