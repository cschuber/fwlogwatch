/* $Id: modes.c,v 1.17 2002/02/14 21:32:47 bwess Exp $ */

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
#include <zlib.h>
#include "main.h"
#include "parser.h"
#include "output.h"
#include "compare.h"
#include "report.h"
#include "response.h"
#include "utils.h"
#include "net.h"

extern struct options opt;
extern struct conn_data *first;

void mode_summary()
{
  char buf[BUFSIZE], nows[TIMESIZE], first_entry[TIMESIZE], last_entry[TIMESIZE];
  FILE *output = NULL;
  int retval, linenum = 0, hitnum = 0, hit = 0, errnum = 0, oldnum = 0, exnum = 0;
  time_t now;
  struct passwd *gen_user;

  if (opt.verbose)
    fprintf(stderr, "Opening input file '%s'\n", opt.inputfile);

  opt.inputfd = gzopen(opt.inputfile, "rb");
  if (opt.inputfd == NULL) {
    fprintf(stderr, "gzopen %s: %s\n", opt.inputfile, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (opt.verbose)
    fprintf(stderr, "Processing\n");

  opt.line = xmalloc(sizeof(struct log_line));

  while (gzgets(opt.inputfd, buf, BUFSIZE) != Z_NULL) {
    ++linenum;
    hit = PARSE_NO_HIT;
    hit = parse_line(buf, linenum);
    opt.repeated = 0;
    switch (hit) {
    case PARSE_OK:
      ++hitnum;
      opt.repeated = 1;
      break;
    case PARSE_WRONG_FORMAT:
      ++errnum;
      break;
    case PARSE_TOO_OLD:
      ++oldnum;
      break;
    case PARSE_EXCLUDED:
      ++hitnum;
      ++exnum;
      break;
    }
  }

  if (opt.verbose == 2)
    fprintf(stderr, "\n");
  if (opt.verbose)
    fprintf(stderr, "Closing '%s'\n", opt.inputfile);

  retval = gzclose(opt.inputfd);
  if (retval != 0) {
    if (retval != Z_ERRNO) {
      fprintf(stderr, "gzclose %s: %s\n", opt.inputfile, gzerror(opt.inputfd, &retval));
    } else {
      perror("gzclose");
    }
    exit(EXIT_FAILURE);
  }

  free(opt.line);

  if (opt.verbose)
    fprintf(stderr, "Sorting data\n");

  if(first != NULL) {
    opt.sortfield = SORT_START_TIME;
    opt.sortmode = ORDER_DESCENDING;
    first = fwlw_mergesort(first);
    if(opt.verbose == 2)
      fprintf(stderr, ".");
    strftime(last_entry, TIMESIZE, "%b %d %H:%M:%S", localtime(&first->start_time));
    opt.sortmode = ORDER_ASCENDING;
    first = fwlw_mergesort(first);
    if(opt.verbose == 2)
      fprintf(stderr, ".");
    strftime(first_entry, TIMESIZE, "%b %d %H:%M:%S", localtime(&first->start_time));
  } else {
    first_entry[0] = '\0';
  }

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
    if (gen_user->pw_gecos[0] != '\0') {
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
  printf("%d %s unique characteristics.\n", retval, (retval==1)?"has":"have");

  if (exnum != 0) {
    if (opt.html)
      printf("<br>\n");

    printf("%d entr%s excluded by configuration.\n", exnum, (exnum==1)?"y was":"ies were");
  }

  if (opt.html)
    printf("<br>\n");

  if (first_entry[0] != '\0') {
    printf("First packet log entry: %s, last: %s.\n", first_entry, last_entry);
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
  free_exclude_data();

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

void check_pidfile()
{
  struct stat *sbuf;

  sbuf = xmalloc(sizeof(struct stat));
  if (stat(opt.pidfile, sbuf) != -1) {
    fprintf(stderr, "Warning: pidfile exists, another fwlogwatch might be running.\n");
  } else {
    if ((errno != ENOENT) && (errno != EACCES)){
      fprintf(stderr, "stat %s: %d, %s\n", opt.pidfile, errno, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
  free(sbuf);
}

void mode_rt_response_open()
{
  opt.inputfd = fopen(opt.inputfile, "r");
  if (opt.inputfd == NULL) {
    syslog(LOG_NOTICE, "fopen %s: %s", opt.inputfile, strerror(errno));
    log_exit(EXIT_FAILURE);
  }
}

void mode_rt_response_restart()
{
  int retval;

  syslog(LOG_NOTICE, "SIGHUP caught, reopening log file");

  retval = fclose(opt.inputfd);
  if(retval == EOF)
    syslog(LOG_NOTICE, "fclose %s: %s", opt.inputfile, strerror(errno));

  mode_rt_response_open();
  signal(SIGHUP, mode_rt_response_restart);
}

void mode_rt_response_core()
{
  char buf[BUFSIZE];
  int retval;
  struct stat info;
  unsigned long size;
  fd_set rfds;
  struct timeval tv;

  retval = fstat(fileno(opt.inputfd), &info);
  if (retval == -1) {
    syslog(LOG_NOTICE, "fstat %s: %s", opt.inputfile, strerror(errno));
    log_exit(EXIT_FAILURE);
  }
  size = info.st_size;

  while (1) {
    if(opt.status) {
      FD_ZERO(&rfds);
      FD_SET(opt.sock, &rfds);
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      retval = select(opt.sock+1, &rfds, NULL, NULL, &tv);
      if (retval) {
	handshake();
      }
    } else {
      sleep(1);
    }

    retval = fstat(fileno(opt.inputfd), &info);
    if (retval == -1) {
      syslog(LOG_NOTICE, "fstat %s: %s", opt.inputfile, strerror(errno));
      log_exit(EXIT_FAILURE);
    }
    remove_old();
    if(size != info.st_size) {
      size = info.st_size;
      while (fgets(buf, BUFSIZE, opt.inputfd)) {
	opt.line = xmalloc(sizeof(struct log_line));
	parse_line(buf, 0);
	free(opt.line);
      }
      look_for_alert();
    }
  }
}

void mode_rt_response_terminate()
{
  syslog(LOG_NOTICE, "SIGTERM caught, cleaning up");
  free_hosts();
  if(opt.response & OPT_RESPOND)
    modify_firewall(FW_STOP);
  log_exit(EXIT_SUCCESS);
}

void mode_rt_response()
{
  int retval;
  FILE *pidfile;
#ifndef RR_DEBUG
  pid_t pid;

  if(opt.pidfile[0] != '\0')
    check_pidfile();

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

  signal(SIGTERM, mode_rt_response_terminate);

  if(opt.pidfile[0] != '\0') {
    pidfile = fopen(opt.pidfile, "w");
    if (pidfile == NULL) {
      syslog(LOG_NOTICE, "fopen %s: %s\n", opt.pidfile, strerror(errno));
    } else {
      fprintf(pidfile, "%d\n", (int)getpid());
      retval = fclose(pidfile);
      if (retval == EOF) {
	syslog(LOG_NOTICE, "fclose %s: %s\n", opt.pidfile, strerror(errno));
      }
    }
  }

  if(opt.status)
    prepare_socket();

  if((opt.format & PARSER_IPCHAINS) != 0)
    check_for_ipchains();

  if((opt.response & OPT_NOTIFY) != 0)
    check_script_perms(FWLW_NOTIFY);

  if((opt.response & OPT_RESPOND) != 0) {
    check_script_perms(FWLW_RESPOND);
    modify_firewall(FW_START);
  }

  syslog(LOG_NOTICE, "Alert threshold is %d attempt%s", opt.threshold, (opt.threshold == 1)?"":"s");

  syslog(LOG_NOTICE, "Events older than %d %s%s are discarded",
	 (opt.recent < 3600)?opt.recent:opt.recent/3600,
	 (opt.recent < 3600)?"second":"hour",
	 ((opt.recent == 1) || (opt.recent == 3600))?"":"s");

  syslog(LOG_NOTICE, "Response mode: log%s%s",
	 (opt.response & OPT_NOTIFY)?", notify":"",
	 (opt.response & OPT_RESPOND)?", respond":"");

  mode_rt_response_open();

  retval = fseek(opt.inputfd, 0, SEEK_END);
  if (retval == -1) {
    syslog(LOG_NOTICE, "fseek %s: %s", opt.inputfile, strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  signal(SIGHUP, mode_rt_response_restart);
  mode_rt_response_core();
}

void mode_show_log_times()
{
  char first_entry[TIMESIZE], last_entry[TIMESIZE], buf[BUFSIZE], month[3];
  int retval = 0, day, hour, minute, second, linenum = 0;
  FILE *input;

  input = gzopen(opt.inputfile, "rb");
  if (input == NULL) {
    fprintf(stderr, "gzopen %s: %s\n", opt.inputfile, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (opt.verbose)
    fprintf(stderr, "Reading '%s'\n", opt.inputfile);

  while ((retval != 5) && (gzgets(input, buf, BUFSIZE) != Z_NULL)) {
    retval = sscanf(buf, "%3s %2d %2d:%2d:%2d ", month, &day, &hour, &minute, &second);
    linenum++;
  }

  if(retval == 5) {
    snprintf(first_entry, TIMESIZE, "%s %02d %02d:%02d:%02d", month, day, hour, minute, second);

    retval = 0;
    while (gzgets(input, buf, BUFSIZE) != Z_NULL) {
      retval = sscanf(buf, "%3s %2d %2d:%2d:%2d ", month, &day, &hour, &minute, &second);
      linenum++;
    }

    if (retval == 5) {
      snprintf(last_entry, TIMESIZE, "%s %02d %02d:%02d:%02d", month, day, hour, minute, second);

      printf("# of lines : %d\n", linenum);
      printf("First entry: %s\n", first_entry);
      printf("Last entry : %s\n", last_entry);
    } else {
      printf("# of lines : %d\n", linenum);
      printf("First entry: %s\n", first_entry);
    }

  } else {
    printf("No valid time entries found.\n");
  }

  if (opt.verbose)
    fprintf(stderr, "Closing '%s'\n", opt.inputfile);

  retval = gzclose(input);
  if (retval != 0) {
    if (retval != Z_ERRNO) {
      fprintf(stderr, "gzclose %s: %s\n", opt.inputfile, gzerror(input, &retval));
    } else {
      perror("gzclose");
    }
    exit(EXIT_FAILURE);
  }
}
