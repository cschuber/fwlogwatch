/* $Id: modes.c,v 1.19 2002/02/14 21:48:38 bwess Exp $ */

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
#include "whois.h"

extern struct options opt;
extern struct conn_data *first;

void mode_summary()
{
  char buf[BUFSIZE], nows[TIMESIZE], first_entry[TIMESIZE], last_entry[TIMESIZE];
  FILE *output = NULL;
  int retval, linenum = 0, hitnum = 0, hit = 0, errnum = 0, oldnum = 0, exnum = 0;
  time_t now;
  struct passwd *gen_user;

  if (opt.std_in) {
    if (opt.verbose)
      fprintf(stderr, _("Using stdin as input\n"));

    opt.inputfd = stdin;
  } else {
    if (opt.verbose)
      fprintf(stderr, _("Opening input file '%s'\n"), opt.inputfile);

    opt.inputfd = gzopen(opt.inputfile, "rb");
    if (opt.inputfd == NULL) {
      fprintf(stderr, "gzopen %s: %s\n", opt.inputfile, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  if (opt.verbose)
    fprintf(stderr, _("Processing\n"));

  opt.line = xmalloc(sizeof(struct log_line));

  if (opt.std_in) {
    retval = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
  } else {
    retval = (gzgets(opt.inputfd, buf, BUFSIZE) != Z_NULL);
  }

  while (retval) {
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

    if (opt.std_in) {
      retval = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
    } else {
      retval = (gzgets(opt.inputfd, buf, BUFSIZE) != Z_NULL);
    }
  }

  if (opt.verbose == 2)
    fprintf(stderr, "\n");

  if(!opt.std_in) {
    if (opt.verbose)
      fprintf(stderr, _("Closing '%s'\n"), opt.inputfile);

    retval = gzclose(opt.inputfd);
    if (retval != 0) {
      if (retval != Z_ERRNO) {
	fprintf(stderr, "gzclose %s: %s\n", opt.inputfile, gzerror(opt.inputfd, &retval));
      } else {
	perror("gzclose");
      }
      exit(EXIT_FAILURE);
    }
  }

  free(opt.line);

  if (opt.verbose)
    fprintf(stderr, _("Sorting data\n"));

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
      fprintf(stderr, _("Opening output file '%s'\n"), opt.outputfile);

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
  printf(_("Generated %s by "), nows);

  gen_user = getpwuid(getuid());
  if (gen_user != NULL) {
    if (gen_user->pw_gecos[0] != '\0') {
      printf("%s.\n", gen_user->pw_gecos);
    } else {
      printf("%s.\n", gen_user->pw_name);
    }
  } else {
    printf(_("an unknown user.\n"));
  }

  if (opt.html)
    printf("<br>\n");

  printf("%d ", hitnum);
  if (oldnum > 0) {
    printf(_("(and %d older than %d seconds) "), oldnum, opt.recent);
  }
  if (errnum > 0) {
    printf(_("(and %d malformed) "), errnum);
  }
  printf(_("of %d entries in the file "), linenum);
  printf(_("\"%s\" are packet logs, "), opt.inputfile);
  retval = list_stats();
  if(retval == 1) {
    printf(_("one has unique characteristics.\n"));
  } else {
    printf(_("%d have unique characteristics.\n"), retval);
  }

  if (exnum != 0) {
    if (opt.html)
      printf("<br>\n");

    if(exnum == 1) {
      printf(_("One entry was excluded by configuration.\n"));
    } else {
      printf(_("%d entries were excluded by configuration.\n"), exnum);
    }
  }

  if (opt.html)
    printf("<br>\n");

  if (first_entry[0] != '\0') {
    printf(_("First packet log entry: %s, last: %s.\n"), first_entry, last_entry);
  } else {
    printf(_("No valid time entries found.\n"));
  }

  if(!opt.loghost) {
    if(opt.html)
      printf("<br>\n");

    printf(_("All entries were logged by the same host: \"%s\".\n"), opt.hostname);
  }

  if(!opt.chains) {
    if(opt.html)
      printf("<br>\n");

    printf(_("All entries are from the same chain: \"%s\".\n"), opt.chainlabel);
  }

  if(!opt.branches) {
    if(opt.html)
      printf("<br>\n");

    printf(_("All entries have the same target: \"%s\".\n"), opt.branchname);
  }

  if(!opt.ifs) {
    if(opt.html)
      printf("<br>\n");

    printf(_("All entries are from the same interface: \"%s\".\n"), opt.interface);
  }

  if(opt.least > 0) {
    if(opt.html)
      printf("<br>\n");

    printf(_("Only entries with a count larger than %d are shown.\n"), opt.least);
  }

  if (opt.html)
    output_html_table();
  else
    printf("\n");

  if(opt.mode == INTERACTIVE_REPORT)
    printf(_("Reporting threshold: %d\n\n"), opt.threshold);

  if(opt.whois_lookup)
    whois_connect(RADB);

  show_list();

  if(opt.whois_lookup)
    whois_close();

  if(opt.mode == INTERACTIVE_REPORT)
    report();

  if (opt.html)
    output_html_footer();

  free_conn_data();
  free_dns_cache();
  free_exclude_data();

  if (opt.use_out) {
    if (opt.verbose)
      fprintf(stderr, _("Closing '%s'\n"), opt.outputfile);

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
    fprintf(stderr, _("Warning: pidfile exists, another fwlogwatch might be running.\n"));
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
  if(opt.std_in) {
    opt.inputfd = stdin;
  } else {
    opt.inputfd = fopen(opt.inputfile, "r");
    if (opt.inputfd == NULL) {
      syslog(LOG_NOTICE, "fopen %s: %s", opt.inputfile, strerror(errno));
      log_exit(EXIT_FAILURE);
    }
  }
}

void mode_rt_response_restart()
{
  int retval;

  if(opt.std_in) {
    syslog(LOG_NOTICE, _("SIGHUP caught, ignoring"));
  } else {
    syslog(LOG_NOTICE, _("SIGHUP caught, reopening log file"));

    retval = fclose(opt.inputfd);
    if(retval == EOF)
      syslog(LOG_NOTICE, "fclose %s: %s", opt.inputfile, strerror(errno));

    mode_rt_response_open();
    signal(SIGHUP, mode_rt_response_restart);
  }
}

void mode_rt_response_core()
{
  char buf[BUFSIZE];
  int retval;
  struct stat info;
  unsigned long size = 0;
  fd_set rfds;
  struct timeval tv;

  if(!opt.std_in) {
    retval = fstat(fileno(opt.inputfd), &info);
    if (retval == -1) {
      syslog(LOG_NOTICE, "fstat %s: %s", opt.inputfile, strerror(errno));
      log_exit(EXIT_FAILURE);
    }
    size = info.st_size;
  }

  while (1) {
    if(opt.status) {
      FD_ZERO(&rfds);
      FD_SET(opt.sock, &rfds);
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      retval = select(opt.sock+1, &rfds, NULL, NULL, &tv);
      if (retval == -1) {
	syslog(LOG_NOTICE, "select: %s", strerror(errno));
	exit(EXIT_FAILURE);
      }
      if (retval) {
	handshake();
      }
    } else {
      sleep(1);
    }

    remove_old();
    if(opt.std_in) {
      while (fgets(buf, BUFSIZE, opt.inputfd)) {
	opt.line = xmalloc(sizeof(struct log_line));
	parse_line(buf, 0);
	free(opt.line);
      }
      look_for_alert();
    } else {
      retval = fstat(fileno(opt.inputfd), &info);
      if (retval == -1) {
	syslog(LOG_NOTICE, "fstat %s: %s", opt.inputfile, strerror(errno));
	log_exit(EXIT_FAILURE);
      }
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
}

void mode_rt_response_terminate()
{
  syslog(LOG_NOTICE, _("SIGTERM caught, cleaning up"));
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
  if(!opt.std_in) {
    retval = close(0);
    if (retval == -1) {
      perror("close");
      exit(EXIT_FAILURE);
    }
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
  if(!opt.std_in) {
    retval = dup(0);
    if (retval == -1) {
      perror("dup");
      exit(EXIT_FAILURE);
    }
  }
  openlog("fwlogwatch", LOG_CONS, LOG_DAEMON);
#else
  openlog("fwlogwatch", LOG_CONS|LOG_PERROR, LOG_DAEMON);
#endif
  syslog(LOG_NOTICE, _("Starting (pid %d)"), getpid());

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

  if((opt.ipchains_check == 1) && ((opt.format & PARSER_IPCHAINS) != 0))
    check_for_ipchains();

  if((opt.response & OPT_NOTIFY) != 0)
    check_script_perms(opt.notify_script);

  if((opt.response & OPT_RESPOND) != 0) {
    check_script_perms(opt.respond_script);
    modify_firewall(FW_START);
  }

  if(opt.threshold == 1) {
    syslog(LOG_NOTICE, _("Alert threshold is one attempt"));
  } else {
    syslog(LOG_NOTICE, _("Alert threshold is %d attempts"), opt.threshold);
  }

  if(opt.recent < 3600) {
    syslog(LOG_NOTICE, _("Events older than %d second(s) are discarded"),
	   opt.recent);
  } else {
    syslog(LOG_NOTICE, _("Events older than %d hour(s) are discarded"),
	   opt.recent/3600);
  }

  syslog(LOG_NOTICE, _("Response mode: log%s%s"),
	 (opt.response & OPT_NOTIFY)?_(", notify"):"",
	 (opt.response & OPT_RESPOND)?_(", respond"):"");

  mode_rt_response_open();

  if(!opt.std_in) {
    retval = fseek(opt.inputfd, 0, SEEK_END);
    if (retval == -1) {
      syslog(LOG_NOTICE, "fseek %s: %s", opt.inputfile, strerror(errno));
      log_exit(EXIT_FAILURE);
    }
  }

  signal(SIGHUP, mode_rt_response_restart);
  mode_rt_response_core();
}

void mode_show_log_times()
{
  char first_entry[TIMESIZE], last_entry[TIMESIZE], buf[BUFSIZE], month[3];
  int retval = 0, retval2, day, hour, minute, second, linenum = 0;
  FILE *input;

  if (opt.std_in) {
    opt.inputfd = stdin;
    input = 0;

    if (opt.verbose)
      fprintf(stderr, _("Reading standard input\n"));
  } else {
    input = gzopen(opt.inputfile, "rb");
    if (input == NULL) {
      fprintf(stderr, "gzopen %s: %s\n", opt.inputfile, strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (opt.verbose)
      fprintf(stderr, _("Reading '%s'\n"), opt.inputfile);
  }

  if (opt.std_in) {
    retval2 = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
  } else {
    retval2 = (gzgets(input, buf, BUFSIZE) != Z_NULL);
  }

  while ((retval != 5) && (retval2)) {
    retval = sscanf(buf, "%3s %2d %2d:%2d:%2d ", month, &day, &hour, &minute, &second);
    linenum++;

    if (opt.std_in) {
      retval2 = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
    } else {
      retval2 = (gzgets(input, buf, BUFSIZE) != Z_NULL);
    }
  }

  if(retval == 5) {
    snprintf(first_entry, TIMESIZE, "%s %02d %02d:%02d:%02d", month, day, hour, minute, second);

    retval = 0;
    while (retval2) {
      retval = sscanf(buf, "%3s %2d %2d:%2d:%2d ", month, &day, &hour, &minute, &second);
      linenum++;
      if (opt.std_in) {
	retval2 = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
      } else {
	retval2 = (gzgets(input, buf, BUFSIZE) != Z_NULL);
      }
    }

    printf(_("# of lines : %d\n"), linenum);
    printf(_("First entry: %s\n"), first_entry);
    if (retval == 5) {
      snprintf(last_entry, TIMESIZE, "%s %02d %02d:%02d:%02d", month, day, hour, minute, second);
      printf(_("Last entry : %s\n"), last_entry);
    }
  } else {
    printf(_("No valid time entries found.\n"));
  }

  if(!opt.std_in) {
    if (opt.verbose)
      fprintf(stderr, _("Closing '%s'\n"), opt.inputfile);

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
}
