/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: modes.c,v 1.29 2004/04/25 18:56:21 bwess Exp $ */

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

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "main.h"
#include "parser.h"
#include "output.h"
#include "compare.h"
#include "report.h"
#include "response.h"
#include "utils.h"
#include "net.h"
#include "whois.h"
#include "rcfile.h"

extern struct options opt;
extern struct conn_data *first;
extern struct input_file *first_file;

void common_input_loop(int *linenum, int *hitnum, int *errnum, int *oldnum, int *exnum)
{
  char buf[BUFSIZE];
  int retval, hit = 0;

#ifdef HAVE_ZLIB
  if ((opt.std_in) || (opt.mode == REALTIME_RESPONSE)) {
#endif
    retval = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
#ifdef HAVE_ZLIB
  } else {
    retval = (gzgets(opt.inputfd, buf, BUFSIZE) != Z_NULL);
  }
#endif

  while (retval) {
    *linenum += 1;
    hit = PARSE_NO_HIT;
    hit = parse_line(buf, *linenum);
    opt.repeated = 0;
    switch (hit) {
    case PARSE_OK:
      *hitnum += 1;
      opt.repeated = 1;
      break;
    case PARSE_WRONG_FORMAT:
      *errnum += 1;
      break;
    case PARSE_TOO_OLD:
      *oldnum += 1;
      break;
    case PARSE_EXCLUDED:
      *hitnum += 1;
      *exnum += 1;
    }

#ifdef HAVE_ZLIB
    if ((opt.std_in) || (opt.mode == REALTIME_RESPONSE)) {
#endif
      retval = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
#ifdef HAVE_ZLIB
    } else {
      retval = (gzgets(opt.inputfd, buf, BUFSIZE) != Z_NULL);
    }
#endif
  }
}

void mode_summary()
{
  char nows[TIMESIZE], first_entry[TIMESIZE], last_entry[TIMESIZE], *input = NULL, last_file = 0;
  FILE *output = NULL;
  int retval, linenum = 0, hitnum = 0, errnum = 0, oldnum = 0, exnum = 0;
  time_t now;
  struct passwd *gen_user;
  struct input_file *file;

  opt.line = xmalloc(sizeof(struct log_line));

  file = first_file;
  while (last_file == 0) {
    if (opt.std_in) {
      if (opt.verbose)
	fprintf(stderr, _("Using stdin as input\n"));

      opt.inputfd = stdin;
    } else {
      input = file->name;
      if (opt.verbose)
	fprintf(stderr, _("Opening input file '%s'\n"), input);

#ifdef HAVE_ZLIB
      opt.inputfd = gzopen(input, "rb");
#else
      opt.inputfd = fopen(input, "r");
#endif
      if (opt.inputfd == NULL) {
#ifdef HAVE_ZLIB
	fprintf(stderr, "gzopen %s: %s\n", input, strerror(errno));
#else
	fprintf(stderr, "fopen %s: %s\n", input, strerror(errno));
#endif
	exit(EXIT_FAILURE);
      }
    }

    if (opt.verbose)
      fprintf(stderr, _("Processing\n"));

    common_input_loop(&linenum, &hitnum, &errnum, &oldnum, &exnum);

    if (opt.verbose == 2)
      fprintf(stderr, "\n");
    if (errnum && opt.verbose) {
      fprintf(stderr, _("Unrecognized entries or tokens can be submitted at\n"));
      fprintf(stderr, "http://fwlogwatch.inside-security.de/unrecognized.php\n");
    }

    if(opt.std_in) {
      last_file++;
    } else {
      if (opt.verbose)
	fprintf(stderr, _("Closing '%s'\n"), input);

#ifndef HAVE_ZLIB
      retval = fclose(opt.inputfd);
      if (retval == EOF) {
	perror("fclose");
#else
      retval = gzclose(opt.inputfd);
      if (retval != 0) {
	if (retval != Z_ERRNO) {
	  fprintf(stderr, "gzclose %s: %s\n", input, gzerror(opt.inputfd, &retval));
	} else {
	  perror("gzclose");
	}
#endif
	exit(EXIT_FAILURE);
      }

      if (file->next != NULL) {
	file = file->next;
      } else {
	last_file++;
      }
    }
  }

  free(opt.line);

  if (opt.verbose)
    fprintf(stderr, _("Sorting data\n"));

  if(first != NULL) {
    opt.sortfield = SORT_END_TIME;
    opt.sortmode = ORDER_DESCENDING;
    first = fwlw_mergesort(first);
    if(opt.verbose == 2)
      fprintf(stderr, ".");
    strftime(last_entry, TIMESIZE, _("%b %d %H:%M:%S"), localtime(&first->end_time));
    opt.sortfield = SORT_START_TIME;
    opt.sortmode = ORDER_ASCENDING;
    first = fwlw_mergesort(first);
    if(opt.verbose == 2)
      fprintf(stderr, ".");
    strftime(first_entry, TIMESIZE, _("%b %d %H:%M:%S"), localtime(&first->start_time));
  } else {
    first_entry[0] = '\0';
  }

  sort_data();

  if (opt.verbose == 2)
    fprintf(stderr, "\n");

  if (opt.use_out) {
    if (opt.verbose)
      fprintf(stderr, _("Opening output file '%s'\n"), opt.outputfile);

    output = freopen(opt.outputfile, "w", stdout);
    if (output == NULL) {
      fprintf(stderr, "freopen %s: %s\n", opt.outputfile, strerror(errno));
      exit(EXIT_FAILURE);
    }
  } else if ((opt.mode != INTERACTIVE_REPORT) && (opt.recipient[0] != '\0')) {
    char buf[BUFSIZE];

    if(opt.verbose)
      fprintf(stderr, _("Sending\n"));

    snprintf(buf, BUFSIZE, "%s -t", P_SENDMAIL);
    output = popen(buf, "w");
    if(output == NULL) {
      perror("popen");
      exit(EXIT_FAILURE);
    }

    generate_email_header(output);
    fflush(output);
  } else {
    output = stdout;
  }

  if (opt.html) {
    output_html_header(fileno(output));
    fprintf(output, "<p>\n");
  } else {
    fprintf(output, "%s\n", opt.title);
  }

  now = time(NULL);
  strftime(nows, TIMESIZE, _("%A %B %d %H:%M:%S %Z %Y"), localtime(&now));
  fprintf(output, _("Generated %s by "), nows);

  gen_user = getpwuid(getuid());
  if (gen_user != NULL) {
    if (gen_user->pw_gecos[0] != '\0') {
      fprintf(output, "%s.\n", gen_user->pw_gecos);
    } else {
      fprintf(output, "%s.\n", gen_user->pw_name);
    }
  } else {
    fprintf(output, _("an unknown user.\n"));
  }

  if (opt.html)
    fprintf(output, "<br />\n");

  fprintf(output, "%d ", hitnum);
  if (oldnum > 0) {
    fprintf(output, _("(and %d older than %d seconds) "), oldnum, opt.recent);
  }
  if (errnum > 0) {
    fprintf(output, _("(and %d malformed) "), errnum);
  }
  if (opt.filecount == 1) {
    fprintf(output, _("of %d entries in the file \"%s\" are packet logs, "), linenum, input);
  } else if (opt.filecount == 0) {
    fprintf(output, _("of %d entries in standard input are packet logs, "), linenum);
  } else {
    fprintf(output, _("of %d entries in %d input files are packet logs, "), linenum, opt.filecount);
  }
  retval = list_stats();
  if(retval == 1) {
    fprintf(output, _("one has unique characteristics.\n"));
  } else {
    fprintf(output, _("%d have unique characteristics.\n"), retval);
  }

  if (exnum != 0) {
    if (opt.html)
      fprintf(output, "<br />\n");

    if(exnum == 1) {
      fprintf(output, _("One entry was excluded by configuration.\n"));
    } else {
      fprintf(output, _("%d entries were excluded by configuration.\n"), exnum);
    }
  }

  if (opt.html)
    fprintf(output, "<br />\n");

  if (first_entry[0] != '\0') {
    fprintf(output, _("First packet log entry: %s, last: %s.\n"), first_entry, last_entry);
  } else {
    fprintf(output, _("No valid time entries found.\n"));
  }

  if(!opt.loghost) {
    if(opt.html)
      fprintf(output, "<br />\n");

    fprintf(output, _("All entries were logged by the same host: \"%s\".\n"), opt.hostname);
  }

  if(!opt.chains) {
    if(opt.html)
      fprintf(output, "<br />\n");

    fprintf(output, _("All entries are from the same chain: \"%s\".\n"), opt.chainlabel);
  }

  if(!opt.branches) {
    if(opt.html)
      fprintf(output, "<br />\n");

    fprintf(output, _("All entries have the same target: \"%s\".\n"), opt.branchname);
  }

  if(!opt.ifs) {
    if(opt.html)
      fprintf(output, "<br />\n");

    fprintf(output, _("All entries are from the same interface: \"%s\".\n"), opt.interface);
  }

  if(opt.least > 1) {
    if(opt.html)
      fprintf(output, "<br />\n");

    fprintf(output, _("Only entries with a count of at least %d are shown.\n"), opt.least);
  }

  if(opt.max) {
    if(opt.html)
      fprintf(output, "<br />\n");

    fprintf(output, _("Only the top %d entries are shown.\n"), opt.max);
  }

  if (opt.html)
    output_html_table(output);
  else
    fprintf(output, "\n");

  if(opt.mode == INTERACTIVE_REPORT)
    fprintf(output, _("Reporting threshold: %d\n\n"), opt.threshold);

  if(opt.whois_lookup)
    whois_connect(RADB);

  show_list(output);
  fflush(output);

  if(opt.whois_lookup)
    whois_close();

  if(opt.mode == INTERACTIVE_REPORT)
    report();

  if (opt.html) {
    fprintf(output, "</table>\n");
    fflush(output);
    output_html_footer(fileno(output));
  }

  free_conn_data();
  free_dns_cache();
  free_whois();
  free_exclude_data();
  free_input_file();

  if (opt.use_out) {
    if (opt.verbose)
      fprintf(stderr, _("Closing '%s'\n"), opt.outputfile);

    retval = fclose(output);
    if (retval == EOF) {
      perror("fclose");
    }
  } else if ((opt.mode != INTERACTIVE_REPORT) && (opt.recipient[0] != '\0')) {
    retval = pclose(output);
    if (retval == -1) {
      perror("pclose");
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

void mode_rt_response_reread_conf()
{
  free_exclude_data();
  if(read_rcfile(opt.rcfile, MAY_NOT_EXIST) == EXIT_SUCCESS) {
    syslog(LOG_NOTICE, _("SIGHUP caught, reread configuration file %s"), opt.rcfile);
  } else {
    syslog(LOG_NOTICE, _("SIGHUP caught, unable to reread configuration file %s"), opt.rcfile);
  }
  signal(SIGHUP, mode_rt_response_reread_conf);
}

void mode_rt_response_open()
{
  if(opt.std_in) {
    opt.inputfd = stdin;
  } else {
    opt.inputfd = fopen(first_file->name, "r");
    if (opt.inputfd == NULL) {
      syslog(LOG_NOTICE, "fopen %s: %s", first_file->name, strerror(errno));
      log_exit(EXIT_FAILURE);
    }
  }
}

void mode_rt_response_reopen_log()
{
  int retval;

  if(opt.std_in) {
    syslog(LOG_NOTICE, _("SIGUSR1 caught, reading input from stdin, no need to reopen log file"));
  } else {
    syslog(LOG_NOTICE, _("SIGUSR1 caught, reopening log file %s"), first_file->name);

    retval = fclose(opt.inputfd);
    if(retval == EOF)
      syslog(LOG_NOTICE, "fclose %s: %s", first_file->name, strerror(errno));

    mode_rt_response_open();
    signal(SIGUSR1, mode_rt_response_reopen_log);
  }
}

void mode_rt_response_core()
{
  int retval, linenum = 0, hitnum = 0, ignored = 0;
  struct stat info;
  off_t size = 0;
  fd_set rfds;
  struct timeval tv;

  if((!opt.std_in) && (!opt.stateful_start)) {
    retval = fstat(fileno(opt.inputfd), &info);
    if (retval == -1) {
      syslog(LOG_NOTICE, "fstat %s: %s", first_file->name, strerror(errno));
      log_exit(EXIT_FAILURE);
    }
    size = info.st_size;
  }

  opt.line = xmalloc(sizeof(struct log_line));

  while (1) {
    if(opt.status) {
      FD_ZERO(&rfds);
      FD_SET(opt.sock, &rfds);
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      retval = select(opt.sock+1, &rfds, NULL, NULL, &tv);
      if (retval == -1) {
	if(errno != EINTR) {
	  syslog(LOG_NOTICE, "select: %s", strerror(errno));
	  exit(EXIT_FAILURE);
	}
      }
      if (retval > 0) {
	handshake(linenum, hitnum, ignored);
      }
    } else {
      sleep(1);
    }

    remove_old(RESP_REMOVE_OPC|RESP_REMOVE_OHS);
    if(opt.std_in) {
      common_input_loop(&linenum, &hitnum, &ignored, &ignored, &ignored);
      look_for_alert();
    } else {
      retval = fstat(fileno(opt.inputfd), &info);
      if (retval == -1) {
	syslog(LOG_NOTICE, "fstat %s: %s", first_file->name, strerror(errno));
	log_exit(EXIT_FAILURE);
      }
      if(size != info.st_size) {
	size = info.st_size;
	clearerr(opt.inputfd);
	common_input_loop(&linenum, &hitnum, &ignored, &ignored, &ignored);
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

  mode_rt_response_open();

  if(opt.run_as[0] != '\0') {
    uid_t olduid;
    gid_t oldgid;
    struct passwd *pwe;

    pwe = getpwnam(opt.run_as);
    if(pwe == NULL) {
      syslog(LOG_NOTICE, _("User to run as was not found"));
      log_exit(EXIT_FAILURE);
    }
    olduid = getuid();
    oldgid = getgid();
    retval = setgid(pwe->pw_gid);
    if (retval == -1) {
      syslog(LOG_NOTICE, "setgid: %s", strerror(errno));
      log_exit(EXIT_FAILURE);
    }
    retval = setuid(pwe->pw_uid);
    if (retval == -1) {
      syslog(LOG_NOTICE, "setuid: %s", strerror(errno));
      log_exit(EXIT_FAILURE);
    }
    syslog(LOG_NOTICE, _("Changed uid from %d to %d, gid from %d to %d"), olduid, getuid(), oldgid, getgid());
  } else {
    syslog(LOG_NOTICE, _("Running with uid %d, gid %d"), getuid(), getgid());
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

  syslog(LOG_NOTICE, _("Response mode: Log%s%s"),
	 (opt.response & OPT_NOTIFY)?_(", notify"):"",
	 (opt.response & OPT_RESPOND)?_(", respond"):"");

  if((!opt.std_in) && (!opt.stateful_start)) {
    retval = fseek(opt.inputfd, 0, SEEK_END);
    if (retval == -1) {
      syslog(LOG_NOTICE, "fseek %s: %s", first_file->name, strerror(errno));
      log_exit(EXIT_FAILURE);
    }
  }

  signal(SIGHUP, mode_rt_response_reread_conf);
  signal(SIGUSR1, mode_rt_response_reopen_log);
  mode_rt_response_core();
}

void mode_show_log_times()
{
  char buf[BUFSIZE], stime[TIMESIZE], month[3], *input = NULL, last_file = 0;
  int retval = 0, loop, day, hour, minute, second, linenum = 0;
  struct input_file *file;
  time_t first = 0, last = 0;

  opt.line = xmalloc(sizeof(struct log_line));

  file = first_file;
  while (last_file == 0) {
    if (opt.std_in) {
      opt.inputfd = stdin;

      if (opt.verbose)
	fprintf(stderr, _("Reading standard input\n"));
    } else {
      input = file->name;
#ifdef HAVE_ZLIB
      opt.inputfd = gzopen(input, "rb");
#else
      opt.inputfd = fopen(input, "r");
#endif
      if (opt.inputfd == NULL) {
#ifdef HAVE_ZLIB
	fprintf(stderr, "gzopen %s: %s\n", input, strerror(errno));
#else
	fprintf(stderr, "fopen %s: %s\n", input, strerror(errno));
#endif
	exit(EXIT_FAILURE);
      }

      if (opt.verbose)
	fprintf(stderr, _("Reading '%s'\n"), input);
    }

#ifdef HAVE_ZLIB
    if (opt.std_in) {
#endif
      loop = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
#ifdef HAVE_ZLIB
    } else {
      loop = (gzgets(opt.inputfd, buf, BUFSIZE) != Z_NULL);
    }
#endif

    while (loop) {
      linenum++;
      retval = sscanf(buf, "%3s %2d %2d:%2d:%2d ", month, &day, &hour, &minute, &second);
      if(retval == 5) {
	build_time(month, day, hour, minute, second);
	if (first == 0)
	  first = last = opt.line->time;
	if (opt.line->time < first)
	  first = opt.line->time;
	if (opt.line->time > last)
	  last = opt.line->time;
      }

#ifdef HAVE_ZLIB
      if (opt.std_in) {
#endif
	loop = (fgets(buf, BUFSIZE, opt.inputfd) != NULL);
#ifdef HAVE_ZLIB
      } else {
	loop = (gzgets(opt.inputfd, buf, BUFSIZE) != Z_NULL);
      }
#endif
    }

    if(opt.std_in) {
      last_file++;
    } else {
      if (opt.verbose)
	fprintf(stderr, _("Closing '%s'\n"), input);

#ifndef HAVE_ZLIB
      retval = fclose(opt.inputfd);
      if (retval == EOF) {
	perror("fclose");
#else
      retval = gzclose(opt.inputfd);
      if (retval != 0) {
	if (retval != Z_ERRNO) {
	  fprintf(stderr, "gzclose %s: %s\n", input, gzerror(opt.inputfd, &retval));
	} else {
	  perror("gzclose");
	}
#endif
	exit(EXIT_FAILURE);
      }

      if (file->next != NULL) {
	file = file->next;
      } else {
	last_file++;
      }
    }
  }

  printf(_("Number of files: %d\n"), opt.filecount);
  printf(_("Number of lines: %d\n"), linenum);
  if (first == 0) {
    printf(_("No valid time entries found.\n"));
  } else {
    strftime(stime, TIMESIZE, _("%b %d %H:%M:%S"), localtime(&first));
    printf(_("First entry: %s\n"), stime);
    strftime(stime, TIMESIZE, _("%b %d %H:%M:%S"), localtime(&last));
    printf(_("Last entry : %s\n"), stime);
    output_timediff(first, last, stime);
    printf(_("Difference : %s\n"), stime);
  }

  free(opt.line);
}
