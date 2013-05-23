/* Copyright (C) 2000-2013 Boris Wesslowski */
/* $Id: rcfile.c,v 1.33 2013/05/23 15:04:15 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include "rcfile.h"
#include "main.h"
#include "parser.h"
#include "utils.h"
#include "resolve.h"

extern struct options opt;

char *get_one_parameter(char *string, unsigned char mode)
{
  char *pnt;

  while (*string == ' ' || *string == '\t' || *string == '=')
    ++string;

  pnt = string;
  while (*pnt != '\n' && *pnt != ' ' && *pnt != '\t' && *pnt != '\0' && (mode == HASH_IGNORE || *pnt != '#'))
    ++pnt;
  *pnt = '\0';

  return string;
}

char *get_parameter(char *string)
{
  char *pnt;

  while (*string == ' ' || *string == '\t' || *string == '=')
    ++string;

  pnt = string;
  while (*pnt != '\n' && *pnt != '#' && *pnt != '\0')
    ++pnt;
  *pnt = '\0';

  return string;
}

int get_num_parameter(char *string, char *rcfile, int linenum)
{
  char *pnt;

  while (*string == ' ' || *string == '\t' || *string == '=')
    ++string;

  pnt = string;
  while (*pnt != '\n' && *pnt != ' ' && *pnt != '#' && *pnt != '\t' && *pnt != '\0') {
    if (!isdigit((int) *pnt))
      fprintf(stderr, _("Error in configuration file '%s' line %d: not a number\n"), rcfile, linenum);
    ++pnt;
  }
  *pnt = '\0';

  return atoi(string);
}

unsigned char get_yes_or_no(char *string, char *rcfile, int linenum)
{
  char *pnt;

  while (*string == ' ' || *string == '\t' || *string == '=')
    ++string;

  pnt = string;
  while (*pnt != '\n' && *pnt != ' ' && *pnt != '#' && *pnt != '\t' && *pnt != '\0')
    ++pnt;
  *pnt = '\0';

  if ((strncasecmp(string, "yes", 3) == 0)
      || (strncasecmp(string, "on", 2) == 0)
      || (strncasecmp(string, "true", 4) == 0)) {
    return YES;
  } else if ((strncasecmp(string, "no", 2) == 0)
	     || (strncasecmp(string, "off", 3) == 0)
	     || (strncasecmp(string, "false", 5) == 0)) {
    return NO;
  } else {
    fprintf(stderr, _("Error in configuration file '%s' line %d, assuming 'true'\n"), rcfile, linenum);
    return YES;
  }
}

void parse_rcfile(char *input, char *rcfile, int linenum)
{
  char *command;

  while (*input == ' ' || *input == '\t')
    ++input;

  if (*input == '#' || *input == '\n')
    return;

  command = strdup(input);

  /* Include files */

  if (strncasecmp(command, "include_file", 12) == 0) {
    xstrncpy(opt.rcfile, get_one_parameter(command + 13, HASH_ENDS_INPUT), FILESIZE);
    read_rcfile(opt.rcfile, MUST_EXIST, RCFILE_CF);
  }

  /* Global options */

  else if (strncasecmp(command, "verbose", 7) == 0) {
    opt.verbose = opt.verbose + get_yes_or_no(command + 8, rcfile, linenum);
  } else if (strncasecmp(command, "resolve_hosts", 13) == 0) {
    opt.resolve = get_yes_or_no(command + 14, rcfile, linenum);
  } else if (strncasecmp(command, "resolve_services", 16) == 0) {
    opt.sresolve = get_yes_or_no(command + 17, rcfile, linenum);
  } else if (strncasecmp(command, "input", 5) == 0) {
    add_input_file(get_one_parameter(command + 6, HASH_ENDS_INPUT));
  } else if (strncasecmp(command, "dns_cache", 9) == 0) {
    xstrncpy(opt.rcfile_dns, get_one_parameter(command + 10, HASH_ENDS_INPUT), FILESIZE);
  }

  /* Evaluation options */

  else if (strncasecmp(command, "parser", 6) == 0) {
    xstrncpy(opt.format_sel, get_one_parameter(command + 7, HASH_ENDS_INPUT), SHORTLEN);
  } else if (strncasecmp(command, "src_ip", 6) == 0) {
    opt.src_ip = get_yes_or_no(command + 7, rcfile, linenum);
  } else if (strncasecmp(command, "dst_ip", 6) == 0) {
    opt.dst_ip = get_yes_or_no(command + 7, rcfile, linenum);
  } else if (strncasecmp(command, "protocol", 8) == 0) {
    opt.proto = get_yes_or_no(command + 9, rcfile, linenum);
  } else if (strncasecmp(command, "src_port", 8) == 0) {
    opt.src_port = get_yes_or_no(command + 9, rcfile, linenum);
  } else if (strncasecmp(command, "dst_port", 8) == 0) {
    opt.dst_port = get_yes_or_no(command + 9, rcfile, linenum);
  } else if (strncasecmp(command, "tcp_opts", 8) == 0) {
    opt.opts = get_yes_or_no(command + 9, rcfile, linenum);
  } else if (strncasecmp(command, "exclude_src_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_HOST | PARSER_MODE_SRC | PARSER_MODE_NOT);
  } else if (strncasecmp(command, "exclude_src_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_PORT | PARSER_MODE_SRC | PARSER_MODE_NOT);
  } else if (strncasecmp(command, "exclude_dst_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_HOST | PARSER_MODE_NOT);
  } else if (strncasecmp(command, "exclude_dst_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_PORT | PARSER_MODE_NOT);
  } else if (strncasecmp(command, "include_src_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_HOST | PARSER_MODE_SRC);
  } else if (strncasecmp(command, "include_src_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_PORT | PARSER_MODE_SRC);
  } else if (strncasecmp(command, "include_dst_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_HOST);
  } else if (strncasecmp(command, "include_dst_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command + 16, HASH_ENDS_INPUT), PARSER_MODE_PORT);
  } else if (strncasecmp(command, "exclude_chain", 13) == 0) {
    add_exclude_hpb(get_parameter(command + 14), PARSER_MODE_CHAIN | PARSER_MODE_NOT);
  } else if (strncasecmp(command, "include_chain", 13) == 0) {
    add_exclude_hpb(get_parameter(command + 14), PARSER_MODE_CHAIN);
  } else if (strncasecmp(command, "exclude_branch", 14) == 0) {
    add_exclude_hpb(get_parameter(command + 15), PARSER_MODE_BRANCH | PARSER_MODE_NOT);
  } else if (strncasecmp(command, "include_branch", 14) == 0) {
    add_exclude_hpb(get_parameter(command + 15), PARSER_MODE_BRANCH);
  }

  /* Sorting options */

  else if (strncasecmp(command, "sort_order", 10) == 0) {
    xstrncpy(opt.sort_order, get_one_parameter(command + 11, HASH_ENDS_INPUT), MAXSORTSIZE);
  }

  /* Output options */

  else if (strncasecmp(command, "title", 5) == 0) {
    xstrncpy(opt.title, get_parameter(command + 6), TITLESIZE);
  } else if (strncasecmp(command, "stylesheet", 10) == 0) {
    xstrncpy(opt.stylesheet, get_one_parameter(command + 11, HASH_ENDS_INPUT), CSSSIZE);
  } else if (strncasecmp(command, "textcolor", 9) == 0) {
    xstrncpy(opt.textcol, get_one_parameter(command + 10, HASH_IGNORE), COLORSIZE);
  } else if (strncasecmp(command, "bgcolor", 7) == 0) {
    xstrncpy(opt.bgcol, get_one_parameter(command + 8, HASH_IGNORE), COLORSIZE);
  } else if (strncasecmp(command, "rowcolor1", 9) == 0) {
    xstrncpy(opt.rowcol1, get_one_parameter(command + 10, HASH_IGNORE), COLORSIZE);
  } else if (strncasecmp(command, "rowcolor2", 9) == 0) {
    xstrncpy(opt.rowcol2, get_one_parameter(command + 10, HASH_IGNORE), COLORSIZE);
  }

  /* Log summary mode */

  else if (strncasecmp(command, "data_amount", 11) == 0) {
    opt.datalen = get_yes_or_no(command + 12, rcfile, linenum);
  } else if (strncasecmp(command, "start_times", 11) == 0) {
    opt.stimes = get_yes_or_no(command + 12, rcfile, linenum);
  } else if (strncasecmp(command, "end_times", 9) == 0) {
    opt.etimes = get_yes_or_no(command + 10, rcfile, linenum);
  } else if (strncasecmp(command, "duration", 8) == 0) {
    opt.duration = get_yes_or_no(command + 9, rcfile, linenum);
  } else if (strncasecmp(command, "html", 4) == 0) {
    opt.html = get_yes_or_no(command + 5, rcfile, linenum);
  } else if (strncasecmp(command, "output", 6) == 0) {
    opt.use_out = 1;
    xstrncpy(opt.outputfile, get_one_parameter(command + 7, HASH_ENDS_INPUT), FILESIZE);
  } else if (strncasecmp(command, "recent", 6) == 0) {
    opt.recent = parse_time(get_one_parameter(command + 7, HASH_ENDS_INPUT));
  } else if (strncasecmp(command, "at_least", 8) == 0) {
    opt.least = get_num_parameter(command + 9, rcfile, linenum);
  } else if (strncasecmp(command, "maximum", 7) == 0) {
    opt.max = get_num_parameter(command + 8, rcfile, linenum);
  } else if (strncasecmp(command, "whois_lookup", 12) == 0) {
    opt.whois_lookup = get_yes_or_no(command + 13, rcfile, linenum);
  } else if (strncasecmp(command, "sender", 6) == 0) {
    xstrncpy(opt.sender, get_parameter(command + 7), EMAILSIZE);
  } else if (strncasecmp(command, "recipient", 9) == 0) {
    xstrncpy(opt.recipient, get_parameter(command + 10), EMAILSIZE);
  } else if (strncasecmp(command, "cc", 2) == 0) {
    xstrncpy(opt.cc, get_parameter(command + 3), EMAILSIZE);
  }

  /* Realtime response mode */

  else if (strncasecmp(command, "realtime_response", 17) == 0) {
    if (get_yes_or_no(command + 18, rcfile, linenum) == YES) {
      if ((opt.mode != LOG_SUMMARY) && (opt.mode != REALTIME_RESPONSE)) {
	mode_error();
      }
      opt.mode = REALTIME_RESPONSE;
    }
  } else if (strncasecmp(command, "ipchains_check", 14) == 0) {
    opt.ipchains_check = get_yes_or_no(command + 15, rcfile, linenum);
  } else if (strncasecmp(command, "pidfile", 7) == 0) {
    xstrncpy(opt.pidfile, get_one_parameter(command + 8, HASH_ENDS_INPUT), FILESIZE);
  } else if (strncasecmp(command, "run_as", 6) == 0) {
    xstrncpy(opt.run_as, get_one_parameter(command + 7, HASH_ENDS_INPUT), USERSIZE);
  } else if (strncasecmp(command, "stateful_start", 14) == 0) {
    opt.stateful_start = get_yes_or_no(command + 15, rcfile, linenum);
  } else if (strncasecmp(command, "alert_threshold", 15) == 0) {
    opt.threshold = get_num_parameter(command + 16, rcfile, linenum);
  } else if (strncasecmp(command, "notify", 6) == 0) {
    if (get_yes_or_no(command + 7, rcfile, linenum) == YES) {
      opt.response = opt.response | OPT_NOTIFY;
    } else {
      opt.response = opt.response & ~OPT_NOTIFY;
    }
  } else if (strncasecmp(command, "respond", 7) == 0) {
    if (get_yes_or_no(command + 8, rcfile, linenum) == YES) {
      opt.response = opt.response | OPT_RESPOND;
    } else {
      opt.response = opt.response & ~OPT_RESPOND;
    }
  } else if (strncasecmp(command, "notification_script", 19) == 0) {
    xstrncpy(opt.notify_script, get_one_parameter(command + 20, HASH_ENDS_INPUT), FILESIZE);
  } else if (strncasecmp(command, "response_script", 15) == 0) {
    xstrncpy(opt.respond_script, get_one_parameter(command + 16, HASH_ENDS_INPUT), FILESIZE);
  } else if (strncasecmp(command, "known_host", 10) == 0) {
    add_known_host(get_one_parameter(command + 11, HASH_ENDS_INPUT));
  } else if (strncasecmp(command, "server_status", 13) == 0) {
    opt.status = get_yes_or_no(command + 14, rcfile, linenum);
  } else if (strncasecmp(command, "bind_to", 7) == 0) {
    xstrncpy(opt.listenif, get_one_parameter(command + 8, HASH_ENDS_INPUT), IP6LEN);
  } else if (strncasecmp(command, "listen_port", 11) == 0) {
    opt.listenport = get_num_parameter(command + 12, rcfile, linenum);
  } else if (strncasecmp(command, "listen_to", 9) == 0) {
    xstrncpy(opt.listento, get_one_parameter(command + 10, HASH_ENDS_INPUT), IP6LEN);
  } else if (strncasecmp(command, "status_user", 11) == 0) {
    xstrncpy(opt.user, get_one_parameter(command + 12, HASH_ENDS_INPUT), USERSIZE);
  } else if (strncasecmp(command, "status_password", 15) == 0) {
    xstrncpy(opt.password, get_one_parameter(command + 16, HASH_ENDS_INPUT), PASSWORDSIZE);
  } else if (strncasecmp(command, "refresh", 7) == 0) {
    opt.refresh = get_num_parameter(command + 8, rcfile, linenum);
  }

  /* Show log times mode */

  else if (strncasecmp(command, "show_log_times", 14) == 0) {
    if ((opt.mode != LOG_SUMMARY) && (opt.mode != SHOW_LOG_TIMES)) {
      mode_error();
    }
    opt.mode = SHOW_LOG_TIMES;
  } else {
    fprintf(stderr, _("Unrecognized option in configuration file '%s' line %d\n"), rcfile, linenum);
    exit(EXIT_FAILURE);
  }

  free(command);
}

void parse_dns_cache(char *input, char *rcfile, int linenum)
{
  char *p, *p1, *p2;
  struct in6_addr addr;

  while (*input == ' ' || *input == '\t')
    ++input;

  if (*input == '#' || *input == '\n')
    return;

  p1 = strchr(input, ' ');
  p2 = strchr(input, '\t');
  if (p1 != NULL && p2 != NULL) {
    if (p1 < p2)
      p = p1;
    else
      p = p2;
  } else if (p1 != NULL || p2 != NULL) {
    if (p1 != NULL)
      p = p1;
    else
      p = p2;
  } else {
    goto unrecognized;
  }
  *p = 0;
  p++;
  if (convert_ip(input, &addr) == IN_ADDR_OK) {
    while (*p == ' ' || *p == '\t')
      p++;
    p1 = strchr(p, ' ');
    if (p1 != NULL)
      *p1 = 0;
    p1 = strchr(p, '\t');
    if (p1 != NULL)
      *p1 = 0;
    p1 = strchr(p, '\n');
    if (p1 != NULL)
      *p1 = 0;
    init_dns_cache(&addr, p);
    return;
  }
unrecognized:
  fprintf(stderr, _("Unrecognized entry in DNS cache file '%s' line %d\n"), rcfile, linenum);
}

unsigned char read_rcfile(char *rcfile, unsigned char must_exist, unsigned char type)
{
  char buf[BUFSIZE], *name;
  FILE *fd;
  int linenum = 1, retval;
  struct stat info;

  if (!must_exist) {
    retval = stat(rcfile, &info);
    if (retval == -1) {
      return EXIT_FAILURE;
    }

    if (!S_ISREG(info.st_mode)) {
      fprintf(stderr, _("%s is not a regular file, ignoring.\n"), rcfile);
      return EXIT_FAILURE;
    }
  }

  name = strdup(rcfile);

  if (opt.verbose) {
    if (type == RCFILE_DNS) {
      fprintf(stderr, _("Opening DNS cache file '%s'\n"), name);
    } else {
      fprintf(stderr, _("Opening configuration file '%s'\n"), name);
    }
  }

  fd = fopen(name, "r");
  if (fd == NULL) {
    fprintf(stderr, "fopen %s: %s\n", name, strerror(errno));
    exit(EXIT_FAILURE);
  }

  while (fgets(buf, BUFSIZE, fd)) {
    if (type == RCFILE_CF)
      parse_rcfile(buf, name, linenum);
    else
      parse_dns_cache(buf, name, linenum);
    linenum++;
  }

  if (opt.verbose)
    fprintf(stderr, _("Closing '%s'\n"), name);

  xstrncpy(opt.rcfile, name, FILESIZE);
  free(name);

  retval = fclose(fd);
  if (retval == EOF) {
    perror("fclose");
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
