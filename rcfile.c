/* $Id: rcfile.c,v 1.21 2002/02/24 14:27:30 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include "rcfile.h"
#include "main.h"
#include "parser.h"
#include "utils.h"

extern struct options opt;

char * get_one_parameter(char *string)
{
  char *pnt;

  while (*string == ' ' || *string == '\t' || *string == '=')
    ++string;

  pnt = string;
  while (*pnt != '\n' && *pnt != ' ' && *pnt != '#' && *pnt != '\t' && *pnt != '\0')
    ++pnt;
  *pnt = '\0';

  return string;
}

char * get_parameter(char *string)
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

int get_num_parameter(char *string)
{
  char *pnt;

  while (*string == ' ' || *string == '\t' || *string == '=')
    ++string;

  pnt = string;
  while (*pnt != '\n' && *pnt != ' ' && *pnt != '#' && *pnt != '\t' && *pnt != '\0')
    ++pnt;
  *pnt = '\0';

  return atoi(string);
}

void parse_rcfile(char *input)
{
  char *command;

  while (*input == ' ' || *input == '\t')
    ++input;

  if (*input == '#' || *input == '\n')
    return;

  command = strdup(input);

  /* Global options */

  if (strncmp(command, "verbose", 7) == 0) {
    opt.verbose++;
    return;
  }
  if (strncmp(command, "resolve_hosts", 13) == 0) {
    opt.resolve = 1;
    return;
  }
  if (strncmp(command, "resolve_services", 16) == 0) {
    opt.sresolve = 1;
    return;
  }
  if (strncmp(command, "input", 5) == 0) {
    xstrncpy(opt.inputfile, get_one_parameter(command+6), FILESIZE);
    return;
  }

  /* Evaluation options */

  if (strncmp(command, "parser", 6) == 0) {
    xstrncpy(opt.format_sel, get_one_parameter(command+7), SHORTLEN);
    return;
  }
  if (strncmp(command, "src_ip_off", 10) == 0) {
    opt.src_ip = 0;
    return;
  }
  if (strncmp(command, "dst_ip_off", 10) == 0) {
    opt.dst_ip = 0;
    return;
  }
  if (strncmp(command, "protocol", 8) == 0) {
    opt.proto = 1;
    return;
  }
  if (strncmp(command, "src_port", 8) == 0) {
    opt.src_port = 1;
    return;
  }
  if (strncmp(command, "dst_port", 8) == 0) {
    opt.dst_port = 1;
    return;
  }
  if (strncmp(command, "tcp_opts", 8) == 0) {
    opt.opts = 1;
    return;
  }
  if (strncmp(command, "exclude_src_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_HOST|PARSER_MODE_SRC|PARSER_MODE_NOT);
    return;
  }
  if (strncmp(command, "exclude_src_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_PORT|PARSER_MODE_SRC|PARSER_MODE_NOT);
    return;
  }
  if (strncmp(command, "exclude_dst_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_HOST|PARSER_MODE_NOT);
    return;
  }
  if (strncmp(command, "exclude_dst_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_PORT|PARSER_MODE_NOT);
    return;
  }
  if (strncmp(command, "include_src_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_HOST|PARSER_MODE_SRC);
    return;
  }
  if (strncmp(command, "include_src_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_PORT|PARSER_MODE_SRC);
    return;
  }
  if (strncmp(command, "include_dst_host", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_HOST);
    return;
  }
  if (strncmp(command, "include_dst_port", 16) == 0) {
    add_exclude_hpb(get_one_parameter(command+16), PARSER_MODE_PORT);
    return;
  }
  if (strncmp(command, "exclude_chain", 13) == 0) {
    add_exclude_hpb(get_parameter(command+14), PARSER_MODE_CHAIN|PARSER_MODE_NOT);
    return;
  }
  if (strncmp(command, "include_chain", 13) == 0) {
    add_exclude_hpb(get_parameter(command+14), PARSER_MODE_CHAIN);
    return;
  }
  if (strncmp(command, "exclude_branch", 14) == 0) {
    add_exclude_hpb(get_parameter(command+15), PARSER_MODE_BRANCH|PARSER_MODE_NOT);
    return;
  }
  if (strncmp(command, "include_branch", 14) == 0) {
    add_exclude_hpb(get_parameter(command+15), PARSER_MODE_BRANCH);
    return;
  }
  if (strncmp(command, "sort_order", 10) == 0) {
    xstrncpy(opt.sort_order, get_one_parameter(command+11), MAXSORTSIZE);
    return;
  }
  if (strncmp(command, "title", 5) == 0) {
    xstrncpy(opt.title, get_parameter(command+6), TITLESIZE);
    return;
  }
  if (strncmp(command, "textcolor", 9) == 0) {
    xstrncpy(opt.textcol, get_one_parameter(command+10), COLORSIZE);
    return;
  }
  if (strncmp(command, "bgcolor", 7) == 0) {
    xstrncpy(opt.bgcol, get_one_parameter(command+8), COLORSIZE);
    return;
  }
  if (strncmp(command, "rowcolor1", 9) == 0) {
    xstrncpy(opt.rowcol1, get_one_parameter(command+10), COLORSIZE);
    return;
  }
  if (strncmp(command, "rowcolor2", 9) == 0) {
    xstrncpy(opt.rowcol2, get_one_parameter(command+10), COLORSIZE);
    return;
  }

  /* Log summary mode */

  if (strncmp(command, "data_amount", 11) == 0) {
    opt.datalen = 1;
    return;
  }
  if (strncmp(command, "start_times", 11) == 0) {
    opt.stimes = 1;
    return;
  }
  if (strncmp(command, "end_times", 9) == 0) {
    opt.etimes = 1;
    return;
  }
  if (strncmp(command, "duration", 8) == 0) {
    opt.duration = 1;
    return;
  }
  if (strncmp(command, "html", 4) == 0) {
    opt.html = 1;
    return;
  }
  if (strncmp(command, "output", 6) == 0) {
    opt.use_out = 1;
    xstrncpy(opt.outputfile, get_one_parameter(command+7), FILESIZE);
    return;
  }
  if (strncmp(command, "recent", 6) == 0) {
    opt.recent = parse_time(get_one_parameter(command+7));
    return;
  }
  if (strncmp(command, "at_least", 8) == 0) {
    opt.least = get_num_parameter(command+9);
    return;
  }
  if (strncmp(command, "whois_lookup", 12) == 0) {
    opt.whois_lookup = 1;
    return;
  }

  /* Interactive report mode */

  if (strncmp(command, "interactive", 11) == 0) {
    if ((opt.mode != LOG_SUMMARY) && (opt.mode != INTERACTIVE_REPORT)) {
      mode_error();
    }
    opt.mode = INTERACTIVE_REPORT;
    opt.threshold = get_num_parameter(command+12);
    return;
  }
  if (strncmp(command, "sender", 6) == 0) {
    xstrncpy(opt.sender, get_parameter(command+7), EMAILSIZE);
    return;
  }
  if (strncmp(command, "recipient", 9) == 0) {
    xstrncpy(opt.recipient, get_parameter(command+10), EMAILSIZE);
    return;
  }
  if (strncmp(command, "cc", 2) == 0) {
    xstrncpy(opt.cc, get_parameter(command+3), EMAILSIZE);
    return;
  }
  if (strncmp(command, "template", 8) == 0) {
    xstrncpy(opt.templatefile, get_one_parameter(command+9), FILESIZE);
    return;
  }

  /* Realtime response mode */

  if (strncmp(command, "realtime_response", 17) == 0) {
    if ((opt.mode != LOG_SUMMARY) && (opt.mode != REALTIME_RESPONSE)) {
      mode_error();
    }
    opt.mode = REALTIME_RESPONSE;
    return;
  }
  if (strncmp(command, "ipchains_check", 14) == 0) {
    opt.ipchains_check = 1;
    return;
  }
  if (strncmp(command, "pidfile", 7) == 0) {
    xstrncpy(opt.pidfile, get_one_parameter(command+8), FILESIZE);
    return;
  }
  if (strncmp(command, "run_as", 6) == 0) {
    xstrncpy(opt.run_as, get_one_parameter(command+7), USERSIZE);
    return;
  }
  if (strncmp(command, "alert_threshold", 15) == 0) {
    opt.threshold = get_num_parameter(command+16);
    return;
  }
  if (strncmp(command, "notify", 6) == 0) {
    opt.response = opt.response | OPT_NOTIFY;
    return;
  }
  if (strncmp(command, "respond", 7) == 0) {
    opt.response = opt.response | OPT_RESPOND;
    return;
  }
  if (strncmp(command, "notification_script", 19) == 0) {
    xstrncpy(opt.notify_script, get_one_parameter(command+20), FILESIZE);
    return;
  }
  if (strncmp(command, "response_script", 15) == 0) {
    xstrncpy(opt.respond_script, get_one_parameter(command+16), FILESIZE);
    return;
  }
  if (strncmp(command, "known_host", 10) == 0) {
    add_known_host(get_one_parameter(command+11));
    return;
  }
  if (strncmp(command, "server_status", 13) == 0) {
    opt.status = 1;
    return;
  }
  if (strncmp(command, "bind_to", 7) == 0) {
    xstrncpy(opt.listenif, get_one_parameter(command+8), IPLEN);
    return;
  }
  if (strncmp(command, "listen_port", 11) == 0) {
    opt.listenport = get_num_parameter(command+12);
    return;
  }
  if (strncmp(command, "listen_to", 9) == 0) {
    xstrncpy(opt.listento, get_one_parameter(command+10), IPLEN);
    return;
  }
  if (strncmp(command, "status_user", 11) == 0) {
    xstrncpy(opt.user, get_one_parameter(command+12), USERSIZE);
    return;
  }
  if (strncmp(command, "status_password", 15) == 0) {
    xstrncpy(opt.password, get_one_parameter(command+16), PASSWORDSIZE);
    return;
  }
  if (strncmp(command, "refresh", 7) == 0) {
    opt.refresh = get_num_parameter(command+8);
    return;
  }

  /* Show log times mode */

  if (strncmp(command, "show_log_times", 14) == 0) {
    if ((opt.mode != LOG_SUMMARY) && (opt.mode != SHOW_LOG_TIMES)) {
      mode_error();
    }
    opt.mode = SHOW_LOG_TIMES;
    xstrncpy(opt.inputfile, get_one_parameter(command+15), FILESIZE);
    return;
  }


  printf(_("Unrecognized option in rcfile: %s"), command);

  free(command);
}

void read_rcfile(char *rcfile)
{
  char buf[BUFSIZE];
  FILE *fd;
  int retval;
  struct stat info;

  retval = stat(rcfile, &info);
  if (retval == -1) {
    return;
  }

  if (!S_ISREG(info.st_mode)) {
    fprintf(stderr, _("%s is not a regular file, ignoring.\n"), rcfile);
    return;
  }

  fd = fopen(rcfile, "r");
  if (fd == NULL) {
    fprintf(stderr, "fopen %s: %s\n", rcfile, strerror(errno));
    exit(EXIT_FAILURE);
  }

  while (fgets(buf, BUFSIZE, fd)) {
    parse_rcfile(buf);
  }

  retval = fclose(fd);
  if (retval == EOF) {
    perror("fclose");
    exit(EXIT_FAILURE);
  }
}
