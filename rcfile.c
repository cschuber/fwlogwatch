/* $Id: rcfile.c,v 1.1 2002/02/14 19:43:03 bwess Exp $ */

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
extern struct known_hosts *first_host;

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
  struct known_hosts *host;

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
  if (strncmp(command, "resolve", 7) == 0) {
    opt.resolve = 1;
    return;
  }
  if (strncmp(command, "input", 5) == 0) {
    strncpy(opt.inputfile, get_one_parameter(command+6), FILESIZE);
    return;
  }

  /* Evaluation options */

  if (strncmp(command, "src_ip_off", 10) == 0) {
    opt.src_port = 0;
    return;
  }
  if (strncmp(command, "dst_ip_off", 10) == 0) {
    opt.dst_port = 0;
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

  /* Log summary mode */

  if (strncmp(command, "times", 5) == 0) {
    opt.times = 1;
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
    strncpy(opt.outputfile, get_one_parameter(command+7), FILESIZE);
    return;
  }
  if (strncmp(command, "recent", 6) == 0) {
    opt.recent = parse_time(get_one_parameter(command+7));
    return;
  }

  /* Interactive report mode */

  if (strncmp(command, "interactive", 11) == 0) {
    opt.mode = INTERACTIVE_REPORT;
    opt.threshold = get_num_parameter(command+12);
    return;
  }
  if (strncmp(command, "sender", 6) == 0) {
    strncpy(opt.sender, get_parameter(command+7), EMAILSIZE);
    return;
  }
  if (strncmp(command, "recipient", 9) == 0) {
    strncpy(opt.recipient, get_parameter(command+10), EMAILSIZE);
    return;
  }
  if (strncmp(command, "cc", 2) == 0) {
    strncpy(opt.cc, get_parameter(command+3), EMAILSIZE);
    return;
  }
  if (strncmp(command, "template", 8) == 0) {
    strncpy(opt.templatefile, get_one_parameter(command+9), FILESIZE);
    return;
  }

  /* Realtime response mode */

  if (strncmp(command, "realtime_response", 17) == 0) {
    opt.mode = REALTIME_RESPONSE;
    return;
  }
  if (strncmp(command, "alert_threshold", 15) == 0) {
    opt.threshold = get_num_parameter(command+16);
    return;
  }
  if (strncmp(command, "block", 5) == 0) {
    opt.response = BLOCK;
    return;
  }
  if (strncmp(command, "smb_notify", 10) == 0) {
    opt.response = NOTIFY_SMB;
    strncpy(opt.action, get_one_parameter(command+11), FILESIZE);
    return;
  }
  if (strncmp(command, "action", 6) == 0) {
    opt.response = CUSTOM_ACTION;
    strncpy(opt.action, get_parameter(command+7), FILESIZE);
    return;
  }
  if (strncmp(command, "known_host", 10) == 0) {
    host = xmalloc(sizeof(struct known_hosts));
    host->time = 0;
    strncpy(host->shost, get_one_parameter(command+11), IPLEN);
    host->next = first_host;
    first_host = host;
    return;
  }

  /* Show log times mode */

  if (strncmp(command, "show_log_times", 14) == 0) {
    opt.mode = SHOW_LOG_TIMES;
    return;
  }


  printf("Unrecognized option in rcfile: '%s'\n", command);

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
    fprintf(stderr, "%s is not a regular file, ignoring.\n", rcfile);
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
