/* $Id: utils.c,v 1.8 2002/02/14 20:48:49 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "main.h"

extern struct options opt;
extern struct conn_data *first;
extern struct dns_cache *dns_first;
extern struct known_hosts *first_host;

void *xmalloc(int size)
{
  void *ptr;

  ptr = malloc(size);
  if (ptr == NULL) {
    fprintf(stderr, "\nMemory allocation error, exiting.\n");
    exit(EXIT_FAILURE);
  }

  return ptr;
}

void log_exit()
{
  syslog(LOG_NOTICE, "Exiting");
  exit(EXIT_FAILURE);
}

void run_command(char *buf)
{
  pid_t pid;

  if (strstr(buf, "[invalid]") != NULL) {
    syslog(LOG_NOTICE, "Not executing buffer containing invalid string");
    return;
  }

  if(opt.verbose == 2) {
    syslog(LOG_NOTICE, "Executing '%s'", buf);
  }

  pid = fork();
  if (pid == -1) {
    syslog(LOG_NOTICE, "fork: %s", strerror(errno));
    log_exit();
  }

  if (pid == 0) {
    execl("/bin/sh", "/bin/sh", "-c", buf, NULL);
    syslog(LOG_NOTICE, "execl: %s", strerror(errno));
    log_exit();
  }

  wait(NULL);
}

void free_conn_data()
{
  struct conn_data *this;

  this = first;
  while (this != NULL) {
    first = this;
    this = this->next;
    free(first);
  }
}

void free_dns_cache()
{
  struct dns_cache *dns_this;

  dns_this = dns_first;
  while (dns_this != NULL) {
    dns_first = dns_this;
    dns_this = dns_this->next;
    free(dns_first);
  }
}

void free_hosts()
{
  struct known_hosts *this_host;

  this_host = first_host;
  while (this_host != NULL) {
    first_host = this_host;
    this_host = this_host->next;
    free(first_host);
  }
}

void init_line()
{
  opt.line->time = 0;
  opt.line->hostname[0] = '\0';
  opt.line->chainlabel[0] = '\0';
  opt.line->branchname[0] = '\0';
  opt.line->interface[0] = '\0';
  opt.line->protocol = 0;
  opt.line->shost[0] = '\0';
  opt.line->sport = 0;
  opt.line->dhost[0] = '\0';
  opt.line->dport = 0;
  opt.line->syn = 0;
  opt.line->count = 0;
}
