/* $Id: utils.c,v 1.12 2002/02/14 21:06:11 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
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
  if(unlink(PIDFILE) == -1) {
    if(opt.verbose)
      syslog(LOG_NOTICE, "unlink %s: %s", PIDFILE, strerror(errno));
  }
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
  first = NULL;
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
  dns_first = NULL;
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
  first_host = NULL;
}

void init_line()
{
  opt.line->time = 0;
  opt.line->hostname[0] = '\0';
  opt.line->chainlabel[0] = '\0';
  opt.line->branchname[0] = '\0';
  opt.line->interface[0] = '\0';
  opt.line->protocol = 0;
  opt.line->shost.s_addr = 0;
  opt.line->sport = 0;
  opt.line->dhost.s_addr = 0;
  opt.line->dport = 0;
  opt.line->flags = 0;
  opt.line->count = 0;
}

void mode_error()
{
  printf("fwlogwatch error: mode collision, please check that you didn't specify\n"
	 "   several modes on the command line or a second mode is active in the\n"
	 "   default or specified configuration file.\n"
	 "   Please use a separate configuration file for each mode or comment out all\n"
	 "   entries in the default configuration and use command line parameters.\n");
  exit(EXIT_FAILURE);
}

void build_time(char *smonth, int day, int hour, int minute, int second)
{
  int month = 0, now, then;
  struct tm *t;

  if(opt.mode != REALTIME_RESPONSE) {
    t = localtime(&opt.now);
  } else {
    time_t rr_now;

    rr_now = time(NULL);
    t = localtime(&rr_now);
  }
  now = (int)mktime(t);
  if (strncmp(smonth, "Jan", 3) == 0) { month = 0; }
  if (strncmp(smonth, "Feb", 3) == 0) { month = 1; }
  if (strncmp(smonth, "Mar", 3) == 0) { month = 2; }
  if (strncmp(smonth, "Apr", 3) == 0) { month = 3; }
  if (strncmp(smonth, "May", 3) == 0) { month = 4; }
  if (strncmp(smonth, "Jun", 3) == 0) { month = 5; }
  if (strncmp(smonth, "Jul", 3) == 0) { month = 6; }
  if (strncmp(smonth, "Aug", 3) == 0) { month = 7; }
  if (strncmp(smonth, "Sep", 3) == 0) { month = 8; }
  if (strncmp(smonth, "Oct", 3) == 0) { month = 9; }
  if (strncmp(smonth, "Nov", 3) == 0) { month = 10; }
  if (strncmp(smonth, "Dec", 3) == 0) { month = 11; }
  t->tm_mon = month;
  t->tm_mday = day;
  t->tm_hour = hour;
  t->tm_min = minute;
  t->tm_sec = second;
  t->tm_isdst = -1;
  then = (int)mktime(t);
  if (then > now)
    --t->tm_year;

  opt.line->time = mktime(t);
}

unsigned char convert_ip(char *ip, struct in_addr *addr)
{
#ifndef SOLARIS
  int retval;

  retval = inet_aton(ip, addr);
  if (retval == 0) {
#else
#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
  addr->s_addr = inet_addr(ip);
  if (addr->s_addr == INADDR_NONE) {
#endif
    if (opt.verbose)
      printf("IP address error: %s\n", ip);
    return IN_ADDR_ERROR;
  }
  return IN_ADDR_OK;
}

unsigned long int parse_cidr(char *input)
{
  int mask = 32;
  char *pnt;

  pnt = strstr(input, "/");
  if (pnt != NULL) {
    mask = atoi(pnt+1);
    if ((mask < 0) || (mask > 32)) {
      printf("Error in CIDR format: %s\n", input);
      exit(EXIT_FAILURE);
    }
    *pnt = '\0';
  }
  if (mask == 0) {
    return 0;
  } else {
    return (0xFFFFFFFF >> (32-mask));
  }
}

void add_host_ip_net(char *input, time_t time)
{
  struct known_hosts *host;

  host = xmalloc(sizeof(struct known_hosts));
  host->time = time;
  host->netmask.s_addr = parse_cidr(input);
  if(convert_ip(input, &host->shost) == IN_ADDR_ERROR) {
    printf("(known host)\n");
    free(host);
    exit(EXIT_FAILURE);
  }
  host->shost.s_addr = host->shost.s_addr & host->netmask.s_addr;
  host->next = first_host;
  first_host = host;
}
