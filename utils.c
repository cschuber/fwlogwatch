/* Copyright (C) 2000-2006 Boris Wesslowski */
/* $Id: utils.c,v 1.30 2010/10/11 12:17:44 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "main.h"

struct input_file *first_file = NULL;

extern struct options opt;
extern struct conn_data *first;
extern struct dns_cache *dns_first;
extern struct known_hosts *first_host;
extern struct whois_entry *whois_first;
extern struct parser_options *excluded_first;


/*
 * xstrncpy() - similar to strncpy(3) but always terminates string
 * with '\0' (if n > 0 and dest != NULL),  doesn't do padding.
 */
char *xstrncpy(char *dest, const char *src, size_t n)
{
  char *r = dest;

  if((n <= 0) || (dest == NULL)) {
    return dest;
  }
  if(src != NULL) {
    while ((--n != 0) && (*src != '\0')) {
      *dest++ = *src++;
    }
  }
  *dest = '\0';
  return r;
}

void *xmalloc(int size)
{
  void *ptr;

  ptr = malloc(size);
  if (ptr == NULL) {
    fprintf(stderr, _("\nMemory allocation error, exiting.\n"));
    exit(EXIT_FAILURE);
  }

  return ptr;
}

void log_exit(unsigned char returncode)
{
  if(opt.pidfile[0] != '\0') {
    if(unlink(opt.pidfile) == -1) {
      if(opt.verbose)
	syslog(LOG_NOTICE, "unlink %s: %s", opt.pidfile, strerror(errno));
    }
  }
  syslog(LOG_NOTICE, _("Exiting"));
  exit(returncode);
}

void run_command(char *buf)
{
  pid_t pid;

  if (strstr(buf, "%") != NULL) {
    syslog(LOG_NOTICE, _("Not executing buffer containing format string"));
    return;
  }

  if(opt.verbose == 2) {
    syslog(LOG_NOTICE, _("Executing '%s'"), buf);
  }

  pid = fork();
  if (pid == -1) {
    syslog(LOG_NOTICE, "fork: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  if (pid == 0) {
    execl("/bin/sh", "/bin/sh", "-c", buf, NULL);
    syslog(LOG_NOTICE, "execl: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
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
    free(first->hostname);
    free(first->chainlabel);
    free(first->branchname);
    free(first->interface);
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
    free(dns_first->fqdn);
    free(dns_first);
  }
  dns_first = NULL;
}

void free_whois()
{
  struct whois_entry *whois_this;

  whois_this = whois_first;
  while (whois_this != NULL) {
    whois_first = whois_this;
    whois_this = whois_this->next;
    free(whois_first->ip_route);
    free(whois_first->ip_descr);
    free(whois_first->as_descr);
    free(whois_first);
  }
  whois_first = NULL;
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

void free_exclude_data()
{
  struct parser_options *excluded_this;

  excluded_this = excluded_first;
  while (excluded_this != NULL) {
    excluded_first = excluded_this;
    excluded_this = excluded_this->next;
    if(excluded_first->svalue != NULL)
      free(excluded_first->svalue);
    free(excluded_first);
  }
  excluded_first = NULL;
}

void init_line()
{
  opt.line->time = 0;
  opt.line->hostname[0] = '\0';
  opt.line->chainlabel[0] = '\0';
  opt.line->branchname[0] = '\0';
  opt.line->interface[0] = '\0';
  opt.line->protocol = 0;
  opt.line->datalen = 0;
  opt.line->shost.s_addr = 0;
  opt.line->sport = 0;
  opt.line->dhost.s_addr = 0;
  opt.line->dport = 0;
  opt.line->flags = 0;
  opt.line->count = 0;
}

void mode_error()
{
  fprintf(stderr, _("fwlogwatch error: mode collision, please check that you didn't specify\n"
		    "   several modes on the command line or a second mode is active in the\n"
		    "   configuration file.\n"
		    "   Please use a separate configuration file for each mode or comment out all\n"
		    "   entries in the default configuration and use command line parameters.\n"));
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
  else if (strncmp(smonth, "Feb", 3) == 0) { month = 1; }
  else if (strncmp(smonth, "Mar", 3) == 0) { month = 2; }
  else if (strncmp(smonth, "Apr", 3) == 0) { month = 3; }
  else if (strncmp(smonth, "May", 3) == 0) { month = 4; }
  else if (strncmp(smonth, "Jun", 3) == 0) { month = 5; }
  else if (strncmp(smonth, "Jul", 3) == 0) { month = 6; }
  else if (strncmp(smonth, "Aug", 3) == 0) { month = 7; }
  else if (strncmp(smonth, "Sep", 3) == 0) { month = 8; }
  else if (strncmp(smonth, "Oct", 3) == 0) { month = 9; }
  else if (strncmp(smonth, "Nov", 3) == 0) { month = 10; }
  else if (strncmp(smonth, "Dec", 3) == 0) { month = 11; }
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
      fprintf(stderr, _("IP address error: %s\n"), ip);
    return IN_ADDR_ERROR;
  }
  return IN_ADDR_OK;
}

unsigned long int parse_cidr(char *input)
{
  char *pnt;
  int n;
  unsigned long int netmask[33] = {
    0x0,
    0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
    0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
    0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
    0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
    0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
    0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
    0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
    0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF
  };

  pnt = strstr(input, "/");
  if (pnt != NULL) {
    n = atoi(pnt+1);
    if ((n < 0) || (n > 32)) {
      fprintf(stderr, _("Error in CIDR format: %s\n"), input);
      exit(EXIT_FAILURE);
    }
    *pnt = '\0';
  } else {
    n = 32;
  }

  return ntohl(netmask[n]);
}

void add_known_host(char *ip)
{
  struct known_hosts *host, *test_host;

  host = xmalloc(sizeof(struct known_hosts));
  host->netmask.s_addr = parse_cidr(ip);
  if(convert_ip(ip, &host->shost) == IN_ADDR_ERROR) {
    fprintf(stderr, _("(known host)\n"));
    free(host);
    exit(EXIT_FAILURE);
  }

  host->shost.s_addr = host->shost.s_addr & host->netmask.s_addr;

  test_host = first_host;
  while (test_host != NULL) {
    if (test_host->shost.s_addr == host->shost.s_addr) {
      free(host);
      return;
    }
    test_host = test_host->next;
  }

  host->time = 0;
  host->count = 0;
  host->protocol = 0;
  host->dhost.s_addr = 0;
  host->sport = 0;
  host->dport = 0;
  host->id = opt.global_id++;
  host->next = first_host;
  first_host = host;
}

void add_exclude_hpb(char *input, unsigned char mode)
{
  struct parser_options *excluded_this;
  struct in_addr ip;

  excluded_this = xmalloc(sizeof(struct parser_options));
  excluded_this->mode = mode;
  excluded_this->svalue = NULL;
  if(mode & PARSER_MODE_HOST) {
    struct parser_options *excluded_test;
    excluded_this->netmask.s_addr = parse_cidr(input);
    if (convert_ip(input, &ip) == IN_ADDR_ERROR) {
      fprintf(stderr, _("(excluded host)\n"));
      free(excluded_this);
      exit(EXIT_FAILURE);
    }
    excluded_this->value = ip.s_addr & excluded_this->netmask.s_addr;
    excluded_test = excluded_first;
    while (excluded_test != NULL) {
      if (excluded_test->value == excluded_this->value) {
	free(excluded_this);
	return;
      }
      excluded_test = excluded_test->next;
    }
  } else if(mode & PARSER_MODE_PORT) {
    excluded_this->value = atoi(input);
  } else if(mode & (PARSER_MODE_CHAIN | PARSER_MODE_BRANCH)) {
    excluded_this->svalue = xmalloc(strlen(input)+1);
    xstrncpy(excluded_this->svalue, input, strlen(input)+1);
  }
  excluded_this->next = excluded_first;
  excluded_first = excluded_this;
}

void add_input_file(char *name)
{
  struct input_file *file, *ptr;

  if(!strncmp(name, "-", FILESIZE))
    opt.std_in = 1;

  if (opt.std_in) {
    opt.filecount = 0;
    return;
  }

  file = xmalloc(sizeof(struct input_file));
  file->name = xmalloc(strlen(name)+1);
  file->next = NULL;

  xstrncpy(file->name, name, strlen(name)+1);

  ptr = first_file;
  if (ptr == NULL) {
    first_file = file;
  } else {
    while (ptr->next != NULL) {
      ptr = ptr->next;
    }
    ptr->next = file;
  }
  opt.filecount++;
}

void free_input_file()
{
  struct input_file *file;

  file = first_file;
  while (file != NULL) {
    free(file->name);
    first_file = file;
    file = file->next;
    free(first_file);
  }
  first_file = NULL;
}

void generate_email_header(FILE *fd)
{
  time_t now;
  char stime[TIMESIZE];

  now = time(NULL);
  strftime(stime, TIMESIZE, "%Y%m%d-%H%M%S", localtime(&now));

  fprintf(fd, "From: %s\n", opt.sender);
  fprintf(fd, "To: %s\n", opt.recipient);
  if(opt.cc[0] != '\0')
    fprintf(fd, "Cc: %s\n", opt.cc);
  fprintf(fd, "Subject: %s\n", opt.title);
  fprintf(fd, "X-Generator: %s %s (C) %s\n", PACKAGE, VERSION, COPYRIGHT);
  if(opt.html) {
    fprintf(fd, "Mime-Version: 1.0\n");
    fprintf(fd, "Content-Type: text/html; charset=iso-8859-1\n");
    fprintf(fd, "Content-Disposition: inline; filename=\"fwlogwatch_summary-%s.html\"\n", stime);
  }
  fprintf(fd, "\n");
}

void fdprintf(int fd, char *format, ...)
{
  if(opt.status != FD_ERROR) {
    char buf[BUFSIZE];
    va_list argv;
    ssize_t retval;

    va_start(argv, format);
    vsnprintf(buf, BUFSIZE, format, argv);
    retval = write(fd, buf, strlen(buf));
    va_end(argv);
    if(retval == -1) {
      syslog(LOG_NOTICE, "write: %s", strerror(errno));
      opt.status = FD_ERROR;
      return;
    }
    fflush(NULL);
  }
}
