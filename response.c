/* $Id: response.c,v 1.21 2002/02/24 14:27:30 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "response.h"
#include "output.h"
#include "utils.h"

struct known_hosts *first_host = NULL;
extern struct options opt;
extern struct conn_data *first;

void check_for_ipchains()
{
  char buf[BUFSIZE];
  unsigned int found = 0;
  FILE *fd;
  int retval;

  char chain[10], src_dst[36], interface[16];
  unsigned int fw_flg, fw_invflg, protocol;
  char rest[80];

  fd = fopen("/proc/net/ip_fwchains", "r");
  if (fd == NULL) {
    syslog(LOG_NOTICE, "fopen /proc/net/ip_fwchains: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  while (fgets(buf, BUFSIZE, fd)) {
    retval = sscanf(buf, "%10s %36s %16s %6X %6X %5u %80s\n",
		    chain, src_dst, interface,
		    &fw_flg,
		    &fw_invflg, &protocol, rest);
    if (retval == 7) {
      if(fw_flg & IP_FW_F_PRN) {
	found++;
      }
    }
  }

  retval = fclose(fd);
  if (retval == EOF) {
    syslog(LOG_NOTICE, "fclose /proc/net/ip_fwchains: %s", strerror(errno));
  }

  if (found > 0) {
    if(found == 1) {
      syslog(LOG_NOTICE, _("One logging ipchains firewall rule defined"));
    } else {
      syslog(LOG_NOTICE, _("%u logging ipchains firewall rules defined"), found);
    }
  } else {
    syslog(LOG_NOTICE, _("No logging ipchains firewall rules defined, format was requested"));
    log_exit(EXIT_FAILURE);
  }
}

void check_script_perms(char *name)
{
  int retval;
  struct stat *buf;

  buf = xmalloc(sizeof(struct stat));

  retval = stat(name, buf);
  if (retval == -1) {
    syslog(LOG_NOTICE, "stat %s: %s", name, strerror(errno));
    free(buf);
    log_exit(EXIT_FAILURE);
  }

  if((getuid() == 0) || (geteuid() == 0)) {
    if ((buf->st_mode & (S_IWGRP|S_IWOTH)) != 0) {
      syslog(LOG_NOTICE, _("%s is group/world writable"), name);
      free(buf);
      log_exit(EXIT_FAILURE);
    }
  }

  free(buf);
}

void modify_firewall(unsigned char action)
{
  char buf[BUFSIZE];

  if (action == FW_START) {
    snprintf(buf, BUFSIZE, "%s start", opt.respond_script);
    run_command(buf);
  } else if (action == FW_STOP) {
    snprintf(buf, BUFSIZE, "%s stop", opt.respond_script);
    run_command(buf);
  }
}

void react(unsigned char mode, struct known_hosts *this_host)
{
  char buf[BUFSIZE], buf2[BUFSIZE];

  if(mode == EX_NOTIFY) {
    xstrncpy(buf, opt.notify_script, BUFSIZE);
  } else {
    xstrncpy(buf, opt.respond_script, BUFSIZE);
    if(mode == EX_RESPOND_ADD) {
      strncat(buf, " add", BUFSIZE);
    } else {
      strncat(buf, " remove", BUFSIZE);
    }
  }

  snprintf(buf2, BUFSIZE, " %d %s", this_host->count, inet_ntoa(this_host->shost));
  strncat(buf, buf2, BUFSIZE);

  if(opt.dst_ip) {
    snprintf(buf2, BUFSIZE, " %s", inet_ntoa(this_host->dhost));
    strncat(buf, buf2, BUFSIZE);
  } else {
    strncat(buf, " -", BUFSIZE);
  }

  if(opt.proto) {
    snprintf(buf2, BUFSIZE, " %d", this_host->protocol);
    strncat(buf, buf2, BUFSIZE);
  } else {
    strncat(buf, " -", BUFSIZE);
  }

  if(opt.src_port) {
    snprintf(buf2, BUFSIZE, " %d", this_host->sport);
    strncat(buf, buf2, BUFSIZE);
  } else {
    strncat(buf, " -", BUFSIZE);
  }

  if(opt.dst_port) {
    snprintf(buf2, BUFSIZE, " %d", this_host->dport);
    strncat(buf, buf2, BUFSIZE);
  } else {
    strncat(buf, " -", BUFSIZE);
  }

  run_command(buf);
}

void remove_old()
{
  struct conn_data *prev, *this;
  struct known_hosts *prev_host, *this_host;
  time_t now, diff;
  unsigned char is_first;

  now = time(NULL);

  prev = this = first;
  is_first = 1;
  while (this != NULL) {
    if (this->end_time != 0)
      diff = now - this->end_time;
    else
      diff = now - this->start_time;
    if (diff >= opt.recent) {
      if(opt.verbose == 2)
	syslog(LOG_NOTICE, _("Deleting packet cache entry (%s)"), inet_ntoa(this->shost));
      if (is_first == 1) {
	prev = this->next;
	free(this);
	first = this = prev;
      } else {
	this = this->next;
	free(prev->next);
	prev->next = this;
      }
    } else {
      prev = this;
      this = this->next;
      is_first = 0;
    }
  }

  prev_host = this_host = first_host;
  is_first = 1;
  while (this_host != NULL) {
    if ((this_host->time != 0) && ((now - this_host->time) >= opt.recent)) {
      if (opt.verbose == 2)
	syslog(LOG_NOTICE, _("Deleting host status entry (%s)"), inet_ntoa(this_host->shost));
      if (opt.response & OPT_RESPOND)
	react(EX_RESPOND_REMOVE, this_host);
      if (is_first == 1) {
	prev_host = this_host->next;
	free(this_host);
	first_host = this_host = prev_host;
      } else {
	this_host = this_host->next;
	free(prev_host->next);
	prev_host->next = this_host;
      }
    } else {
      prev_host = this_host;
      this_host = this_host->next;
      is_first = 0;
    }
  }
}

unsigned char is_known(struct conn_data *host)
{
  struct known_hosts *this_host;

  this_host = first_host;
  while (this_host != NULL) {
    if (this_host->shost.s_addr != (host->shost.s_addr & this_host->netmask.s_addr)) {goto no_match;}
    if ((opt.dst_ip) && (this_host->dhost.s_addr != host->dhost.s_addr)) {goto no_match;}
    if ((opt.dst_port) && (this_host->dport != host->dport)) {goto no_match;}
    if ((opt.src_port) && (this_host->sport != host->sport)) {goto no_match;}
    if ((opt.proto) && (this_host->protocol != host->protocol)) {goto no_match;}
    return 1;
  no_match:
    this_host = this_host->next;
  }
  return 0;
}

void look_for_alert()
{
  struct conn_data *this;

  this = first;
  while (this != NULL) {
    if (this->count >= opt.threshold) {
      struct known_hosts *this_host;
      if (!is_known(this)) {
	this_host = xmalloc(sizeof(struct known_hosts));
	this_host->time = time(NULL);
	this_host->count = this->count;
	this_host->shost = this->shost;
	this_host->netmask.s_addr = 0xFFFFFFFF;
	this_host->protocol = this->protocol;
	this_host->dhost = this->dhost;
	this_host->sport = this->sport;
	this_host->dport = this->dport;
	this_host->next = first_host;
	first_host = this_host;
	if(opt.response & OPT_NOTIFY)
	  react(EX_NOTIFY, this_host);
	if(opt.response & OPT_RESPOND)
	  react(EX_RESPOND_ADD, this_host);
      } else {
	this_host = first_host;
	while (this_host != NULL) {
	  if (this_host->shost.s_addr != this->shost.s_addr) {goto no_match;}
	  if ((opt.dst_ip) && (this_host->dhost.s_addr != this->dhost.s_addr)) {goto no_match;}
	  if ((opt.dst_port) && (this_host->dport != this->dport)) {goto no_match;}
	  if ((opt.src_port) && (this_host->sport != this->sport)) {goto no_match;}
	  if ((opt.proto) && (this_host->protocol != this->protocol)) {goto no_match;}
	  this_host->time = this->end_time;
	  this_host->count = this_host->count + this->count;
	  break;
	no_match:
	  this_host = this_host->next;
	}
      }
      syslog(LOG_NOTICE, _("ALERT: %d attempts from %s"), this->count, inet_ntoa(this->shost));
      this->end_time = 1;
    }
    this = this->next;
  }
}
