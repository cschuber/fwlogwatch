/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: response.c,v 1.29 2004/04/25 18:56:22 bwess Exp $ */

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
#include "main.h"
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

void remove_old(unsigned char mode)
{
  time_t now;
  unsigned char is_first;

  now = time(NULL);

  if(mode & RESP_REMOVE_OPC) {
    struct conn_data *prev, *this;

    prev = this = first;
    is_first = 1;
    while (this != NULL) {
      if ((now - this->end_time) >= opt.recent) {
	if(opt.verbose == 2)
	  syslog(LOG_NOTICE, _("Deleting packet cache entry (%s)"), inet_ntoa(this->shost));
	if (is_first == 1) {
	  prev = this->next;
	  free(this->hostname);
	  free(this->chainlabel);
	  free(this->branchname);
	  free(this->interface);
	  free(this);
	  first = this = prev;
	} else {
	  this = this->next;
	  free(prev->next->hostname);
	  free(prev->next->chainlabel);
	  free(prev->next->branchname);
	  free(prev->next->interface);
	  free(prev->next);
	  prev->next = this;
	}
      } else {
	prev = this;
	this = this->next;
	is_first = 0;
      }
    }
  }

  if(mode & RESP_REMOVE_OHS) {
    struct known_hosts *prev_host, *this_host;

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
}

struct known_hosts * is_known(struct conn_data *host)
{
  struct known_hosts *this_host;

  this_host = first_host;
  while (this_host != NULL) {
    if (this_host->shost.s_addr != (host->shost.s_addr & this_host->netmask.s_addr)) {goto no_match;}
    if (this_host->time == 0) return this_host;
    if ((opt.dst_ip) && (this_host->dhost.s_addr != host->dhost.s_addr)) {goto no_match;}
    if ((opt.dst_port) && (this_host->dport != host->dport)) {goto no_match;}
    if ((opt.src_port) && (this_host->sport != host->sport)) {goto no_match;}
    if ((opt.proto) && (this_host->protocol != host->protocol)) {goto no_match;}
    break;
  no_match:
    this_host = this_host->next;
  }
  return this_host;
}

void look_for_alert()
{
  struct conn_data *this;
  unsigned char modified = 0;

  this = first;
  while (this != NULL) {
    if (this->count >= opt.threshold) {
      struct known_hosts *this_host;
      this_host = is_known(this);
      if (this_host == NULL) {
	this_host = xmalloc(sizeof(struct known_hosts));
	this_host->time = time(NULL);
	this_host->count = (this->count / opt.threshold) * opt.threshold;
	this_host->shost = this->shost;
	this_host->netmask.s_addr = 0xFFFFFFFF;
	this_host->protocol = this->protocol;
	this_host->dhost = this->dhost;
	this_host->sport = this->sport;
	this_host->dport = this->dport;
	this_host->id = opt.global_id++;
	this_host->next = first_host;
	first_host = this_host;
	syslog(LOG_NOTICE, _("ALERT: %d attempts from %s"), this_host->count, inet_ntoa(this_host->shost));
	if(opt.response & OPT_NOTIFY)
	  react(EX_NOTIFY, this_host);
	if(opt.response & OPT_RESPOND)
	  react(EX_RESPOND_ADD, this_host);
      } else {
	this_host->count = this_host->count + ((this->count / opt.threshold) * opt.threshold);
	if (this_host->time != 0)
	  this_host->time = time(NULL);
      }
      this->count = (this->count % opt.threshold);
      if(this->count == 0) {
	this->end_time = 1;
	modified = 1;
      }
    }
    this = this->next;
  }
  if(modified)
    remove_old(RESP_REMOVE_OPC);
}

unsigned char hs_compare(struct known_hosts *op1, struct known_hosts *op2)
{
  unsigned char cond = 0;
  time_t now;

  switch(opt.sortfield) {
  case SORT_COUNT:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->count > op2->count) cond++;
    } else {
      if (op1->count < op2->count) cond++;
    }
    break;
  case SORT_START_TIME:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->time > op2->time) cond++;
    } else {
      if (op1->time < op2->time) cond++;
    }
    break;
  case SORT_END_TIME:
    now = time(NULL);
    if (opt.sortmode == ORDER_ASCENDING) {
      if ((now - op1->time) < (now - op2->time)) cond++;
    } else {
      if ((now - op1->time) > (now - op2->time)) cond++;
    }
    break;
  case SORT_PROTOCOL:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->protocol > op2->protocol) cond++;
    } else {
      if (op1->protocol < op2->protocol) cond++;
    }
    break;
  case SORT_SOURCEHOST:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (ntohl(op1->shost.s_addr) > ntohl(op2->shost.s_addr)) cond++;
    } else {
      if (ntohl(op1->shost.s_addr) < ntohl(op2->shost.s_addr)) cond++;
    }
    break;
  case SORT_SOURCEPORT:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->sport > op2->sport) cond++;
    } else {
      if (op1->sport < op2->sport) cond++;
    }
    break;
  case SORT_DESTHOST:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (ntohl(op1->dhost.s_addr) > ntohl(op2->dhost.s_addr)) cond++;
    } else {
      if (ntohl(op1->dhost.s_addr) < ntohl(op2->dhost.s_addr)) cond++;
    }
    break;
  case SORT_DESTPORT:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->dport > op2->dport) cond++;
    } else {
      if (op1->dport < op2->dport) cond++;
    }
  }

  return cond;
}

struct known_hosts *fwlw_hs_mergesort(struct known_hosts *list) {
  struct known_hosts *p, *q, *e, *tail;
  int size, merges, psize, qsize, i;

  switch(opt.sortfield) {
  case SORT_COUNT:
  case SORT_START_TIME:
  case SORT_END_TIME:
  case SORT_PROTOCOL:
  case SORT_SOURCEHOST:
  case SORT_SOURCEPORT:
  case SORT_DESTHOST:
  case SORT_DESTPORT:
    if(list != NULL) {
      size = 1;
      while(1) {
	p = list;
	list = tail = NULL;
	merges = 0;
	while (p != NULL) {
	  merges++;
	  q = p;
	  psize = 0;
	  for (i = 0; i < size; i++) {
	    psize++;
	    q = q->next;
	    if (q == NULL) break;
	  }
	  qsize = size;
	  while (psize > 0 || ((qsize > 0) && (q != NULL))) {
	    if (psize == 0) {
	      e = q; q = q->next; qsize--;
	    } else if (qsize == 0 || (q == NULL)) {
	      e = p; p = p->next; psize--;
	    } else if (hs_compare(p,q) <= 0) {
	      e = p; p = p->next; psize--;
	    } else {
	      e = q; q = q->next; qsize--;
	    }
	    if (tail != NULL) {
	      tail->next = e;
	    } else {
	      list = e;
	    }
	    tail = e;
	  }
	  p = q;
	}
	tail->next = NULL;
	if (merges <= 1)
	  return list;
	size *= 2;
      }
    } else {
      return NULL;
    }
    break;
  default:
    return list;
  }
}

void sort_hs()
{
  first_host = fwlw_hs_mergesort(first_host);
}
