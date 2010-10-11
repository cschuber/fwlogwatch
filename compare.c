/* Copyright (C) 2000-2006 Boris Wesslowski */
/* $Id: compare.c,v 1.30 2010/10/11 12:17:44 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "compare.h"
#include "output.h"
#include "response.h"
#include "utils.h"

struct conn_data *first = NULL;
extern struct known_hosts *first_host;
extern struct options opt;

void add_entry()
{
  struct conn_data *data;

  data = xmalloc(sizeof(struct conn_data));

  data->count = opt.line->count;
  data->start_time = opt.line->time;
  if(opt.mode != REALTIME_RESPONSE) {
    data->end_time = 0;
  } else {
    data->end_time = opt.line->time;
  }
  data->hostname = xmalloc(strlen(opt.line->hostname)+1);
  xstrncpy(data->hostname, opt.line->hostname, strlen(opt.line->hostname)+1);
  data->chainlabel = xmalloc(strlen(opt.line->chainlabel)+1);
  xstrncpy(data->chainlabel, opt.line->chainlabel, strlen(opt.line->chainlabel)+1);
  data->branchname = xmalloc(strlen(opt.line->branchname)+1);
  xstrncpy(data->branchname, opt.line->branchname, strlen(opt.line->branchname)+1);
  data->interface = xmalloc(strlen(opt.line->interface)+1);
  xstrncpy(data->interface, opt.line->interface, strlen(opt.line->interface)+1);
  data->protocol = opt.line->protocol;
  data->datalen = opt.line->datalen;
  data->shost = opt.line->shost;
  data->sport = opt.line->sport;
  data->dhost = opt.line->dhost;
  data->dport = opt.line->dport;
  data->flags = opt.line->flags;
  data->id = opt.global_id++;

  data->next = first;
  first = data;
}

unsigned char compare(struct conn_data *op1, struct conn_data *op2)
{
  unsigned char cond = 0;

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
      if (op1->start_time > op2->start_time) cond++;
    } else {
      if (op1->start_time < op2->start_time) cond++;
    }
    break;
  case SORT_END_TIME:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->end_time > op2->end_time) cond++;
    } else {
      if (op1->end_time < op2->end_time) cond++;
    }
    break;
  case SORT_DELTA_TIME:
    if (opt.sortmode == ORDER_ASCENDING) {
      if ((op1->end_time - op1->start_time) > (op2->end_time - op2->start_time)) cond++;
    } else {
      if ((op1->end_time - op1->start_time) < (op2->end_time - op2->start_time)) cond++;
    }
    break;
  case SORT_CHAINLABEL:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (strncmp(op1->chainlabel, op2->chainlabel, SHORTLEN) > 0) cond++;
    } else {
      if (strncmp(op1->chainlabel, op2->chainlabel, SHORTLEN) < 0) cond++;
    }
    break;
  case SORT_PROTOCOL:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->protocol > op2->protocol) cond++;
    } else {
      if (op1->protocol < op2->protocol) cond++;
    }
    break;
  case SORT_DATALEN:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op1->datalen > op2->datalen) cond++;
    } else {
      if (op1->datalen < op2->datalen) cond++;
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
    break;
  default:
    fprintf(stderr, _("conn_sort_up: wrong mode\n"));
  }

  return cond;
}

struct conn_data *fwlw_pc_mergesort(struct conn_data *list) {
  struct conn_data *p, *q, *e, *tail;
  int size, merges, psize, qsize, i;

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
	  } else if (compare(p,q) <= 0) {
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
}

void sort_data(unsigned char mode)
{
  unsigned char i = 0, error;

  while ((i < MAXSORTSIZE) && (opt.sort_order[i] != '\0')) {
    error = 0;
    switch (opt.sort_order[i]) {
    case 'c':
      opt.sortfield = SORT_COUNT;
      break;
    case 't':
      opt.sortfield = SORT_START_TIME;
      break;
    case 'e':
      opt.sortfield = SORT_END_TIME;
      break;
    case 'z':
      opt.sortfield = SORT_DELTA_TIME;
      break;
    case 'n':
      opt.sortfield = SORT_CHAINLABEL;
      break;
    case 'p':
      opt.sortfield = SORT_PROTOCOL;
      break;
    case 'b':
      opt.sortfield = SORT_DATALEN;
      break;
    case 'S':
      opt.sortfield = SORT_SOURCEHOST;
      break;
    case 's':
      opt.sortfield = SORT_SOURCEPORT;
      break;
    case 'D':
      opt.sortfield = SORT_DESTHOST;
      break;
    case 'd':
      opt.sortfield = SORT_DESTPORT;
      break;
    default:
      fprintf(stderr, _("Error in sort string: '%c', order expected, ignoring.\n"), opt.sort_order[i]);
      error = 1;
    }

    i++;
    if (opt.sort_order[i] != '\0') {
      switch (opt.sort_order[i]) {
      case 'a':
	opt.sortmode = ORDER_ASCENDING;
	break;
      case 'd':
	opt.sortmode = ORDER_DESCENDING;
	break;
      default:
	fprintf(stderr, _("Error in sort string: '%c', direction expected, ignoring.\n"), opt.sort_order[i]);
	error = 1;
      }
    } else {
      fprintf(stderr, _("Error in sort string, direction expected, ignoring.\n"));
      error = 1;
    }

    i++;
    if (error == 0) {
      if(mode == SORT_PC) {
        first = fwlw_pc_mergesort(first);
      } else {
        first_host = fwlw_hs_mergesort(first_host);
      }
      if (opt.verbose == 2)
	fprintf(stderr, ".");
    }
  }
}

void build_list()
{
  struct conn_data *this;
  char stime[TIMESIZE];

  if (opt.loghost == 0) {
    if (opt.hostname[0] != '\0') {
      if (strcmp(opt.hostname, opt.line->hostname) != 0) {
	opt.loghost = 1;
      }
    } else {
      xstrncpy(opt.hostname, opt.line->hostname, SHOSTLEN);
    }
  }

  if(opt.chains == 0) {
    if (opt.chainlabel[0] != '\0') {
      if (strncmp(opt.chainlabel, opt.line->chainlabel, SHORTLEN) != 0) {
	opt.chains = 1;
      }
    } else {
      xstrncpy(opt.chainlabel, opt.line->chainlabel, SHORTLEN);
    }
  }

  if(opt.branches == 0) {
    if (opt.branchname[0] != '\0') {
      if (strncmp(opt.branchname, opt.line->branchname, SHORTLEN) != 0) {
	opt.branches = 1;
      }
    } else {
      xstrncpy(opt.branchname, opt.line->branchname, SHORTLEN);
    }
  }

  if (opt.ifs == 0) {
    if (opt.interface[0] != '\0') {
      if (strncmp(opt.interface, opt.line->interface, SHORTLEN) != 0) {
	opt.ifs = 1;
      }
    } else {
      xstrncpy(opt.interface, opt.line->interface, SHORTLEN);
    }
  }

  this = first;
  while (this != NULL) {
    if ((opt.dst_ip) && (this->dhost.s_addr != opt.line->dhost.s_addr)) {goto no_match;}
    if ((opt.src_ip) && (this->shost.s_addr != opt.line->shost.s_addr)) {goto no_match;}
    if ((opt.dst_port) && (this->dport != opt.line->dport)) {goto no_match;}
    if ((opt.src_port) && (this->sport != opt.line->sport)) {goto no_match;}
    if ((opt.proto) && (this->protocol != opt.line->protocol)) {goto no_match;}
    if ((opt.opts) && (this->flags != opt.line->flags)) {goto no_match;}
    if (strcmp(this->interface, opt.line->interface) != 0) {goto no_match;}
    if (strcmp(this->branchname, opt.line->branchname) != 0) {goto no_match;}
    if (strcmp(this->chainlabel, opt.line->chainlabel) != 0) {goto no_match;}
    if (strcmp(this->hostname, opt.line->hostname) != 0) {goto no_match;}

    this->datalen = this->datalen + opt.line->datalen;
    if (opt.line->time >= this->end_time) {
      this->end_time = opt.line->time;
    } else {
      if(opt.verbose) {
	strftime(stime, TIMESIZE, _("%b %d %H:%M:%S"), localtime(&this->end_time));
	fprintf(stderr, _("Timewarp in log file (%s"), stime);
	strftime(stime, TIMESIZE, _("%b %d %H:%M:%S"), localtime(&opt.line->time));
	fprintf(stderr, " < %s).\n", stime);
      }
    }

    this->count += opt.line->count;
    return;

  no_match: this = this->next;
  }

  add_entry();
}

int list_stats()
{
  struct conn_data *this;
  int count = 0;

  this = first;
  while (this != NULL) {
    ++count;
    this = this->next;
  }
  return count;
}

void show_list(FILE *fd)
{
  struct conn_data *this;
  int max = 0;

  this = first;
  while ((this != NULL) && (opt.max == 0 || max < opt.max || opt.mode == INTERACTIVE_REPORT)) {
    if(this->count >= opt.least && (opt.mode != INTERACTIVE_REPORT || this->count > opt.threshold)) {
      if (opt.html) {
	output_html_entry(this, fd);
	if (opt.html == 1) {
	  opt.html = 2;
	} else {
	  opt.html = 1;
	}
      } else {
	output_text_entry(this, fd);
      }
    }
    if (opt.max != 0)
      max++;
    this = this->next;
  }
}
