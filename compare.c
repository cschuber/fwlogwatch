/* $Id: compare.c,v 1.12 2002/02/14 21:06:11 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "compare.h"
#include "output.h"
#include "utils.h"

struct conn_data *first = NULL;
extern struct options opt;

void add_entry()
{
  struct conn_data *data;

  data = xmalloc(sizeof(struct conn_data));

  data->count = opt.line->count;
  data->start_time = opt.line->time;
  data->end_time = 0;
  strncpy(data->hostname, opt.line->hostname, SHOSTLEN);
  strncpy(data->chainlabel, opt.line->chainlabel, SHORTLEN);
  strncpy(data->branchname, opt.line->branchname, SHORTLEN);
  strncpy(data->interface, opt.line->interface, SHORTLEN);
  data->protocol = opt.line->protocol;
  data->shost = opt.line->shost;
  data->sport = opt.line->sport;
  data->dhost = opt.line->dhost;
  data->dport = opt.line->dport;
  data->flags = opt.line->flags;

  data->next = first;
  first = data;
}

unsigned char compare(struct conn_data *op1, struct conn_data *op2)
{
  unsigned char cond = 0;

  switch(opt.sortfield) {
  case SORT_COUNT:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op2->count > op1->count) cond++;
    } else {
      if (op2->count < op1->count) cond++;
    }
    break;
  case SORT_START_TIME:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op2->start_time > op1->start_time) cond++;
    } else {
      if (op2->start_time < op1->start_time) cond++;
    }
    break;
  case SORT_DELTA_TIME:
    if (opt.sortmode == ORDER_ASCENDING) {
      if ((op2->end_time - op2->start_time) > (op1->end_time - op1->start_time)) cond++;
    } else {
      if ((op2->end_time - op2->start_time) < (op1->end_time - op1->start_time)) cond++;
    }
    break;
  case SORT_CHAINLABEL:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (strncmp(op1->chainlabel, op2->chainlabel, SHORTLEN) < 0) cond++;
    } else {
      if (strncmp(op1->chainlabel, op2->chainlabel, SHORTLEN) > 0) cond++;
    }
    break;
  case SORT_PROTOCOL:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op2->protocol > op1->protocol) cond++;
    } else {
      if (op2->protocol < op1->protocol) cond++;
    }
    break;
  case SORT_SOURCEHOST:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (ntohl(op2->shost.s_addr) > ntohl(op1->shost.s_addr)) cond++;
    } else {
      if (ntohl(op2->shost.s_addr) < ntohl(op1->shost.s_addr)) cond++;
    }
    break;
  case SORT_SOURCEPORT:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op2->sport > op1->sport) cond++;
    } else {
      if (op2->sport < op1->sport) cond++;
    }
    break;
  case SORT_DESTHOST:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (ntohl(op2->dhost.s_addr) > ntohl(op1->dhost.s_addr)) cond++;
    } else {
      if (ntohl(op2->dhost.s_addr) < ntohl(op1->dhost.s_addr)) cond++;
    }
    break;
  case SORT_DESTPORT:
    if (opt.sortmode == ORDER_ASCENDING) {
      if (op2->dport > op1->dport) cond++;
    } else {
      if (op2->dport < op1->dport) cond++;
    }
    break;
  default:
    fprintf(stderr, "conn_sort_up: wrong mode\n");
  }

  return cond;
}

struct conn_data *merge(struct conn_data *list1, struct conn_data *list2)
{
  if (list1 == NULL) return list2;
  else if (list2 == NULL) return list1;
  else if (compare(list1, list2)) {
    list1->next = merge(list1->next, list2);
    return list1;
  } else {
    list2->next = merge(list1, list2->next);
    return list2;
  }
}

struct conn_data *split(struct conn_data *list1)
{
  struct conn_data *list2;

  if (list1 == NULL) return NULL;
  else if (list1->next == NULL) return NULL;
  else  {
    list2 = list1->next;
    list1->next = list2->next;
    list2->next = split(list2->next);
    return list2;
  }
}

struct conn_data *mergesort(struct conn_data *list1)
{
  struct conn_data *list2;

  if (list1 == NULL) return NULL;
  else if (list1->next == NULL) return list1;
  else {
    list2 = split(list1);
    return merge(mergesort(list1), mergesort(list2));
  }
}

void sort_data()
{
  unsigned char i = 0, error;

  while (opt.sort_order[i] != '\0') {
    error = 0;
    switch (opt.sort_order[i]) {
    case 'c':
      opt.sortfield = SORT_COUNT;
      break;
    case 't':
      opt.sortfield = SORT_START_TIME;
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
      fprintf(stderr, "Error in sort string: '%c', order expected, ignoring.\n", opt.sort_order[i]);
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
	fprintf(stderr, "Error in sort string: '%c', direction expected, ignoring.\n", opt.sort_order[i]);
	error = 1;
      }
    } else {
      error = 1;
    }

    i++;
    if (error == 0) {
      first = mergesort(first);
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
      if (strncmp(opt.hostname, opt.line->hostname, SHOSTLEN) != 0) {
	opt.loghost = 1;
      }
    } else {
      strncpy(opt.hostname, opt.line->hostname, SHOSTLEN);
    }
  }

  if(opt.chains == 0) {
    if (opt.chainlabel[0] != '\0') {
      if (strncmp(opt.chainlabel, opt.line->chainlabel, SHORTLEN) != 0) {
	opt.chains = 1;
      }
    } else {
      strncpy(opt.chainlabel, opt.line->chainlabel, SHORTLEN);
    }
  }

  if(opt.branches == 0) {
    if (opt.branchname[0] != '\0') {
      if (strncmp(opt.branchname, opt.line->branchname, SHORTLEN) != 0) {
	opt.branches = 1;
      }
    } else {
      strncpy(opt.branchname, opt.line->branchname, SHORTLEN);
    }
  }

  if (opt.ifs == 0) {
    if (opt.interface[0] != '\0') {
      if (strncmp(opt.interface, opt.line->interface, SHORTLEN) != 0) {
	opt.ifs = 1;
      }
    } else {
      strncpy(opt.interface, opt.line->interface, SHORTLEN);
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
    if (strncmp(this->interface, opt.line->interface, SHORTLEN) != 0) {goto no_match;}
    if (strncmp(this->branchname, opt.line->branchname, SHORTLEN) != 0) {goto no_match;}
    if (strncmp(this->chainlabel, opt.line->chainlabel, SHORTLEN) != 0) {goto no_match;}
    if (strncmp(this->hostname, opt.line->hostname, SHOSTLEN) != 0) {goto no_match;}

    if (opt.line->time >= this->end_time) {
      this->end_time = opt.line->time;
    } else {
      if(opt.verbose) {
	strftime(stime, TIMESIZE, "%b %d %H:%M:%S", localtime(&this->end_time));
	fprintf(stderr, "Timewarp in log file (%s", stime);
	strftime(stime, TIMESIZE, "%b %d %H:%M:%S", localtime(&opt.line->time));
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

void show_list()
{
  struct conn_data *this;

  this = first;
  while (this != NULL) {
    if(this->count > opt.least && this->count > opt.threshold) {
      output_resolved(this);
      if (opt.html) {
	if (opt.html == 1) {
	  opt.html = 2;
	} else {
	  opt.html = 1;
	}
      }
    }
    this = this->next;
  }
}
