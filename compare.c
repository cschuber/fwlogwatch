/* $Id: compare.c,v 1.5 2002/02/14 20:36:55 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "compare.h"
#include "output.h"
#include "utils.h"

struct conn_data *first = NULL;
extern struct options opt;

void add_entry()
{
  struct conn_data *data;

  data = xmalloc(sizeof(struct conn_data));

  data->count = 1;
  data->start_time = opt.line->time;
  data->end_time = 0;
  strncpy(data->hostname, opt.line->hostname, SHOSTLEN);
  strncpy(data->chainlabel, opt.line->chainlabel, SHORTLEN);
  strncpy(data->branchname, opt.line->branchname, SHORTLEN);
  strncpy(data->interface, opt.line->interface, SHORTLEN);
  data->protocol = opt.line->protocol;
  strncpy(data->shost, opt.line->shost, IPLEN);
  data->sport = opt.line->sport;
  strncpy(data->dhost, opt.line->dhost, IPLEN);
  data->dport = opt.line->dport;
  data->syn = opt.line->syn;

  data->next = first;
  first = data;
}

void sort_list(int field, char mode)
{
  struct conn_data *prev, *this, *next;
  char changed = 1, start_of_chain, cond;

  while (changed) {
    changed = 0;
    start_of_chain = 1;

    prev = this = first;

    while (this != NULL && this->next != NULL) {
      next = this->next;

      cond = 0;
      switch(field) {
      case COUNT:
	if (mode) {
	  if (next->count > this->count)
	    cond = 1;
	} else {
	  if (next->count < this->count)
	    cond = 1;
	}
	break;
      case SOURCEHOST:
	if (mode) {
	  if (strncmp(this->shost, next->shost, IPLEN) < 0)
	    cond = 1;
	} else {
	  if (strncmp(next->shost, this->shost, IPLEN) < 0)
	    cond = 1;
	}
	break;
      case DESTHOST:
	if (mode) {
	  if (strncmp(this->dhost, next->dhost, IPLEN) < 0)
	    cond = 1;
	} else {
	  if (strncmp(next->dhost, this->dhost, IPLEN) < 0)
	    cond = 1;
	}
	break;
      case SOURCEPORT:
	if (mode) {
	  if (next->sport > this->sport)
	    cond = 1;
	} else {
	  if (next->sport < this->sport)
	    cond = 1;
	}
	break;
      case DESTPORT:
	if (mode) {
	  if (next->dport > this->dport)
	    cond = 1;
	} else {
	  if (next->dport < this->dport)
	    cond = 1;
	}
	break;
      case START_TIME:
	if (mode) {
	  if (next->start_time > this->start_time)
	    cond = 1;
	} else {
	  if (next->start_time < this->start_time)
	    cond = 1;
	}
	break;
      case DELTA_TIME:
	if (mode) {
	  if ((next->end_time - next->start_time) > (this->end_time - this->start_time))
	    cond = 1;
	} else {
	  if ((next->end_time - next->start_time) < (this->end_time - this->start_time))
	    cond = 1;
	}
	break;
      default:
	fprintf(stderr, "conn_sort_up: wrong mode\n");
      }

      if (cond == 1) {
	this->next = next->next;
	next->next = this;
	if (start_of_chain) {
	  prev = first = next;
	  --start_of_chain;
	} else {
	  prev->next = next;
	  prev = next;
	}
	changed = 1;
      } else {
	prev = this;
	this = next;
	if (start_of_chain)
	  --start_of_chain;
      }
    }
  }
}

void sort_data()
{
  unsigned char i = 0, error, field = 0, mode = 0;

  while (opt.sort_order[i] != '\0') {
    error = 0;
    switch (opt.sort_order[i]) {
    case 'c':
      field = COUNT;
      break;
    case 'S':
      field = SOURCEHOST;
      break;
    case 'D':
      field = DESTHOST;
      break;
    case 's':
      field = SOURCEPORT;
      break;
    case 'd':
      field = DESTPORT;
      break;
    case 't':
      field = START_TIME;
      break;
    case 'z':
      field = DELTA_TIME;
      break;
    default:
      fprintf(stderr, "Error in sort string: '%c', order expected, ignoring.\n", opt.sort_order[i]);
      error = 1;
    }

    i++;
    if (opt.sort_order[i] != '\0') {
      switch (opt.sort_order[i]) {
      case 'a':
	mode = SMALLERFIRST;
	break;
      case 'd':
	mode = BIGGERFIRST;
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
      sort_list(field, mode);
      if (opt.verbose == 2)
	fprintf(stderr, ".");
    }
  }
}

void build_list()
{
  struct conn_data *this;

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
    if ((opt.dst_port) && (this->dport != opt.line->dport)) {goto no_match;}
    if ((opt.src_port) && (this->sport != opt.line->sport)) {goto no_match;}
    if ((opt.proto) && (this->protocol != opt.line->protocol)) {goto no_match;}
    if ((opt.opts) && (this->syn != opt.line->syn)) {goto no_match;}
    if ((opt.src_ip) && (strncmp(this->shost, opt.line->shost, IPLEN) != 0)) {goto no_match;}
    if ((opt.dst_ip) && (strncmp(this->dhost, opt.line->dhost, IPLEN) != 0)) {goto no_match;}
    if (strncmp(this->interface, opt.line->interface, SHOSTLEN) != 0) {goto no_match;}
    if (strncmp(this->branchname, opt.line->branchname, SHOSTLEN) != 0) {goto no_match;}
    if (strncmp(this->chainlabel, opt.line->chainlabel, SHOSTLEN) != 0) {goto no_match;}
    if (strncmp(this->hostname, opt.line->hostname, SHOSTLEN) != 0) {goto no_match;}

    if (opt.line->time >= this->end_time) {
      this->end_time = opt.line->time;
    } else {
      fprintf(stderr, "\nTimewarp in log file (%d < %d), ignoring.\n", (int)opt.line->time, (int)this->end_time);
      return;
    }

    this->count++;
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
    if(this->count > opt.threshold) {
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
