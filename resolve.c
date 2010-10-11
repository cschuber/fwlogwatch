/* Copyright (C) 2000-2006 Boris Wesslowski */
/* $Id: resolve.c,v 1.30 2010/10/11 12:17:44 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>

#ifdef HAVE_ADNS
#include <adns.h>
#include <errno.h>
#endif

#include "resolve.h"
#include "main.h"
#include "utils.h"

struct dns_cache *dns_first = NULL;
extern struct options opt;

#ifdef HAVE_ADNS
extern struct conn_data *first;
extern struct known_hosts *first_host;
adns_state adns;
struct adns_entry {
  struct in_addr ip;
  adns_query query;
  struct adns_entry *next;
} *adnse_first = NULL;
#endif

char * resolve_protocol(int proto)
{
  struct protoent *protoent;

  protoent = getprotobynumber(proto);
  if (protoent != NULL) {
    return (protoent->p_name);
  } else {
    char *number;
    number = xmalloc(4);
    snprintf(number, 4, "%d", proto);
    return (number);
  }
}

char * resolve_service(int port, char *proto)
{
  struct servent *servent;
  int p;

  p = htons(port);
  servent = getservbyport(p, proto);
  if (servent != NULL) {
    p = ntohs(servent->s_port);
    if (p != port) {
      fprintf(stderr, _("port mismatch: %d != %d\n"), p, port);
    } else {
      return (servent->s_name);
    }
  }
  return ("-");
}

#ifndef HAVE_ADNS
char * resolve_hostname(struct in_addr ip)
{
  struct hostent *reverse, *forward;
  struct dns_cache *dns;
  char *pnt, fqdn[HOSTLEN];

  dns = dns_first;
  while(dns != NULL) {
    if (ip.s_addr == dns->ip.s_addr) {
      if(opt.verbose) {
	fprintf(stderr, _("Resolving %s from cache\n"), inet_ntoa(ip));
      }
      return (dns->fqdn);
    }
    dns = dns->next;
  }

  if(opt.verbose)
    fprintf(stderr, _("Resolving %s\n"), inet_ntoa(ip));

  reverse = gethostbyaddr((void *)&ip.s_addr, sizeof(struct in_addr), AF_INET);

  if((reverse != NULL) && (reverse->h_name != NULL)) {
    if ((unsigned int)reverse->h_length > sizeof(struct in_addr)) {
      fprintf(stderr, _("Wrong host name size\n"));
      reverse->h_length = sizeof(struct in_addr);
      reverse->h_name[reverse->h_length] = '\0';
    }

    pnt = reverse->h_name;
    while (*pnt != '\0') {
      if (isalnum((int)*pnt) || *pnt == '.' || *pnt == '-') {
	pnt++;
	continue;
      } else {
	*pnt = '_';
	pnt++;
      }
    }

    if(opt.verbose)
      fprintf(stderr, _("Resolving %s\n"), reverse->h_name);

    forward = gethostbyname(reverse->h_name);
    if ((forward != NULL) && (forward->h_addr_list[0]) != NULL) {
      if (strncmp(inet_ntoa(ip), inet_ntoa(*(struct in_addr *)forward->h_addr_list[0]), IPLEN) == 0) {
	xstrncpy(fqdn, reverse->h_name, HOSTLEN);
      } else {
	snprintf(fqdn, HOSTLEN, _("%s [forward lookup: %s]"), reverse->h_name, inet_ntoa(*(struct in_addr *)forward->h_addr_list[0]));
      }
    } else {
      snprintf(fqdn, HOSTLEN, _("%s [forward lookup failed]"), reverse->h_name);
    }
  } else {
    xstrncpy(fqdn, "-", HOSTLEN);
  }

  dns = xmalloc(sizeof(struct dns_cache));
  dns->ip.s_addr = ip.s_addr;
  dns->fqdn = xmalloc(strlen(fqdn)+1);
  xstrncpy(dns->fqdn, fqdn, strlen(fqdn)+1);
  dns->next = dns_first;
  dns_first = dns;

  return (dns->fqdn);
}

#else

char * resolve_hostname(struct in_addr ip)
{
  struct dns_cache *dns;
  struct adns_entry *adnse;
  adns_answer *answer;
  char fqdn[HOSTLEN];

  dns = dns_first;
  while(dns != NULL) {
    if (ip.s_addr == dns->ip.s_addr) {
      if(opt.verbose)
	fprintf(stderr, _("Resolving %s from cache\n"), inet_ntoa(ip));
      return (dns->fqdn);
    }
    dns = dns->next;
  }

  adnse = adnse_first;
  while(adnse != NULL) {
    if(adnse->ip.s_addr == ip.s_addr) {
      errno = adns_wait(adns, &adnse->query, &answer, NULL);
      if(!errno) {
	if(opt.verbose)
	  fprintf(stderr, _("Resolving %s from adns\n"), inet_ntoa(ip));
	if(answer->status == adns_s_ok) {
	  xstrncpy(fqdn, *answer->rrs.str, HOSTLEN);
	} else if(answer->status == adns_s_inconsistent) {
	  xstrncpy(fqdn, _("[inconsistent forward lookup]"), HOSTLEN);
	} else if(answer->status == adns_s_nxdomain) {
	  xstrncpy(fqdn, "-", HOSTLEN);
	} else {
	  snprintf(fqdn, HOSTLEN, _("[adns status %d]"), answer->status);
	}
	free(answer);
	dns = xmalloc(sizeof(struct dns_cache));
	dns->ip.s_addr = ip.s_addr;
	dns->fqdn = xmalloc(strlen(fqdn)+1);
	xstrncpy(dns->fqdn, fqdn, strlen(fqdn)+1);
	dns->next = dns_first;
	dns_first = dns;
	return (dns->fqdn);
      } else {
	perror("adns_wait");
	break;
      }
    }
    adnse = adnse->next;
  }

  return _("DNS cache error");
}

void adns_list_add(struct in_addr ip)
{
  struct sockaddr_in sa;
  struct adns_entry *adnse;

  adnse = xmalloc(sizeof(struct adns_entry));
  adnse->ip.s_addr = ip.s_addr;
  bzero(&sa, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr = adnse->ip;
  adns_submit_reverse(adns, (struct sockaddr *)&sa, adns_r_ptr, 0, NULL, &adnse->query);
  adnse->next = adnse_first;
  adnse_first = adnse;

  if(opt.verbose == 2)
    fprintf(stderr, _("Submitted %s to adns\n"), inet_ntoa(adnse->ip));
}

void adns_check_entry(struct in_addr ip)
{
  struct dns_cache *dns;
  struct adns_entry *adnse;
  unsigned char found = 0;

  dns = dns_first;
  while(dns != NULL) {
    if (ip.s_addr == dns->ip.s_addr) {
      found++;
      break;
    }
    dns = dns->next;
  }
  if(!found) {
    adnse = adnse_first;
    while(adnse != NULL) {
      if(ip.s_addr == adnse->ip.s_addr) {
	found++;
	break;
      }
      adnse = adnse->next;
    }
  }
  if(!found)
    adns_list_add(ip);
}

void adns_preresolve(unsigned char mode)
{
  if(mode == RES_ADNS_PC) {
    int max = 0;
    struct conn_data *this;
    this = first;
    while((this != NULL) && (opt.max == 0 || max < opt.max)) {
      if(this->count >= opt.least) {
        if(opt.src_ip)
	  adns_check_entry(this->shost);
        if(opt.dst_ip)
	  adns_check_entry(this->dhost);
      }
      if (opt.max != 0)
        max++;
      this = this->next;
    }
  } else if(mode == RES_ADNS_HS) {
    struct known_hosts *this_host;
    this_host = first_host;
    while(this_host != NULL) {
      if(opt.src_ip)
	adns_check_entry(this_host->shost);
      if(opt.dst_ip)
	adns_check_entry(this_host->dhost);
      this_host = this_host->next;
    }
  }
}

#endif
