/* Copyright (C) 2000-2013 Boris Wesslowski */
/* $Id: resolve.c,v 1.33 2013/05/23 15:04:15 bwess Exp $ */

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
  struct in6_addr ip;
  adns_query query;
  struct adns_entry *next;
} *adnse_first = NULL;
#endif

char *resolve_protocol(int proto)
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

char *resolve_service(int port, char *proto)
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

char *resolve_address_sync(struct in6_addr ip)
{
  char *fqdn;

  int r;

  char hbuf[NI_MAXHOST];

  socklen_t len;

  void *sa;
  struct sockaddr_in6 *sai6;
  struct in6_addr in6a;

  unsigned char buf[sizeof(struct sockaddr_in6)];
  memset(&buf, 0, sizeof(struct sockaddr_in6));

  fqdn = xmalloc(HOSTLEN);

  memcpy(&in6a, &ip, sizeof(struct in6_addr));
  sai6 = (struct sockaddr_in6 *) &buf;
  sai6->sin6_addr = in6a;
  sai6->sin6_family = AF_INET6;
  len = sizeof(struct sockaddr_in6);
  sa = sai6;
  r = getnameinfo((struct sockaddr *) sa, len, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD);
  if (r == EAI_NONAME) {
    snprintf(fqdn, HOSTLEN, "-");
  } else if (r == EAI_AGAIN) {
    xstrncpy(fqdn, _("[timeout]"), HOSTLEN);
  } else if (r == EAI_FAIL) {
    xstrncpy(fqdn, _("[server failure]"), HOSTLEN);
  } else if (r != 0) {
    snprintf(fqdn, HOSTLEN, "[%s]", gai_strerror(r));
  } else {
    {
      struct addrinfo hints, *res, *rp;
      int s;
      char dst[HOSTLEN], dst2[HOSTLEN];

      if (opt.verbose)
	fprintf(stderr, _("Resolving %s\n"), hbuf);

      memset(&hints, 0, sizeof(struct addrinfo));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;

      s = getaddrinfo(hbuf, NULL, &hints, &res);
      if (s != 0) {
#ifdef DNS_DEBUG
	snprintf(fqdn, HOSTLEN, "%s [%s]", hbuf, gai_strerror(s));
#else
	snprintf(fqdn, HOSTLEN, _("%s [forward lookup failed]"), hbuf);
#endif
      } else {
	snprintf(fqdn, HOSTLEN, "%s", hbuf);
	for (rp = res; rp != NULL; rp = rp->ai_next) {
	  if (rp->ai_family == AF_INET && isV4mappedV6addr(&ip)) {
	    struct sockaddr_in *sin;
	    sin = (void *) rp->ai_addr;
	    if (ip.s6_addr32[3] != sin->sin_addr.s_addr) {
	      snprintf(dst2, HOSTLEN, _(" [v4 forward lookup: %s]"), inet_ntop(rp->ai_family, &sin->sin_addr, dst, HOSTLEN));
	      strncat(fqdn, dst2, HOSTLEN - strlen(fqdn) - 1);
	    }
	  } else if (rp->ai_family == AF_INET6 && !isV4mappedV6addr(&ip)) {
	    struct sockaddr_in6 *sin6;
	    sin6 = (void *) rp->ai_addr;
	    if (compare_ipv6_equal(&ip, &sin6->sin6_addr) != 0) {
	      snprintf(dst2, HOSTLEN, _(" [v6 forward lookup: %s]"), inet_ntop(rp->ai_family, &sin6->sin6_addr, dst, HOSTLEN));
	      strncat(fqdn, dst2, HOSTLEN - strlen(fqdn) - 1);
	    }
	  }
	}
	freeaddrinfo(res);
      }
    }
  }
  return (fqdn);
}

#ifdef HAVE_ADNS
char *resolve_address_async(struct in6_addr ip)
{
  struct adns_entry *adnse;
  adns_answer *answer;
  char *fqdn;

  fqdn = xmalloc(HOSTLEN);

  adnse = adnse_first;
  while (adnse != NULL) {
    if (compare_ipv6_equal(&adnse->ip, &ip) == 0) {
      errno = adns_wait(adns, &adnse->query, &answer, NULL);
      if (!errno) {
	if (answer->status == adns_s_ok) {
	  xstrncpy(fqdn, *answer->rrs.str, HOSTLEN);
	} else if (answer->status == adns_s_inconsistent || answer->status == adns_s_prohibitedcname || answer->status == adns_s_answerdomaininvalid) {
	  char *fqdn_sync;
	  fqdn_sync = resolve_address_sync(ip);
	  xstrncpy(fqdn, fqdn_sync, HOSTLEN);
	  free(fqdn_sync);
	} else if (answer->status == adns_s_timeout) {
	  xstrncpy(fqdn, _("[timeout]"), HOSTLEN);
	} else if (answer->status == adns_s_rcodeservfail) {
	  xstrncpy(fqdn, _("[server failure]"), HOSTLEN);
	} else if (answer->status == adns_s_nxdomain) {
	  xstrncpy(fqdn, "-", HOSTLEN);
	} else if (answer->status == adns_s_nodata) {
	  xstrncpy(fqdn, "-", HOSTLEN);
	} else {
	  snprintf(fqdn, HOSTLEN, _("[adns status %d]"), answer->status);
	}
	free(answer);
	return (fqdn);
      } else {
	perror("adns_wait");
	break;
      }
    }
    adnse = adnse->next;
  }

  xstrncpy(fqdn, _("[adns error]"), HOSTLEN);
  return (fqdn);
}
#endif

char *resolve_address(struct in6_addr ip)
{
  struct dns_cache *dns;
  char *fqdn;

  dns = dns_first;
  while (dns != NULL) {
    if (compare_ipv6_equal(&ip, &dns->ip) == 0) {
      if (opt.verbose)
	fprintf(stderr, _("Resolving %s from cache\n"), my_inet_ntop(&ip));
      return (dns->fqdn);
    }
    dns = dns->next;
  }
#ifndef HAVE_ADNS
  if (opt.verbose)
    fprintf(stderr, _("Resolving %s\n"), my_inet_ntop(&ip));

  fqdn = resolve_address_sync(ip);
#else
  if (opt.verbose)
    fprintf(stderr, _("Resolving %s from adns\n"), my_inet_ntop(&ip));

  fqdn = resolve_address_async(ip);
#endif

  dns = xmalloc(sizeof(struct dns_cache));
  memcpy(&dns->ip, &ip, sizeof(struct in6_addr));
  dns->fqdn = xmalloc(strlen(fqdn) + 1);
  xstrncpy(dns->fqdn, fqdn, strlen(fqdn) + 1);
  dns->next = dns_first;
  dns_first = dns;
  free(fqdn);
  return (dns->fqdn);
}

void init_dns_cache(struct in6_addr *ip, char *hostname)
{
  struct dns_cache *dns;
  dns = dns_first;
  while (dns != NULL) {
    if (compare_ipv6_equal(ip, &dns->ip) == 0) {
      if (opt.verbose == 2)
	fprintf(stderr, _("IP address %s is already in DNS cache\n"), my_inet_ntop(ip));
      return;
    }
    dns = dns->next;
  }
  if (opt.verbose == 2)
    fprintf(stderr, _("Adding IP address '%s' with host name '%s' to DNS cache\n"), my_inet_ntop(ip), hostname);
  dns = xmalloc(sizeof(struct dns_cache));
  memcpy(&dns->ip, ip, sizeof(struct in6_addr));
  dns->fqdn = xmalloc(strlen(hostname) + 1);
  xstrncpy(dns->fqdn, hostname, strlen(hostname) + 1);
  dns->next = dns_first;
  dns_first = dns;
}

#ifdef HAVE_ADNS

void adns_list_add(struct in6_addr *ip)
{
  struct adns_entry *adnse;
  struct sockaddr_in sa;
  struct sockaddr_in6 sa6;

  adnse = xmalloc(sizeof(struct adns_entry));

  memcpy(&adnse->ip, ip, sizeof(struct in6_addr));
  if (isV4mappedV6addr(ip)) {
    char buf[INET6_ADDRSTRLEN];
    bzero(&sa, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    inet_ntop(AF_INET, ip->s6_addr + 12, buf, INET_ADDRSTRLEN);
    inet_pton(AF_INET, buf, &sa.sin_addr);
    adns_submit_reverse(adns, (struct sockaddr *) &sa, adns_r_ptr, adns_qf_none, NULL, &adnse->query);
  } else {
    bzero(&sa6, sizeof(struct sockaddr_in6));
    sa6.sin6_family = AF_INET6;
    memcpy(&sa6.sin6_addr, ip, sizeof(struct in6_addr));
    adns_submit_reverse(adns, (struct sockaddr *) &sa6, adns_r_ptr, adns_qf_none, NULL, &adnse->query);
  }
  adnse->next = adnse_first;
  adnse_first = adnse;

  if (opt.verbose == 2)
    fprintf(stderr, _("Submitted %s to adns\n"), my_inet_ntop(&adnse->ip));
}

void adns_check_entry(struct in6_addr *ip)
{
  struct dns_cache *dns;
  struct adns_entry *adnse;
  unsigned char found = 0;

  dns = dns_first;
  while (dns != NULL) {
    if (compare_ipv6_equal(ip, &dns->ip) == 0) {
      found++;
      break;
    }
    dns = dns->next;
  }
  if (!found) {
    adnse = adnse_first;
    while (adnse != NULL) {
      if (compare_ipv6_equal(ip, &adnse->ip) == 0) {
	found++;
	break;
      }
      adnse = adnse->next;
    }
  }
  if (!found)
    adns_list_add(ip);
}

void adns_preresolve(unsigned char mode)
{
  if (mode == RES_ADNS_PC) {
    int max = 0;
    struct conn_data *this;
    this = first;
    while ((this != NULL) && (opt.max == 0 || max < opt.max)) {
      if (this->count >= opt.least) {
	if (opt.src_ip)
	  adns_check_entry(&this->shost);
	if (opt.dst_ip)
	  adns_check_entry(&this->dhost);
      }
      if (opt.max != 0)
	max++;
      this = this->next;
    }
  } else if (mode == RES_ADNS_HS) {
    struct known_hosts *this_host;
    this_host = first_host;
    while (this_host != NULL) {
      if (opt.src_ip)
	adns_check_entry(&this_host->shost);
      if (opt.dst_ip)
	adns_check_entry(&this_host->dhost);
      this_host = this_host->next;
    }
  }
}

#endif

struct in6_addr *resolve_hostname_from_cache(char *name)
{
  struct dns_cache *dns;

  dns = dns_first;
  while (dns != NULL) {
    if (strcmp(dns->fqdn, name) == 0) {
      if (opt.verbose == 2)
	fprintf(stderr, _("Resolving %s from cache\n"), name);
      return &dns->ip;
    }
    dns = dns->next;
  }

  return NULL;
}
