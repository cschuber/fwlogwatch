/* $Id: resolve.c,v 1.7 2002/02/14 20:45:42 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include "resolve.h"
#include "main.h"
#include "utils.h"

struct dns_cache *dns_first = NULL;
extern struct options opt;

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
      fprintf(stderr, "port mismatch: %d != %d\n", p, port);
    } else {
      return (servent->s_name);
    }
  }
  return ("-");
}

char * resolve_hostname(char *ip)
{
  struct hostent *reverse, *forward;
  struct in_addr inaddr;
  struct dns_cache *dns;
  char *pnt;
#ifndef SOLARIS
  int retval;
#endif

  dns = dns_first;
  while(dns != NULL) {
    if (strncmp(ip, dns->ip, IPLEN) == 0) {
      if(opt.verbose) {
	fprintf(stderr, "Resolving %s from cache\n", ip);
      }
      return (dns->fqdn);
    }
    dns = dns->next;
  }

#ifndef SOLARIS
  retval = inet_aton(ip, &inaddr);
  if (retval != 0) {
#else
#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
  inaddr.s_addr = inet_addr(ip);
  if (inaddr.s_addr != INADDR_NONE) {
#endif
    if(opt.verbose)
      fprintf(stderr, "Resolving %s\n", ip);

    reverse = gethostbyaddr((char *)&inaddr.s_addr, sizeof(struct in_addr), AF_INET);

    dns = xmalloc(sizeof(struct dns_cache));
    strncpy(dns->ip, ip, IPLEN);

    if((reverse != NULL) && (reverse->h_name != NULL)) {
      if (reverse->h_length > sizeof(struct in_addr)) {
	fprintf(stderr, "Wrong host name size\n");
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
	fprintf(stderr, "Resolving %s\n", reverse->h_name);

      forward = gethostbyname(reverse->h_name);
      if ((forward != NULL) && (forward->h_addr_list[0]) != NULL) {
	if (strncmp(ip, inet_ntoa(*(struct in_addr *)forward->h_addr_list[0]), IPLEN) == 0) {
	  strncpy(dns->fqdn, reverse->h_name, HOSTLEN);
	} else {
	  snprintf(dns->fqdn, HOSTLEN, "%s [forward lookup: %s]", reverse->h_name, inet_ntoa(*(struct in_addr *)forward->h_addr_list[0]));
	}
      } else {
	snprintf(dns->fqdn, HOSTLEN, "%s [forward lookup failed]", reverse->h_name);
      }
    } else {
      strncpy(dns->fqdn, "-", HOSTLEN);
    }

    dns->next = dns_first;
    dns_first = dns;
  }

  return (dns->fqdn);
}
