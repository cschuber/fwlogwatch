/* $Id: resolve.c,v 1.22 2002/03/29 11:25:52 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
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
      fprintf(stderr, _("port mismatch: %d != %d\n"), p, port);
    } else {
      return (servent->s_name);
    }
  }
  return ("-");
}

char * resolve_hostname(struct in_addr ip)
{
  struct hostent *reverse, *forward;
  struct dns_cache *dns;
  char *pnt;

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

  dns = xmalloc(sizeof(struct dns_cache));
  dns->ip.s_addr = ip.s_addr;

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
	xstrncpy(dns->fqdn, reverse->h_name, HOSTLEN);
      } else {
	snprintf(dns->fqdn, HOSTLEN, _("%s [forward lookup: %s]"), reverse->h_name, inet_ntoa(*(struct in_addr *)forward->h_addr_list[0]));
      }
    } else {
      snprintf(dns->fqdn, HOSTLEN, _("%s [forward lookup failed]"), reverse->h_name);
    }
  } else {
    xstrncpy(dns->fqdn, "-", HOSTLEN);
  }

  dns->next = dns_first;
  dns_first = dns;

  return (dns->fqdn);
}
