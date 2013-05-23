/* Copyright (C) 2000-2013 Boris Wesslowski */
/* $Id: whois.c,v 1.17 2013/05/23 15:04:15 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef SOLARIS
#include <string.h>
#else
#include <strings.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include "main.h"
#include "utils.h"

#define QUAD2IP(a,b,c,d) ((a) | (b)<<8 | (c<<16) | (d)<<24)
#define PREFIX2MASK(n) (~0U>>(32-(n)))

struct whois_entry *whois_first = NULL;
extern struct options opt;

int whois_get_type(char *type)
{
  int cnt = 0, retval = -1;
  char buffer[WHOISCMDLEN];
  signed char c;

  read(opt.whois_sock, &c, 1);
  while ((c != '\n') && (c != EOF) && (cnt < WHOISCMDLEN)) {
    buffer[cnt] = c;
    cnt++;
    read(opt.whois_sock, &c, 1);
  }
  buffer[cnt] = '\0';

  switch (buffer[0]) {
  case 'A':
    *type = buffer[0];
    retval = atoi(&buffer[1]);
    break;
  case 'C':
    *type = buffer[0];
    retval = 0;
    break;
  default:
    *type = '\0';
  }

  return (retval);
}

void whois_read_socket(char *buf, int len)
{
  int cnt = 0, retval;

  bzero(buf, len);
  while (cnt < len) {
    retval = read(opt.whois_sock, (char *) (buf + cnt), (len - cnt));
    cnt += retval;
  }
  *(buf + len) = '\0';
#ifdef WHOIS_DEBUG
  fprintf(stderr, "--- WHOIS_DEBUG ---\n%s--- WHOIS_DEBUG ---\n", buf);
  fflush(stdout);
#endif
}

char *whois_read_data()
{
  int retval;
  char type, *data = NULL;

  while (1) {
    retval = whois_get_type(&type);
    if (type == 'A') {
      data = xmalloc(retval + 1);
      whois_read_socket(data, retval);
    } else {
      break;
    }
  }

  return (data);
}

char *whois_get_from_as(int asn)
{
  char cmdstr[WHOISCMDLEN], *data;

  snprintf(cmdstr, WHOISCMDLEN, "!man,AS%d\n", asn);
  write(opt.whois_sock, cmdstr, strlen(cmdstr));
  data = whois_read_data();

  return (data);
}

void whois_search_desc(struct whois_entry *we)
{
  char *obj, *descs, *desce;

  obj = whois_get_from_as(we->as_number);
  if (obj != NULL) {
    descs = strstr(obj, "descr:");
    if (descs != NULL) {
      descs += 6;
      while ((*descs == ' ') || (*descs == '\t'))
	descs++;
      desce = strchr(descs, '\n');
      if (desce != NULL)
	*desce = '\0';
      we->as_descr = xmalloc(strlen(descs) + 1);
      xstrncpy(we->as_descr, descs, strlen(descs) + 1);
    }
    free(obj);
  }
}

void whois_from_ip(struct in6_addr ip, struct whois_entry *we)
{
  char cmdstr[WHOISCMDLEN], *data, *descs, *desce;

  we->as_number = 0;
  we->ip_route = NULL;
  we->ip_descr = NULL;
  we->as_descr = NULL;

  snprintf(cmdstr, WHOISCMDLEN, "!r%s/32,l\n", my_inet_ntop(&ip));
  write(opt.whois_sock, cmdstr, strlen(cmdstr));
  data = whois_read_data();

  if (data != NULL) {
    descs = data;
    while (*descs != '\0') {
      if ((we->as_number == 0) && (strstr(descs, "origin:") == descs)) {
	descs += 7;
	while ((*descs == ' ') || (*descs == '\t'))
	  descs++;
	descs += 2;
	desce = strchr(descs, '\n');
	if (desce != NULL)
	  *desce = '\0';
	we->as_number = atoi(descs);
	whois_search_desc(we);
	descs = desce + 1;
      } else if ((we->ip_route == NULL) && ((strstr(descs, "route:") == descs) || (strstr(descs, "route6:") == descs))) {
	descs += 7;
	while ((*descs == ' ') || (*descs == '\t'))
	  descs++;
	desce = strchr(descs, '\n');
	if (desce != NULL)
	  *desce = '\0';
	we->ip_route = xmalloc(strlen(descs) + 1);
	xstrncpy(we->ip_route, descs, strlen(descs) + 1);
	descs = desce + 1;
      } else if ((we->ip_descr == NULL) && (strstr(descs, "descr:") == descs)) {
	descs += 6;
	while ((*descs == ' ') || (*descs == '\t'))
	  descs++;
	desce = strchr(descs, '\n');
	if (desce != NULL)
	  *desce = '\0';
	we->ip_descr = xmalloc(strlen(descs) + 1);
	xstrncpy(we->ip_descr, descs, strlen(descs) + 1);
	descs = desce + 1;
      } else {
	descs++;
      }
    }
    free(data);
  }

  if (we->as_number > 0) {
    if (we->ip_route == NULL) {
      we->ip_route = xmalloc(2);
      xstrncpy(we->ip_route, "-", 2);
    }
    if (we->ip_descr == NULL) {
      we->ip_descr = xmalloc(2);
      xstrncpy(we->ip_descr, "-", 2);
    }
    if (we->as_descr == NULL) {
      we->as_descr = xmalloc(2);
      xstrncpy(we->as_descr, "-", 2);
    }
  }
}

struct whois_entry *whois(struct in6_addr ip)
{
  char saddrt[WHOISROUTELEN];
  struct in6_addr in6_mask, in6_addrt, in6_net;
  struct whois_entry *we;
  int i;

  if (opt.whois_sock == -1)
    return NULL;

  if (isV4mappedV6addr(&ip)) {
    if ((ip.s6_addr32[3] == QUAD2IP(0, 0, 0, 0))
	|| ((ip.s6_addr32[3] & PREFIX2MASK(8)) == QUAD2IP(127, 0, 0, 0))
	|| ((ip.s6_addr32[3] & PREFIX2MASK(8)) == QUAD2IP(10, 0, 0, 0))
	|| ((ip.s6_addr32[3] & PREFIX2MASK(12)) == QUAD2IP(172, 16, 0, 0))
	|| ((ip.s6_addr32[3] & PREFIX2MASK(16)) == QUAD2IP(192, 168, 0, 0))
	|| (ip.s6_addr32[3] == QUAD2IP(255, 255, 255, 255)))
      return NULL;
  } else {
    if ((ip.s6_addr[0] & 0xE0) != 0x20)
      return NULL;
  }

  we = whois_first;
  while (we != NULL) {
    xstrncpy(saddrt, we->ip_route, WHOISROUTELEN);
    parse_cidr(saddrt, &in6_mask);
    for (i = 0; i < 16; i++)
      in6_addrt.s6_addr[i] = ip.s6_addr[i] & in6_mask.s6_addr[i];
    convert_ip(saddrt, &in6_net);
    if (compare_ipv6_equal(&in6_addrt, &in6_net) == 0) {
      if (opt.verbose)
	fprintf(stderr, _("Looking up whois info for %s(/%d) from cache\n"), my_inet_ntop(&ip), convert_mask(&in6_mask));
      return (we);
    }
    we = we->next;
  }

  if (opt.verbose)
    fprintf(stderr, _("Looking up whois info for %s\n"), my_inet_ntop(&ip));

  we = xmalloc(sizeof(struct whois_entry));
  whois_from_ip(ip, we);
  if (we->as_number != 0) {
    we->next = whois_first;
    whois_first = we;
    return (we);
  } else {
    return (NULL);
  }
}

void whois_connect(const char *whois_server)
{
  struct hostent *he;
  struct sockaddr_in sin;
  int sock, retval;

  he = gethostbyname(whois_server);
  if (he == NULL) {
    fprintf(stderr, _("lookup failed: %s\n"), whois_server);
    exit(EXIT_FAILURE);
  }

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons(WHOIS);
  bcopy(he->h_addr, &sin.sin_addr, he->h_length);

  retval = connect(sock, (struct sockaddr *) &sin, sizeof(sin));
  if (retval == -1) {
    perror("connect");
    exit(EXIT_FAILURE);
  }

  write(sock, "!!\n", 3);
  opt.whois_sock = sock;
}

void whois_close()
{
  int retval;

  write(opt.whois_sock, "q\n", 2);
  retval = close(opt.whois_sock);
  if (retval == -1)
    perror("close");
  opt.whois_sock = -1;
}
