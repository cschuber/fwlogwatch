/* $Id: whois.c,v 1.2 2002/02/14 21:36:54 bwess Exp $ */

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

struct whois_entry *whois_first = NULL;
extern struct options opt;

int whois_get_type(int sock, char *type)
{
  int cnt = 0, retval = -1;
  char c, buffer[CMDLEN];

  read(sock, &c, 1);
  while ((c != '\n') && (c != EOF) && (cnt < CMDLEN)) {
    buffer[cnt] = c;
    cnt++;
    read(sock, &c, 1);
  }

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

  return(retval);
}

void whois_read_socket(int sock, char *buf, int len)
{
  int cnt = 0, retval;

  bzero(buf, len);
  while (cnt < len) {
    retval = read(sock, (char *)(buf+cnt), (len-cnt));
    cnt += retval;
  }
  *(buf+len) = '\0';
#ifdef WHOIS_DEBUG
  fprintf(stderr, "--- WHOIS_DEBUG ---\n%s--- WHOIS_DEBUG ---\n", buf);
  fflush(stdout);
#endif
}

char *whois_read_data(int sock)
{
  int retval;
  char type, *data = NULL;

  while (1) {
    retval = whois_get_type(sock, &type);
    if(type == 'A') {
      data = xmalloc(retval+1);
      whois_read_socket(sock, data, retval);
    } else {
      break;
    }
  }

  return (data);
}

char *whois_get_from_as(int sock, int asn)
{
  char cmdstr[CMDLEN], *data;

  snprintf(cmdstr, CMDLEN, "!man,AS%d\n", asn);
  write(sock, cmdstr, strlen(cmdstr));
  data = whois_read_data(sock);

  return (data);
}

unsigned char whois_search_desc(int sock, struct whois_entry *we)
{
  char *obj, *descs, *desce;
  unsigned char ok = 0;

  obj = whois_get_from_as(sock, we->as_number);
  if (obj != NULL) {
    descs = strstr(obj, "descr:");
    if (descs != NULL) {
      descs += 6;
      while ((*descs == ' ') || (*descs == '\t'))
	descs++;
      desce = strchr(descs, '\n');
      if (desce != NULL)
	*desce = '\0';
      strncpy(we->as_descr, descs, SHOSTLEN);
      ok++;
    }
    free(obj);
  }

  return(ok);
}

void whois_from_ip(struct in_addr ip, struct whois_entry *we)
{
  unsigned char status = 0;
  char cmdstr[CMDLEN], *data, *descs, *desce;
  int sock, retval;
  struct hostent *he;
  struct sockaddr_in sin;

  he = gethostbyname(RADB);
  if (he == NULL) {
    printf(_("lookup failed: %s\n"), RADB);
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
  snprintf(cmdstr, CMDLEN, "!r%s/32,l\n", inet_ntoa(ip));
  write(sock, cmdstr, strlen(cmdstr));
  data = whois_read_data(sock);

  if (data != NULL) {
    descs = desce = data;
    while (*descs != '\0') {
      if (strstr(descs, "origin:") == descs) {
	descs += 7;
	while ((*descs == ' ') || (*descs == '\t'))
	  descs++;
	descs += 2;
	desce = strchr(descs, '\n');
	if (desce != NULL)
	  *desce = '\0';
	we->as_number = atoi(descs);
	if(we->as_number > 0)
	  status++;
	if(whois_search_desc(sock, we) == 1)
	  status++;
	descs = desce + 1;
      } else if (strstr(descs, "route:") == descs) {
	descs += 6;
	while ((*descs == ' ') || (*descs == '\t'))
	  descs++;
	desce = strchr(descs, '\n');
	if (desce != NULL)
	  *desce = '\0';
	strncpy(we->ip_route, descs, SHOSTLEN);
	descs = desce + 1;
	status++;
      } else if (strstr(descs, "descr:") == descs) {
	descs += 6;
	while ((*descs == ' ') || (*descs == '\t'))
	  descs++;
	desce = strchr(descs, '\n');
	if (desce != NULL)
	  *desce = '\0';
	strncpy(we->ip_descr, descs, SHOSTLEN);
	descs = desce + 1;
	status++;
      } else {
	descs++;
      }
    }
    free(data);
  }
  write(sock, "q\n", 2);
  retval = close(sock);
  if(retval == -1)
    perror("close");

  if(status != 4)
    we->as_number = 0;
}

struct whois_entry * whois(struct in_addr ip)
{
  char adds[IPLEN];
  struct in_addr net, addr;
  struct whois_entry *we;

  if((ip.s_addr == 0) /* 0.0.0.0 */
     || ((ip.s_addr & 0x000000FF) == 0x0000007F) /* 127. */
     || ((ip.s_addr & 0x000000FF) == 0x0000000A) /* 10. */
     || ((ip.s_addr & 0x0000FFFF) == 0x00008A0C) /* 192.168. */
     || (ip.s_addr == 0xFFFFFFFF)) /* 255.255.255.255 */
    return NULL;

  we = whois_first;
  while(we != NULL) {
    strncpy(adds, we->ip_route, IPLEN);
    net.s_addr = ip.s_addr & parse_cidr(adds);
    convert_ip(adds, &addr);
    if (addr.s_addr == net.s_addr) {
      if(opt.verbose)
        fprintf(stderr, _("Looking up whois info for %s from cache\n"), inet_ntoa(ip));
      return (we);
    }
    we = we->next;
  }
 
  if(opt.verbose)
    fprintf(stderr, _("Looking up whois info for %s\n"), inet_ntoa(ip));
 
  we = xmalloc(sizeof(struct whois_entry));
  whois_from_ip(ip, we);
  if (we->as_number != 0) {
    we->next = whois_first;
    whois_first = we;
    return(we);
  } else {
    return(NULL);
  }
}
