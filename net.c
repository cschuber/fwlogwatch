/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: net.c,v 1.32 2016/02/19 16:09:27 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef SOLARIS
#include <string.h>
#else
#include <strings.h>
#include <limits.h>
#endif

#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#ifndef __APPLE__
#ifndef __OpenBSD__
#ifndef __FreeBSD__
#ifndef __NetBSD__
#include <crypt.h>
#endif
#endif
#endif
#endif

#ifndef INT_MAX
#include <limits.h>
#endif

#include "utils.h"
#include "output.h"
#include "response.h"
#include "resolve.h"
#include "compare.h"
#include "utils.h"

extern struct options opt;
extern struct conn_data *first;
extern struct known_hosts *first_host;

void secure_read(int file, char *data_out, int maxlen)
{
  int j = 0, retval;
  signed char c;

  bzero(data_out, maxlen);
  retval = read(file, &c, 1);
  while ((retval != 0) && !(c == EOF || c == '\n') && (j < (maxlen - 1))) {
    data_out[j++] = c;
    retval = read(file, &c, 1);
  }
  if (j > 0)
    data_out[--j] = 0;
}

void prepare_socket()
{
  int retval, x;
  struct sockaddr_in6 sain6;
  struct in6_addr in6a;

  opt.sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (opt.sock == -1) {
    syslog(LOG_NOTICE, "socket: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  retval = setsockopt(opt.sock, SOL_SOCKET, SO_REUSEADDR, (void *) &x, sizeof(x));
  if (retval == -1) {
    syslog(LOG_NOTICE, "setsockopt: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }
  retval = inet_pton(AF_INET6, opt.listenif, in6a.s6_addr);
  if (retval != 1) {
    char nnb[HOSTLEN];
    snprintf(nnb, HOSTLEN, "::ffff:%s", opt.listenif);
    retval = inet_pton(AF_INET6, nnb, in6a.s6_addr);
    if (retval != 1) {
      syslog(LOG_NOTICE, "inet_pton: Bad address %s", opt.listenif);
      log_exit(EXIT_FAILURE);
    }
  }

  bzero(&sain6, sizeof(sain6));
  sain6.sin6_family = AF_INET6;
  sain6.sin6_port = htons(opt.listenport);
  sain6.sin6_addr = in6a;

  retval = bind(opt.sock, (struct sockaddr *) &sain6, sizeof(sain6));
  if (retval == -1) {
    syslog(LOG_NOTICE, "bind: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  retval = listen(opt.sock, 1);
  if (retval == -1) {
    syslog(LOG_NOTICE, "listen: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }
  syslog(LOG_NOTICE, _("Listening on %s port %i"), my_inet_ntop(&sain6.sin6_addr), ntohs(sain6.sin6_port));

  if (opt.listento[0] != '\0') {
    syslog(LOG_NOTICE, _("Connections are only allowed from %s"), opt.listento);
  }
}

/*
  RFC 1945 Hypertext Transfer Protocol -- HTTP/1.0
  Chapter 11.1. Basic Authentication Scheme

  RFC 1521 MIME (Multipurpose Internet Mail Extensions) Part One
  Chapter 5.2. Base64 Content-Transfer-Encoding
*/
void decode_base64(char *input)
{
  int i, j = 0, k;
  unsigned char a[4], b[4], o[3], c, dtable[256];
  char buf[80], *pnt;

  pnt = buf;

  for (i = 0; i < 255; i++) {
    dtable[i] = 0x80;
  }
  for (i = 'A'; i <= 'Z'; i++) {
    dtable[i] = 0 + (i - 'A');
  }
  for (i = 'a'; i <= 'z'; i++) {
    dtable[i] = 26 + (i - 'a');
  }
  for (i = '0'; i <= '9'; i++) {
    dtable[i] = 52 + (i - '0');
  }
  dtable['+'] = 62;
  dtable['/'] = 63;
  dtable['='] = 0;

  while (1) {
    for (i = 0; i < 4; i++) {
      c = input[j];
      if (c == '\0') {
	if (i > 0) {
	  syslog(LOG_NOTICE, _("decode_base64: input string incomplete"));
	  return;
	}
	xstrncpy(input, buf, strlen(input));
	return;
      }
      if (dtable[c] & 0x80) {
	syslog(LOG_NOTICE, _("decode_base64: illegal character '%c' in input string"), c);
	return;
      }
      a[i] = c;
      b[i] = dtable[c];
      j++;
    }
    o[0] = (b[0] << 2) | (b[1] >> 4);
    o[1] = (b[1] << 4) | (b[2] >> 2);
    o[2] = (b[2] << 6) | b[3];
    i = (a[2] == '=') ? 1 : ((a[3] == '=') ? 2 : 3);
    for (k = 0; k < i; k++) {
      *pnt = o[k];
      pnt++;
    }
    *pnt = '\0';
    if (i < 3) {
      xstrncpy(input, buf, strlen(input));
      return;
    }
  }
}

void put_entry(int conn, char *field, char sort, unsigned char mode)
{
  if ((mode == NO_SORTING) || (sort == 0)) {
    fdprintf(conn, "<th>%s</th>\n", field);
  } else {
    fdprintf(conn, "<th>%s<br /><a href=\"?sort=%ca\">&lt;</a>&nbsp;<a href=\"?sort=%cd\">&gt;</a></th>\n", field, sort, sort);
  }
}

void table_header(int conn, unsigned char mode, unsigned char opts)
{
  fdprintf(conn, "<table cellspacing=\"1\" cellpadding=\"3\">\n<tr>\n");
  put_entry(conn, _("count"), 'c', mode);
  put_entry(conn, _("added"), 't', mode);
  if (opt.proto)
    put_entry(conn, _("proto"), 'p', mode);
  if ((opts == NET_OPTS_PC) && (opt.datalen))
    put_entry(conn, _("bytes"), 'b', mode);
  put_entry(conn, _("source"), 'S', mode);
  if (opt.resolve)
    put_entry(conn, _("hostname"), 0, mode);
#ifdef HAVE_GEOIP
  if (opt.geoip)
    put_entry(conn, _("geoip"), 0, mode);
#endif
  if (opt.src_port) {
    put_entry(conn, _("port"), 's', mode);
    if (opt.sresolve)
      put_entry(conn, _("service"), 0, mode);
  }
  if (opt.dst_ip) {
    put_entry(conn, _("destination"), 'D', mode);
    if (opt.resolve)
      put_entry(conn, _("hostname"), 0, mode);
#ifdef HAVE_GEOIP
    if (opt.geoip)
      put_entry(conn, _("geoip"), 0, mode);
#endif
  }
  if (opt.dst_port) {
    put_entry(conn, _("port"), 'd', mode);
    if (opt.sresolve)
      put_entry(conn, _("service"), 0, mode);
  }
  if ((opts == NET_OPTS_PC) && (opt.opts))
    put_entry(conn, _("opts"), 'z', mode);
  put_entry(conn, _("time remaining"), 'e', mode);
  put_entry(conn, _("action"), 0, mode);
  fdprintf(conn, "</tr>\n");
}

void make_header_h2(int conn, char *text)
{
  fdprintf(conn, "<h2>%s</h2>\n", text);
}

void make_link(int conn, char *text, char *url)
{
  fdprintf(conn, "<a href=\"%s\">%s</a>", url, text);
}

void make_gen_table_int(int conn, char *desc, int current)
{
  fdprintf(conn, "<tr class=\"r1\"><td align=\"right\">%s:</td><td align=\"left\">%d</td></tr>\n", desc, current);
}

void make_gen_table_str(int conn, char *desc, char *current)
{
  fdprintf(conn, "<tr class=\"r1\"><td align=\"right\">%s:</td><td align=\"left\">%s</td></tr>\n", desc, current);
}

void make_opt_table_start(int conn, char *desc, char *opt)
{
  fdprintf(conn, "<tr class=\"r1\"><td align=\"right\">%s:</td><td><a href=\"?%s=l\">&lt;</a></td><td>", desc, opt);
}

void make_opt_table_end(int conn, char *opt)
{
  fdprintf(conn, "</td><td><a href=\"?%s=m\">&gt;</a></td></tr>\n", opt);
}

void make_opt_table_int(int conn, char *desc, char *opt, int current)
{
  make_opt_table_start(conn, desc, opt);
  fdprintf(conn, "%d", current);
  make_opt_table_end(conn, opt);
}

void make_opt_table_str(int conn, char *desc, char *opt, char *current)
{
  make_opt_table_start(conn, desc, opt);
  fdprintf(conn, "%s", current);
  make_opt_table_end(conn, opt);
}

void show_navigation(int conn)
{
  fdprintf(conn, "<p>[ ");
  if (opt.webpage == 'i') {
    fdprintf(conn, _("Information"));
  } else {
    make_link(conn, _("Information"), "?page=i");
  }
  fdprintf(conn, " | ");
  if (opt.webpage == 'o') {
    fdprintf(conn, _("Options"));
  } else {
    make_link(conn, _("Options"), "?page=o");
  }
  fdprintf(conn, " | ");
  if (opt.webpage == 'p') {
    fdprintf(conn, _("Packet cache"));
  } else {
    make_link(conn, _("Packet cache"), "?page=p");
  }
  fdprintf(conn, " | ");
  if (opt.webpage == 'h') {
    fdprintf(conn, _("Host status"));
  } else {
    make_link(conn, _("Host status"), "?page=h");
  }
  fdprintf(conn, " | ");
  make_link(conn, _("Reload"), "/");
  fdprintf(conn, " ]</p>\n");
}

void http_header(int conn, char *code, unsigned char complete)
{
  fdprintf(conn, "HTTP/1.1 %s\r\n", code);
  fdprintf(conn, "Server: %s/%s (C) %s\r\n", PACKAGE, VERSION, COPYRIGHT);
  fdprintf(conn, "Connection: close\r\n");
  fdprintf(conn, "Content-Type: text/html; charset=utf-8\r\n");
  if (complete == HEADER_COMPLETE)
    fdprintf(conn, "\r\n");

/*
  Date: Mon, 07 Jul 2003 21:27:17 GMT
  Last-Modified: Mon, 07 Jul 2003 21:25:26 GMT
  Accept-Ranges: bytes
  Content-Length: 80
*/
}

void basic_html_body(int conn, char *title, char *header)
{
  fdprintf(conn, "<html>\n<head>\n<title>%s</title>\n</head>\n", title);
  fdprintf(conn, "<body>\n<h1>%s</h1>\n</body>\n</html>\n", header);
}

void show_status(int conn, int linenum, int hitnum, int ignored)
{
  char buf[BUFSIZE], nows[TIMESIZE];
  struct conn_data *this;
  struct known_hosts *this_host;
  unsigned char color = 1;
  time_t now;
  int count = 0, max = 0;

  http_header(conn, "200 OK", HEADER_COMPLETE);

  output_html_header(conn);
  show_navigation(conn);

  now = time(NULL);

  if (opt.webpage == 'i') {
    make_header_h2(conn, _("Information"));

    fdprintf(conn, "<table cellspacing=\"1\" cellpadding=\"3\">\n");

    strftime(nows, TIMESIZE, _("%A %B %d %H:%M:%S %Z %Y"), localtime(&opt.now));
    make_gen_table_str(conn, _("Daemon start time"), nows);

    strftime(nows, TIMESIZE, _("%A %B %d %H:%M:%S %Z %Y"), localtime(&now));
    make_gen_table_str(conn, _("Current time"), nows);

    output_timediff(opt.now, now, nows);
    make_gen_table_str(conn, _("Running time"), nows);

    snprintf(buf, BUFSIZE, "%s%s%s", _("Log"), (opt.response & OPT_NOTIFY) ? _(", notify") : "", (opt.response & OPT_RESPOND) ? _(", respond") : "");
    make_gen_table_str(conn, _("Response mode"), buf);

    make_gen_table_int(conn, _("Lines seen"), linenum);
    make_gen_table_int(conn, _("Hits"), hitnum);
    make_gen_table_int(conn, _("Old/excluded/malformed"), ignored);

    this = first;
    while (this != NULL) {
      this = this->next;
      count++;
    }
    make_gen_table_int(conn, _("Entries in packet cache"), count);
    this_host = first_host;
    count = 0;
    while (this_host != NULL) {
      this_host = this_host->next;
      count++;
    }
    make_gen_table_int(conn, _("Entries in host status"), count);

    fdprintf(conn, "</table>\n");
  }

  if (opt.webpage == 'o') {
    make_header_h2(conn, _("Options"));
    fdprintf(conn, "<table cellspacing=\"1\" cellpadding=\"3\">\n<tr><th>");
    fdprintf(conn, _("Parameter"));
    fdprintf(conn, "</th><th>");
    fdprintf(conn, _("Decrease"));
    fdprintf(conn, "</th><th>");
    fdprintf(conn, _("Current"));
    fdprintf(conn, "</th><th>");
    fdprintf(conn, _("Increase"));
    fdprintf(conn, "</th></tr>\n");
    make_opt_table_int(conn, _("Alert threshold"), "alert", opt.threshold);
    output_timediff(0, opt.recent, nows);
    make_opt_table_str(conn, _("Discard timeout"), "recent", nows);
    make_opt_table_int(conn, _("Minimum count in packet cache"), "least", opt.least);
    if (opt.max > 0) {
      make_opt_table_int(conn, _("Top amount of entries in packet cache"), "max", opt.max);
    } else {
      make_opt_table_str(conn, _("Top amount of entries in packet cache"), "max", "-");
    }
    if (opt.refresh > 0) {
      make_opt_table_int(conn, _("Refresh time"), "refresh", opt.refresh);
    } else {
      make_opt_table_str(conn, _("Refresh time"), "refresh", "-");
    }
    fdprintf(conn, "</table>\n");
  }

  if (opt.webpage == 'p') {
    make_header_h2(conn, _("Packet cache"));

    table_header(conn, SORTING, NET_OPTS_PC);

    sort_data(SORT_PC);

#ifdef HAVE_ADNS
    if (opt.resolve)
      adns_preresolve(RES_ADNS_PC);
#endif

    this = first;
    while ((this != NULL) && ((opt.max == 0) || (max < opt.max)) && (opt.status != FD_ERROR)) {
      if (this->count >= opt.least) {
	if (opt.max != 0)
	  max++;
	strftime(nows, TIMESIZE, _("%Y/%m/%d %H:%M:%S"), localtime(&this->start_time));
	fdprintf(conn, "<tr class=\"r%d\"><td>%d</td><td>%s</td>", color, this->count, nows);
	if (opt.proto) {
	  fdprintf(conn, "<td>%s</td>", resolve_protocol(this->protocol));
	}
	if (opt.datalen) {
	  fdprintf(conn, "<td>%lu</td>", this->datalen);
	}
	fdprintf(conn, "<td>%s</td>", my_inet_ntop(&this->shost));
	if (opt.resolve) {
	  fdprintf(conn, "<td>%s</td>", resolve_address(this->shost));
	}
#ifdef HAVE_GEOIP
	if (opt.geoip) {
	  fdprintf(conn, "<td>%s</td>", geoip_lookup(&this->shost));
	}
#endif
	if (opt.src_port) {
	  fdprintf(conn, "<td>%d</td>", this->sport);
	  if (opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this->sport, resolve_protocol(this->protocol)));
	  }
	}
	if (opt.dst_ip) {
	  fdprintf(conn, "<td>%s</td>", my_inet_ntop(&this->dhost));
	  if (opt.resolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_address(this->dhost));
	  }
#ifdef HAVE_GEOIP
	  if (opt.geoip) {
	    fdprintf(conn, "<td>%s</td>", geoip_lookup(&this->dhost));
	  }
#endif
	}
	if (opt.dst_port) {
	  fdprintf(conn, "<td>%d</td>", this->dport);
	  if (opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this->dport, resolve_protocol(this->protocol)));
	  }
	}
	if (opt.opts) {
	  output_tcp_opts(this, buf);
	  fdprintf(conn, "<td>%s</td>", buf);
	}
	output_timediff(0, opt.recent - (now - this->end_time), nows);
	fdprintf(conn, "<td>%s</td>", nows);
	fdprintf(conn, "<td><a href=\"?pcdrop=%0.10d\">", this->id);
	fdprintf(conn, _("drop"));
	fdprintf(conn, "</a> / <a href=\"?escalate=%0.10d\">", this->id);
	fdprintf(conn, _("escalate"));
	fdprintf(conn, "</a></td></tr>\n");
	if (color == 1) {
	  color = 2;
	} else {
	  color = 1;
	}
      }
      this = this->next;
    }
    fdprintf(conn, "</table>\n");
  }

  if (opt.webpage == 'h') {
    make_header_h2(conn, _("Host status"));

    color = 1;
    table_header(conn, SORTING, NO_NET_OPTS_PC);

    sort_data(SORT_HS);

#ifdef HAVE_ADNS
    if (opt.resolve)
      adns_preresolve(RES_ADNS_HS);
#endif

    this_host = first_host;
    while (this_host != NULL && (opt.status != FD_ERROR)) {
      fdprintf(conn, "<tr class=\"r%d\"><td>%d</td>", color, this_host->count);

      if (this_host->time == 0) {
	int mask;

	fdprintf(conn, "<td>-</td>");
	if (opt.proto) {
	  fdprintf(conn, _("<td>any</td>"));
	}
	mask = convert_mask(&this_host->netmask);
	if ((mask == 128) || ((isV4mappedV6addr(&this_host->shost)) && (mask == 32))) {
	  fdprintf(conn, "<td>%s</td>", my_inet_ntop(&this_host->shost));
	} else {
	  fdprintf(conn, "<td>%s/%d</td>", my_inet_ntop(&this_host->shost), mask);
	}
	if (opt.resolve) {
	  if ((mask == 128) || ((isV4mappedV6addr(&this_host->shost)) && (mask == 32))) {
	    fdprintf(conn, _("<td>(known host)</td>"));
	  } else {
	    fdprintf(conn, _("<td>(known net)</td>"));
	  }
	}
#ifdef HAVE_GEOIP
	if (opt.geoip) {
	  fdprintf(conn, "<td>-</td>");
	}
#endif
	if (opt.src_port) {
	  fdprintf(conn, _("<td>any</td>"));
	  if (opt.sresolve) {
	    fdprintf(conn, "<td>-</td>");
	  }
	}
	if (opt.dst_ip) {
	  fdprintf(conn, _("<td>any</td>"));
	  if (opt.resolve) {
	    fdprintf(conn, "<td>-</td>");
	  }
#ifdef HAVE_GEOIP
	  if (opt.geoip) {
	    fdprintf(conn, "<td>-</td>");
	  }
#endif
	}
	if (opt.dst_port) {
	  fdprintf(conn, _("<td>any</td>"));
	  if (opt.sresolve) {
	    fdprintf(conn, "<td>-</td>");
	  }
	}
	fdprintf(conn, "<td>-</td></tr>\n");
      } else {
	strftime(nows, TIMESIZE, _("%Y/%m/%d %H:%M:%S"), localtime(&this_host->time));
	fdprintf(conn, "<td>%s</td>", nows);
	if (opt.proto) {
	  fdprintf(conn, "<td>%s</td>", resolve_protocol(this_host->protocol));
	}
	fdprintf(conn, "<td>%s</td>", my_inet_ntop(&this_host->shost));
	if (opt.resolve) {
	  fdprintf(conn, "<td>%s</td>", resolve_address(this_host->shost));
	}
#ifdef HAVE_GEOIP
	if (opt.geoip) {
	  fdprintf(conn, "<td>%s</td>", geoip_lookup(&this_host->shost));
	}
#endif
	if (opt.src_port) {
	  fdprintf(conn, "<td>%d</td>", this_host->sport);
	  if (opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this_host->sport, resolve_protocol(this_host->protocol)));
	  }
	}
	if (opt.dst_ip) {
	  fdprintf(conn, "<td>%s</td>", my_inet_ntop(&this_host->dhost));
	  if (opt.resolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_address(this_host->dhost));
	  }
#ifdef HAVE_GEOIP
	  if (opt.geoip) {
	    fdprintf(conn, "<td>%s</td>", geoip_lookup(&this_host->dhost));
	  }
#endif
	}
	if (opt.dst_port) {
	  fdprintf(conn, "<td>%d</td>", this_host->dport);
	  if (opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this_host->dport, resolve_protocol(this_host->protocol)));
	  }
	}
	output_timediff(0, opt.recent - (now - this_host->time), nows);
	fdprintf(conn, "<td>%s</td>", nows);
	fdprintf(conn, "<td><a href=\"?hsdrop=%0.10d\">", this_host->id);
	fdprintf(conn, _("drop"));
	fdprintf(conn, "</a></td></tr>\n", this_host->id);
      }

      if (color == 1) {
	color = 2;
      } else {
	color = 1;
      }

      this_host = this_host->next;
    }

    fdprintf(conn, "</table>\n");
  }

  show_navigation(conn);
  output_html_footer(conn);
}

void handshake(int linenum, int hitnum, int ignored)
{
#ifdef SOLARIS
  typedef int socklen_t;	/* undefined and not unsigned as in linux */
#endif
  int conn, retval, id = 0;
#ifndef IRIX
  socklen_t socks;
#else
  size_t socks;
#endif
  struct sockaddr_in6 sain6;
  char nab[INET6_ADDRSTRLEN];
  char buf[BUFSIZE], password[PASSWORDSIZE], salt[3], *pnt, command[9] = "", option1 = 'm', option2 = 'm';
  unsigned char auth = 0;

  socks = sizeof(struct sockaddr_in6);

  conn = accept(opt.sock, (struct sockaddr *) &sain6, &socks);
  if (conn == -1) {
    syslog(LOG_NOTICE, "accept: %s", strerror(errno));
    return;
  }
  opt.status = STATUS_OK;

  if ((opt.listento[0] != '\0')
      && (strncmp(opt.listento, inet_ntop(AF_INET6, &sain6.sin6_addr, nab, INET6_ADDRSTRLEN), IP6LEN) != 0)) {
    syslog(LOG_NOTICE, _("Rejected connection from unallowed IP address %s port %i"), my_inet_ntop(&sain6.sin6_addr), ntohs(sain6.sin6_port));
    retval = close(conn);
    if (retval == -1) {
      syslog(LOG_NOTICE, "close: %s", strerror(errno));
    }
    return;
  }

  if (opt.verbose)
    syslog(LOG_NOTICE, _("Connect from %s port %i"), inet_ntop(AF_INET6, &sain6.sin6_addr, nab, INET6_ADDRSTRLEN), ntohs(sain6.sin6_port));

  secure_read(conn, buf, BUFSIZE);
  while (!(strncmp(buf, "", BUFSIZE) == 0)) {
#ifdef WEB_DEBUG
    fprintf(stderr, "%3d %s\n", strlen(buf), buf);
#endif
    if ((strlen(buf) == 14) && (strncmp(buf, "GET / HTTP/1.", 13) == 0)) {
      strcpy(command, "show");
    } else if ((strlen(buf) == 21) && (strncmp(buf, "GET /?page=", 11) == 0) && (strchr("ioph", buf[11]) != NULL)) {
      strcpy(command, "page");
      option1 = buf[11];
    } else if ((strlen(buf) == 22) && (strncmp(buf, "GET /?sort=", 11) == 0) && (strchr("ctpbSsDdze", buf[11]) != NULL) && (strchr("ad", buf[12]) != NULL)) {
      strcpy(command, "sort");
      option1 = buf[11];
      option2 = buf[12];
    } else if ((strlen(buf) == 22) && (strncmp(buf, "GET /?least=", 12) == 0) && (strchr("ml", buf[12]) != NULL)) {
      strcpy(command, "least");
      option1 = buf[12];
    } else if ((strlen(buf) == 20) && (strncmp(buf, "GET /?max=", 10) == 0) && (strchr("ml", buf[10]) != NULL)) {
      strcpy(command, "max");
      option1 = buf[10];
    } else if ((strlen(buf) == 22) && (strncmp(buf, "GET /?alert=", 12) == 0) && (strchr("ml", buf[12]) != NULL)) {
      strcpy(command, "alert");
      option1 = buf[12];
    } else if ((strlen(buf) == 24) && (strncmp(buf, "GET /?refresh=", 14) == 0) && (strchr("ml", buf[14]) != NULL)) {
      strcpy(command, "refresh");
      option1 = buf[14];
    } else if ((strlen(buf) == 23) && (strncmp(buf, "GET /?recent=", 13) == 0) && (strchr("ml", buf[13]) != NULL)) {
      strcpy(command, "recent");
      option1 = buf[13];
    } else if ((strlen(buf) == 32) && (strncmp(buf, "GET /?pcdrop=", 13) == 0)) {
      id = atoi(buf + 13);
      if ((id >= 0) && (id < INT_MAX))
	strcpy(command, "pcdrop");
    } else if ((strlen(buf) == 34) && (strncmp(buf, "GET /?escalate=", 15) == 0)) {
      id = atoi(buf + 15);
      if ((id >= 0) && (id < INT_MAX))
	strcpy(command, "escalate");
    } else if ((strlen(buf) == 32) && (strncmp(buf, "GET /?hsdrop=", 13) == 0)) {
      id = atoi(buf + 13);
      if ((id >= 0) && (id < INT_MAX))
	strcpy(command, "hsdrop");
    } else if (strncmp(buf, "Authorization: Basic ", 21) == 0) {
      xstrncpy(password, buf + 21, PASSWORDSIZE);
      decode_base64(password);
      if (strncmp(opt.user, password, strlen(opt.user)) == 0) {
	salt[0] = opt.password[0];
	salt[1] = opt.password[1];
	salt[2] = '\0';
	pnt = crypt(password + strlen(opt.user) + 1, salt);
	if (strncmp(opt.password, pnt, strlen(opt.password)) == 0) {
	  auth = 1;
	}
      }
    }
    secure_read(conn, buf, BUFSIZE);
  }

  signal(SIGPIPE, SIG_IGN);

  if (auth == 0) {
    if (opt.verbose)
      syslog(LOG_NOTICE, _("Authorization failed"));
    http_header(conn, "401 Authorization Required", HEADER_CONTINUES);
    fdprintf(conn, "WWW-Authenticate: Basic realm=\"fwlogwatch\"\r\n\r\n");
    basic_html_body(conn, _("Authorization required"), _("Authorization required"));
  } else {
    if (strncmp(command, "show", 4) == 0) {
      show_status(conn, linenum, hitnum, ignored);
    } else if (strncmp(command, "page", 4) == 0) {
      opt.webpage = option1;
    } else if (strncmp(command, "sort", 4) == 0) {
      snprintf(opt.sort_order, MAXSORTSIZE, "%c%c", option1, option2);
    } else if (strncmp(command, "least", 5) == 0) {
      if ((option1 == 'l') && (opt.least > 1)) {
	opt.least--;
      } else if (option1 == 'm') {
	opt.least++;
      }
    } else if (strncmp(command, "max", 3) == 0) {
      opt.max -= opt.max % 10;
      if ((option1 == 'l') && (opt.max > 9)) {
	opt.max = opt.max - 10;
      } else if (option1 == 'm') {
	opt.max = opt.max + 10;
      }
    } else if (strncmp(command, "alert", 5) == 0) {
      if ((option1 == 'l') && (opt.threshold > 1)) {
	opt.threshold--;
      } else if (option1 == 'm') {
	opt.threshold++;
      }
      look_for_alert();
    } else if (strncmp(command, "refresh", 7) == 0) {
      opt.refresh -= opt.refresh % 15;
      if ((option1 == 'l') && (opt.refresh > 14)) {
	opt.refresh = opt.refresh - 15;
      } else if (option1 == 'm') {
	opt.refresh = opt.refresh + 15;
      }
    } else if (strncmp(command, "recent", 6) == 0) {
      opt.recent -= opt.recent % 300;
      if ((option1 == 'l') && (opt.recent > 600)) {
	opt.recent = opt.recent - 300;
      } else if (option1 == 'm') {
	opt.recent = opt.recent + 300;
      }
    } else if (strncmp(command, "pcdrop", 6) == 0) {
      struct conn_data *this;
      this = first;
      while (this != NULL) {
	if (this->id == id) {
	  this->end_time = 1;
	  remove_old(RESP_REMOVE_OPC);
	  break;
	}
	this = this->next;
      }
    } else if (strncmp(command, "escalate", 8) == 0) {
      struct conn_data *this;
      this = first;
      while (this != NULL) {
	if (this->id == id) {
	  this->count += opt.threshold - this->count;
	  look_for_alert();
	  break;
	}
	this = this->next;
      }
    } else if (strncmp(command, "hsdrop", 6) == 0) {
      struct known_hosts *this_host;
      this_host = first_host;
      while (this_host != NULL) {
	if (this_host->id == id) {
	  this_host->time = 1;
	  remove_old(RESP_REMOVE_OHS);
	  break;
	}
	this_host = this_host->next;
      }
    } else {
      http_header(conn, "400 Bad request", HEADER_COMPLETE);
      basic_html_body(conn, _("Bad request"), _("Bad request"));
    }
    if ((strncmp(command, "show", 4) != 0) && (command[0] != 0)) {
      http_header(conn, "302 Found", HEADER_CONTINUES);
      fdprintf(conn, "Location: /\r\n\r\n");
      basic_html_body(conn, _("Redirect"), _("You should be redirected to the <a href=\"/\">root directory</a>"));
    }
  }

  signal(SIGPIPE, SIG_DFL);

  retval = close(conn);
  if (retval == -1) {
    syslog(LOG_NOTICE, "close: %s", strerror(errno));
  }

  if (opt.verbose == 2)
    syslog(LOG_NOTICE, _("Requested function: %s"), command);

  if (opt.verbose)
    syslog(LOG_NOTICE, _("Connection closed"));
}
