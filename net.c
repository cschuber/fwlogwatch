/* $Id: net.c,v 1.24 2003/03/22 23:16:48 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef SOLARIS
#include <string.h>
#else
#include <strings.h>
#endif
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __OpenBSD__
#ifndef __FreeBSD__
#include <crypt.h>
#endif
#endif

#include "utils.h"
#include "main.h"
#include "output.h"
#include "response.h"
#include "resolve.h"
#include "compare.h"

extern struct options opt;
extern struct conn_data *first;
extern struct known_hosts *first_host;

void secure_read(int file, char *data_out, int maxlen)
{
  int j = 0;
  signed char c;

  read(file, &c, 1);
  while (!(c == EOF || c == '\n') && (j < (maxlen - 1))) {
    data_out[j++] = c;
    read(file, &c, 1);
  }
  data_out[--j] = 0;
}

void prepare_socket()
{
  int retval, x;
#ifndef HAVE_IPV6
  struct sockaddr_in sa;
  struct in_addr ina;
#else
  struct sockaddr_in6 sain6;
  struct in6_addr in6a;
  char nab[INET6_ADDRSTRLEN];
#endif

#ifndef HAVE_IPV6
  opt.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
  opt.sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
#endif
  if (opt.sock == -1) {
    syslog(LOG_NOTICE, "socket: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  retval = setsockopt(opt.sock, SOL_SOCKET, SO_REUSEADDR, (void *)&x, sizeof(x));
  if (retval == -1) {
    syslog(LOG_NOTICE, "setsockopt: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

#ifndef HAVE_IPV6
  ina.s_addr = inet_addr(opt.listenif);
  bzero(&sa, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(opt.listenport);
  sa.sin_addr = ina;
#else
  retval = inet_pton(AF_INET6, opt.listenif, in6a.s6_addr);
  if (retval != 1) {
    char nnb[HOSTLEN];
    snprintf(nnb, HOSTLEN, "::ffff:%s", opt.listenif);
    retval = inet_pton(AF_INET6, nnb, in6a.s6_addr);
    if (retval != 1) {
      syslog(LOG_NOTICE, "inet_pton: Wrong address %s", opt.listenif);
      log_exit(EXIT_FAILURE);
    }
  }

  bzero(&sain6, sizeof(sain6));
  sain6.sin6_family = AF_INET6;
  sain6.sin6_port = htons(opt.listenport);
  sain6.sin6_addr = in6a;
#endif

#ifndef HAVE_IPV6
  retval = bind(opt.sock, (struct sockaddr *)&sa, sizeof(sa));
#else
  retval = bind(opt.sock, (struct sockaddr *)&sain6, sizeof(sain6));
#endif
  if (retval == -1) {
    syslog(LOG_NOTICE, "bind: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  retval = listen(opt.sock, 1);
  if (retval == -1) {
    syslog(LOG_NOTICE, "listen: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

#ifndef HAVE_IPV6
  syslog(LOG_NOTICE, _("Listening on %s port %i"), inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
#else
  syslog(LOG_NOTICE, _("Listening on %s port %i"), inet_ntop(AF_INET6, &sain6.sin6_addr, nab, INET6_ADDRSTRLEN), ntohs(sain6.sin6_port));
#endif
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

  for (i = 0; i < 255; i++) { dtable[i] = 0x80; }
  for (i = 'A'; i <= 'Z'; i++) { dtable[i] = 0 + (i - 'A'); }
  for (i = 'a'; i <= 'z'; i++) { dtable[i] = 26 + (i - 'a'); }
  for (i = '0'; i <= '9'; i++) { dtable[i] = 52 + (i - '0'); }
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
    for(k=0;k<i;k++) {
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

void fdprintf(int fd, char *format, ...)
{
  char buf[BUFSIZE];
  va_list argv;

  va_start(argv, format);
  vsnprintf(buf, BUFSIZE, format, argv);
  write(fd, buf, strlen(buf));
  va_end(argv);
  fflush(stdout);
}

void table_header(int conn, unsigned char mode)
{
  fdprintf(conn, "<table border=\"0\" cellspacing=\"1\" cellpadding=\"3\">\n");
  fdprintf(conn, _("<tr bgcolor=\"%s\" align=\"center\"><th>count</th><th>added</th>"), opt.rowcol1);
  if(opt.proto)
    fdprintf(conn, _("<th>proto</th>"));
  fdprintf(conn, _("<th>source</th>"));
  if(opt.resolve)
    fdprintf(conn, _("<th>hostname</th>"));
  if(opt.src_port) {
    fdprintf(conn, _("<th>port</th>"));
    if(opt.sresolve)
      fdprintf(conn, _("<th>service</th>"));
  }
  if(opt.dst_ip) {
    fdprintf(conn, _("<th>destination</th>"));
    if(opt.resolve)
      fdprintf(conn, _("<th>hostname</th>"));
  }
  if(opt.dst_port) {
    fdprintf(conn, _("<th>port</th>"));
    if(opt.sresolve)
      fdprintf(conn, _("<th>service</th>"));
  }
  if(mode == TCP_OPTS) {
    if (opt.opts)
      fdprintf(conn, _("<th>opts</th>"));
  }
  fdprintf(conn, _("<th>time remaining</th></tr>\n"));
}

void handshake()
{
#ifdef SOLARIS
  typedef int socklen_t; /* undefined and not unsigned as in linux */
#endif
  int conn, retval;
#ifndef IRIX
  socklen_t socks;
#else
  size_t socks;
#endif
#ifndef HAVE_IPV6
  struct sockaddr_in sac;
#else
  struct sockaddr_in6 sain6;
  char nab[INET6_ADDRSTRLEN];
#endif
  char buf[BUFSIZE], nows[TIMESIZE], password[PASSWORDSIZE], salt[2], *pnt;
  time_t now;
  struct conn_data *this;
  struct known_hosts *this_host;
  unsigned char auth = 0, color = 1;
  int max = 0;

#ifndef HAVE_IPV6
  socks = sizeof(struct sockaddr_in);
#else
  socks = sizeof(struct sockaddr_in6);
#endif

#ifndef HAVE_IPV6
  conn = accept(opt.sock, (struct sockaddr *)&sac, &socks);
#else
  conn = accept(opt.sock, (struct sockaddr *)&sain6, &socks);
#endif
  if (conn == -1) {
    syslog(LOG_NOTICE, "accept: %s", strerror(errno));
    return;
  }

#ifndef HAVE_IPV6
  if((opt.listento[0] != '\0') && (strncmp(opt.listento,inet_ntoa(sac.sin_addr),IPLEN) != 0)) {
    syslog(LOG_NOTICE, _("Rejected connect from unallowed ip %s port %i"), inet_ntoa(sac.sin_addr), ntohs(sac.sin_port));
#else
  if((opt.listento[0] != '\0') && (strncmp(opt.listento,inet_ntop(AF_INET6, &sain6.sin6_addr, nab, INET6_ADDRSTRLEN),IPLEN) != 0)) {
    syslog(LOG_NOTICE, _("Rejected connect from unallowed ip %s port %i"), inet_ntop(AF_INET6, &sain6.sin6_addr, nab, INET6_ADDRSTRLEN), ntohs(sain6.sin6_port));
#endif
    retval = close(conn);
    if (retval == -1) {
      syslog(LOG_NOTICE, "close: %s", strerror(errno));
    }
    return;
  }

  if(opt.verbose)
#ifndef HAVE_IPV6
    syslog(LOG_NOTICE, _("Connect from %s port %i"), inet_ntoa(sac.sin_addr), ntohs(sac.sin_port));
#else
    syslog(LOG_NOTICE, _("Connect from %s port %i"), inet_ntop(AF_INET6, &sain6.sin6_addr, nab, INET6_ADDRSTRLEN), ntohs(sain6.sin6_port));
#endif

  secure_read(conn, buf, BUFSIZE);
  while(!(strncmp(buf, "", BUFSIZE) == 0)) {
    if(strncmp(buf, "Authorization: Basic ", 21) == 0) {
      xstrncpy(password, buf+21, PASSWORDSIZE);
      decode_base64(password);
      if (strncmp(opt.user, password, strlen(opt.user)) == 0) {
	salt[0] = opt.password[0];
	salt[1] = opt.password[1];
	salt[2] = '\0';
	pnt = crypt(password+strlen(opt.user)+1, salt);
	if (strncmp(opt.password, pnt, strlen(opt.password)) == 0) {
	  auth = 1;
	}
      }
    }
    secure_read(conn, buf, BUFSIZE);
  }

  if (auth == 0) {
    if(opt.verbose == 2) {
      syslog(LOG_NOTICE, _("Authorization failed (%s)"), password);
    } else if(opt.verbose) {
      syslog(LOG_NOTICE, _("Authorization failed"));
    }
    fdprintf(conn, "HTTP/1.0 401 Authorization Required\r\n");
    fdprintf(conn, "Server: %s %s (C) %s\r\n", PACKAGE, VERSION, COPYRIGHT);
    fdprintf(conn, "WWW-Authenticate: Basic realm=\"fwlogwatch\"\r\n");
    fdprintf(conn, "Connection: close\r\n");
    fdprintf(conn, "Content-Type: text/html\r\n\r\n");
    fdprintf(conn, "<html>\n<head>\n<title>Authorization Required</title>\n</head>\n");
    fdprintf(conn, _("<body>\n<h1>Authorization Required</h1>\n</body>\n</html>\n"));
  } else {
    fdprintf(conn, "HTTP/1.0 200 OK\r\n");
    fdprintf(conn, "Server: %s %s (C) %s\r\n", PACKAGE, VERSION, COPYRIGHT);
    fdprintf(conn, "Connection: close\r\n");
    fdprintf(conn, "Content-Type: text/html\r\n\r\n");

    fdprintf(conn, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n");
    fdprintf(conn, "<html>\n<head>\n<title>%s</title>\n", opt.title);
    fdprintf(conn, "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n");
    fdprintf(conn, "<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
    fdprintf(conn, "<meta http-equiv=\"expires\" content=\"0\">\n");
    if(opt.refresh > 0) {
      fdprintf(conn, "<meta http-equiv=\"refresh\" content=\"%d\">\n", opt.refresh);
    }
    if (opt.stylesheet[0] != '\0') {
      fdprintf(conn, "<link rel=\"stylesheet\" href=\"%s\">\n", opt.stylesheet);
    } else {
      fdprintf(conn, "<style type=\"text/css\">\n<!--\n");
      fdprintf(conn, "BODY {font-family: arial, helvetica, sans-serif; color: %s; background: %s}\n", opt.textcol, opt.bgcol);
      fdprintf(conn, "A:link, A:active, A:visited {color: %s; background: %s}\n", opt.textcol, opt.bgcol);
      fdprintf(conn, "TH, TD {font-family: arial, helvetica, sans-serif; color: %s}\n", opt.textcol);
      fdprintf(conn, "SMALL {font-family: arial, helvetica, sans-serif; color: %s; background: %s}\n", opt.textcol, opt.bgcol);
      fdprintf(conn, "-->\n</style>\n");
    }
    fdprintf(conn, "</head>\n<body>\n");
    fdprintf(conn, "<div align=\"center\">\n<h1>%s</h1>\n", opt.title);
    fdprintf(conn, _("<a href=\"/\">Reload</a><br>\n"));
    if(opt.refresh > 0) {
      fdprintf(conn, _("(automatic refresh every %d seconds)<br>\n"), opt.refresh);
    }
    fdprintf(conn, _("</div>\n<h2>General information</h2>\n"));

    fdprintf(conn, "<table border=\"0\" cellspacing=\"1\" cellpadding=\"3\">\n");
    strftime(nows, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&opt.now));
    fdprintf(conn, _("<tr><td>Daemon start time:</td><td>%s</td></tr>\n"), nows);

    now = time(NULL);
    strftime(nows, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&now));
    fdprintf(conn, _("<tr><td>Current time:</td><td>%s</td></tr>\n"), nows);

    output_timediff(opt.now, now, nows);
    fdprintf(conn, _("<tr><td>Running time:</td><td>%s</td></tr>\n"), nows);

    output_timediff(0, opt.recent, nows);
    fdprintf(conn, _("<tr><td>Alert threshold:</td><td>%d entries</td></tr>\n<tr><td>Discard timeout:</td><td>%s</td></tr>\n"), opt.threshold, nows);

    fdprintf(conn, _("<tr><td>Response mode:</td><td>log%s%s</td></tr>\n"),
	     (opt.response & OPT_NOTIFY)?_(", notify"):"",
	     (opt.response & OPT_RESPOND)?_(", respond"):"");

    if(opt.least > 1) {
      fdprintf(conn, _("<tr><td colspan=\"2\">Only entries with a count of at least %d are shown in the packet cache.<td></tr>\n"), opt.least);
    }
    if(opt.max != 0) {
      fdprintf(conn, _("<tr><td colspan=\"2\">Only the top %d entries are shown in the packet cache.<td></tr>\n"), opt.max);
    }

    fdprintf(conn, "</table>\n");

    fdprintf(conn, _("<h2>Packet cache</h2>\n"));

    table_header(conn, TCP_OPTS);

    sort_data();

    this = first;
    while((this != NULL) && ((opt.max == 0) || (max < opt.max))) {
      time_t remaining;

      if (opt.max != 0)
	max++;
      if(this->count >= opt.least) {
	strftime(nows, TIMESIZE, "%Y-%m-%d %H:%M:%S", localtime(&this->start_time));
	fdprintf(conn, "<tr bgcolor=\"%s\" align=\"center\"><td>%d</td><td>%s</td>", (color == 1)?opt.rowcol2:opt.rowcol1, this->count, nows);
	if(opt.proto) {
	  fdprintf(conn, "<td>%s</td>", resolve_protocol(this->protocol));
	}
	fdprintf(conn, "<td>%s</td>", inet_ntoa(this->shost));
	if(opt.resolve) {
	  fdprintf(conn, "<td>%s</td>", resolve_hostname(this->shost));
	}
	if(opt.src_port) {
	  fdprintf(conn, "<td>%d</td>", this->sport);
	  if(opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this->sport, resolve_protocol(this->protocol)));
	  }
	}
	if(opt.dst_ip) {
	  fdprintf(conn, "<td>%s</td>", inet_ntoa(this->dhost));
	  if(opt.resolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_hostname(this->dhost));
	  }
	}
	if(opt.dst_port) {
	  fdprintf(conn, "<td>%d</td>", this->dport);
	  if(opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this->dport, resolve_protocol(this->protocol)));
	  }
	}
	if(opt.opts) {
	  output_tcp_opts(this, buf);
	  fdprintf(conn, "<td>%s</td>", buf);
	}
	if (this->end_time != 0) {
	  remaining = opt.recent - (now - this->end_time);
	} else {
	  remaining = opt.recent - (now - this->start_time);
	}
	output_timediff(0, remaining, nows);
	fdprintf(conn, "<td>%s</td></tr>\n", nows);
	if (color == 1) {
	  color = 2;
	} else {
	  color = 1;
	}
      }
      this = this->next;
    }
    fdprintf(conn, "</table>\n<br>\n");

    color = 1;
    fdprintf(conn, _("<h2>Host status</h2>\n"));

    table_header(conn, NO_TCP_OPTS);

    this_host = first_host;
    while(this_host != NULL) {
      fdprintf(conn, "<tr bgcolor=\"%s\" align=\"center\"><td>%d</td>", (color == 1)?opt.rowcol2:opt.rowcol1, this_host->count);

      if (this_host->time == 0) {
	int mask;
	unsigned long int netmask[33] = {
	  0x0,
	  0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
	  0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
	  0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
	  0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
	  0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
	  0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
	  0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
	  0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF
	};

	fdprintf(conn, "<td>-</td>");
	if(opt.proto) { fdprintf(conn, _("<td>any</td>")); }
	for(mask=0;mask<32;mask++) {
	  if (ntohl(netmask[mask]) == this_host->netmask.s_addr)
	    break;
	}
	fdprintf(conn, _("<td>%s/%d (known host/net)</td>"), inet_ntoa(this_host->shost), mask);
	if(opt.resolve) { fdprintf(conn, "<td>-</td>"); }
	if(opt.src_port) { fdprintf(conn, _("<td>any</td>"));
	if(opt.sresolve) { fdprintf(conn, "<td>-</td>"); } }
	if(opt.dst_ip) { fdprintf(conn, _("<td>any</td>"));
	if(opt.resolve) { fdprintf(conn, "<td>-</td>"); } }
	if(opt.dst_port) { fdprintf(conn, _("<td>any</td>"));
	if(opt.sresolve) { fdprintf(conn, "<td>-</td>"); } }
	fdprintf(conn, "<td>-</td></tr>\n");
      } else {
	strftime(nows, TIMESIZE, "%Y-%m-%d %H:%M:%S", localtime(&this_host->time));
	fdprintf(conn, "<td>%s</td>", nows);
	if(opt.proto) {
	  fdprintf(conn, "<td>%s</td>", resolve_protocol(this_host->protocol));
	}
	fdprintf(conn, "<td>%s</td>", inet_ntoa(this_host->shost));
	if(opt.resolve) {
	  fdprintf(conn, "<td>%s</td>", resolve_hostname(this_host->shost));
	}
	if(opt.src_port) {
	  fdprintf(conn, "<td>%d</td>", this_host->sport);
	  if(opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this_host->sport, resolve_protocol(this_host->protocol)));
	  }
	}
	if(opt.dst_ip) {
	  fdprintf(conn, "<td>%s</td>", inet_ntoa(this_host->dhost));
	  if(opt.resolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_hostname(this_host->dhost));
	  }
	}
	if(opt.dst_port) {
	  fdprintf(conn, "<td>%d</td>", this_host->dport);
	  if(opt.sresolve) {
	    fdprintf(conn, "<td>%s</td>", resolve_service(this_host->dport, resolve_protocol(this_host->protocol)));
	  }
	}
	output_timediff(0, opt.recent - (now - this_host->time), nows);
	fdprintf(conn, "<td>%s</td></tr>\n", nows);
      }

      if (color == 1) {
	color = 2;
      } else {
	color = 1;
      }

      this_host = this_host->next;
    }
    fdprintf(conn, "</table>\n<br><br>\n");

    fdprintf(conn, "<small><a href=\"http://cert.uni-stuttgart.de/projects/fwlogwatch/\">%s</a> %s &copy; %s</small>\n", PACKAGE, VERSION, COPYRIGHT);
    fdprintf(conn, "</body>\n</html>\n");
  }

  retval = close(conn);
  if (retval == -1) {
    syslog(LOG_NOTICE, "close: %s", strerror(errno));
  }

  if(opt.verbose)
    syslog(LOG_NOTICE, _("Connection closed"));

  return;
}
