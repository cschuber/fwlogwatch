/* $Id: net.c,v 1.19 2002/02/24 14:27:30 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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

extern struct options opt;
extern struct conn_data *first;
extern struct known_hosts *first_host;

void secure_read(int file, char *data_out, int maxlen)
{
  int j = 0;
  char c;

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
  struct sockaddr_in sa;
  struct in_addr ina;

  opt.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (opt.sock == -1) {
    syslog(LOG_NOTICE, "socket: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  retval = setsockopt(opt.sock, SOL_SOCKET, SO_REUSEADDR, (void *)&x, sizeof(x));
  if (retval == -1) {
    syslog(LOG_NOTICE, "setsockopt: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  ina.s_addr = inet_addr(opt.listenif);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(opt.listenport);
  sa.sin_addr = ina;

  retval = bind(opt.sock, (struct sockaddr *)&sa, sizeof(sa));
  if (retval == -1) {
    syslog(LOG_NOTICE, "bind: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  retval = listen(opt.sock, 1);
  if (retval == -1) {
    syslog(LOG_NOTICE, "listen: %s", strerror(errno));
    log_exit(EXIT_FAILURE);
  }

  syslog(LOG_NOTICE, _("Listening on %s port %i"), inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
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
	strncpy(input, buf, strlen(input));
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
      strncpy(input, buf, strlen(input));
      return;
    }
  }
}

void net_output(int fd, char *buf)
{
  write(fd, buf, strlen(buf));
}

void table_header(int conn)
{
  char buf[BUFSIZE];

  net_output(conn, "<table border=\"0\" cellspacing=\"1\" cellpadding=\"3\">\n");
  snprintf(buf, BUFSIZE, _("<tr bgcolor=\"#%s\" align=\"center\"><td>Count</td><td>Added</td><td>Source IP address</td>"), opt.rowcol1);
  net_output(conn, buf);
  if(opt.resolve) {
    snprintf(buf, BUFSIZE, _("<td>Hostname</td>"));
    net_output(conn, buf);
  }
  if(opt.dst_ip) {
    snprintf(buf, BUFSIZE, _("<td>Destination IP address</td>"));
    net_output(conn, buf);
    if(opt.resolve) {
      snprintf(buf, BUFSIZE, _("<td>Hostname</td>"));
      net_output(conn, buf);
    }
  }
  if(opt.proto) {
    snprintf(buf, BUFSIZE, _("<td>Protocol</td>"));
    net_output(conn, buf);
  }
  if(opt.src_port) {
    snprintf(buf, BUFSIZE, _("<td>Source port</td>"));
    net_output(conn, buf);
    if(opt.sresolve) {
      snprintf(buf, BUFSIZE, _("<td>Service</td>"));
      net_output(conn, buf);
    }
  }
  if(opt.dst_port) {
    snprintf(buf, BUFSIZE, _("<td>Destination port</td>"));
    net_output(conn, buf);
    if(opt.sresolve) {
      snprintf(buf, BUFSIZE, _("<td>Service</td>"));
      net_output(conn, buf);
    }
  }
  snprintf(buf, BUFSIZE, _("<td>Remaining time</td></tr>\n"));
  net_output(conn, buf);
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
  struct sockaddr_in sac;
  char buf[BUFSIZE], nows[TIMESIZE], password[PASSWORDSIZE], salt[2], *pnt;
  time_t now;
  struct conn_data *this;
  struct known_hosts *this_host;
  unsigned char auth = 0, color = 1;

  socks = sizeof(struct sockaddr_in);

  conn = accept(opt.sock, (struct sockaddr *)&sac, &socks);
  if (conn == -1) {
    syslog(LOG_NOTICE, "accept: %s", strerror(errno));
    return;
  }

  if((opt.listento[0] != '\0') && (strncmp(opt.listento,inet_ntoa(sac.sin_addr),IPLEN) != 0)) {
    syslog(LOG_NOTICE, _("Rejected connect from unallowed ip %s port %i"), inet_ntoa(sac.sin_addr), ntohs(sac.sin_port));
    retval = close(conn);
    if (retval == -1) {
      syslog(LOG_NOTICE, "close: %s", strerror(errno));
    }
    return;
  }

  if(opt.verbose)
    syslog(LOG_NOTICE, _("Connect from %s port %i"), inet_ntoa(sac.sin_addr), ntohs(sac.sin_port));

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
    net_output(conn, "HTTP/1.0 401 Authorization Required\r\n");
    snprintf(buf, BUFSIZE, "Server: %s %s (C) %s\r\n", PACKAGE, VERSION, COPYRIGHT);
    net_output(conn, buf);
    net_output(conn, "WWW-Authenticate: Basic realm=\"fwlogwatch\"\r\n");
    net_output(conn, "Connection: close\r\n");
    net_output(conn, "Content-Type: text/html\r\n\r\n");
    net_output(conn, "<html>\n<head>\n<title>Authorization Required</title>\n</head>\n");
    net_output(conn, _("<body>\n<h1>Authorization Required</h1>\n</body>\n</html>\n"));
  } else {
    net_output(conn, "HTTP/1.0 200 OK\r\n");
    snprintf(buf, BUFSIZE, "Server: %s %s (C) %s\r\n", PACKAGE, VERSION, COPYRIGHT);
    net_output(conn, buf);
    net_output(conn, "Connection: close\r\n");
    net_output(conn, "Content-Type: text/html\r\n\r\n");

    snprintf(buf, BUFSIZE, "<html>\n<head>\n<title>%s</title>\n", opt.title);
    net_output(conn, buf);
    net_output(conn, "<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
    net_output(conn, "<meta http-equiv=\"expires\" content=\"0\">\n");
    if(opt.refresh > 0) {
      snprintf(buf, BUFSIZE, "<meta http-equiv=\"refresh\" content=\"%d\">\n", opt.refresh);
      net_output(conn, buf);
    }
    net_output(conn, "</head>\n");
    snprintf(buf, BUFSIZE, "<body text=\"#%s\" bgcolor=\"#%s\" link=\"#%s\" alink=\"#%s\" vlink=\"#%s\">\n", opt.textcol, opt.bgcol, opt.textcol, opt.textcol, opt.textcol);
    net_output(conn, buf);
    net_output(conn, "<font face=\"Arial, Helvetica\">\n");
    snprintf(buf, BUFSIZE, "<div align=\"center\">\n<h1>%s</h1>\n", opt.title);
    net_output(conn, buf);
    net_output(conn, _("<a href=\"/\">Reload</a><br>\n"));
    if(opt.refresh > 0) {
      snprintf(buf, BUFSIZE, _("(automatic refresh every %d seconds)<br>\n"), opt.refresh);
      net_output(conn, buf);
    }
    net_output(conn, _("\n</div>\n<h2>General information</h2>\n"));

    net_output(conn, "<table border=\"0\" cellspacing=\"1\" cellpadding=\"3\">\n");
    strftime(nows, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&opt.now));
    snprintf(buf, BUFSIZE, _("<tr><td>Daemon start time:</td><td>%s</td></tr>\n"), nows);
    net_output(conn, buf);

    now = time(NULL);
    strftime(nows, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&now));
    snprintf(buf, BUFSIZE, _("<tr><td>Current time:</td><td>%s</td></tr>\n"), nows);
    net_output(conn, buf);

    output_timediff(opt.now, now, nows);
    snprintf(buf, BUFSIZE, _("<tr><td>Running time:</td><td>%s</td></tr>\n"), nows);
    net_output(conn, buf);

    snprintf(buf, BUFSIZE, _("<tr><td>Alert threshold:</td><td>%d entries</td></tr>\n<tr><td>Discard timeout:</td><td>%d seconds</td></tr>\n"), opt.threshold, opt.recent);
    net_output(conn, buf);

    snprintf(buf, BUFSIZE, _("<tr><td>Response mode:</td><td>log%s%s</td></tr>\n"),
	     (opt.response & OPT_NOTIFY)?_(", notify"):"",
	     (opt.response & OPT_RESPOND)?_(", respond"):"");
    net_output(conn, buf);

    net_output(conn, "</table>\n");

    net_output(conn, _("<h2>Packet cache</h2>\n"));

    table_header(conn);

    this = first;
    while(this != NULL) {
      time_t remaining;

      strftime(nows, TIMESIZE, "%Y-%m-%d %H:%M:%S", localtime(&this->start_time));
      snprintf(buf, BUFSIZE, "<tr bgcolor=\"#%s\" align=\"center\"><td>%d</td><td>%s</td><td>%s</td>", (color == 1)?opt.rowcol2:opt.rowcol1, this->count, nows, inet_ntoa(this->shost));
      net_output(conn, buf);

      if(opt.resolve) {
	snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_hostname(this->shost));
	net_output(conn, buf);
      }

      if(opt.dst_ip) {
	snprintf(buf, BUFSIZE, "<td>%s</td>", inet_ntoa(this->dhost));
	net_output(conn, buf);
	if(opt.resolve) {
	  snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_hostname(this->dhost));
	  net_output(conn, buf);
	}
      }

      if(opt.proto) {
	snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_protocol(this->protocol));
	net_output(conn, buf);
      }

      if(opt.src_port) {
	snprintf(buf, BUFSIZE, "<td>%d</td>", this->sport);
	net_output(conn, buf);
	if(opt.sresolve) {
	  snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_service(this->sport, resolve_protocol(this->protocol)));
	  net_output(conn, buf);
	}
      }

      if(opt.dst_port) {
	snprintf(buf, BUFSIZE, "<td>%d</td>", this->dport);
	net_output(conn, buf);
	if(opt.sresolve) {
	  snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_service(this->dport, resolve_protocol(this->protocol)));
	  net_output(conn, buf);
	}
      }

      if (this->end_time != 0) {
	remaining = opt.recent - (now - this->end_time);
      } else {
	remaining = opt.recent - (now - this->start_time);
      }
      snprintf(buf, BUFSIZE, "<td>%d</td></tr>\n", (int)remaining);
      net_output(conn, buf);

      if (color == 1) {
	color = 2;
      } else {
	color = 1;
      }

      this = this->next;
    }
    net_output(conn, "</table>\n<br>\n");

    color = 1;
    net_output(conn, _("<h2>Host status</h2>\n"));

    table_header(conn);

    this_host = first_host;
    while(this_host != NULL) {
      snprintf(buf, BUFSIZE, "<tr bgcolor=\"#%s\" align=\"center\"><td>%d</td>", (color == 1)?opt.rowcol2:opt.rowcol1, this_host->count);
      net_output(conn, buf);

      if (this_host->time == 0) {
	int mask = 0;
	uint32_t res;
	res = this_host->netmask.s_addr;
	while(res >= 1) {
	  mask++;
	  res /= 2;
	}
	snprintf(buf, BUFSIZE, _("<td>-</td><td>%s/%d (known host/net)</td>"), inet_ntoa(this_host->shost), mask);
	net_output(conn, buf);
	if(opt.resolve) { net_output(conn, "<td>-</td>"); }
	if(opt.dst_ip) { net_output(conn, _("<td>any</td>")); }
	if(opt.resolve) { net_output(conn, "<td>-</td>"); }
	if(opt.proto) { net_output(conn, _("<td>any</td>")); }
	if(opt.src_port) { net_output(conn, _("<td>any</td>")); }
	if(opt.sresolve) { net_output(conn, "<td>-</td>"); }
	if(opt.dst_port) { net_output(conn, _("<td>any</td>")); }
	if(opt.sresolve) { net_output(conn, "<td>-</td>"); }
	net_output(conn, "<td>-</td></tr>\n");
      } else {
	strftime(nows, TIMESIZE, "%Y-%m-%d %H:%M:%S", localtime(&this_host->time));
	snprintf(buf, BUFSIZE, "<td>%s</td><td>%s</td>", nows, inet_ntoa(this_host->shost));
	net_output(conn, buf);

	if(opt.resolve) {
	  snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_hostname(this_host->shost));
	  net_output(conn, buf);
	}

	if(opt.dst_ip) {
	  snprintf(buf, BUFSIZE, "<td>%s</td>", inet_ntoa(this_host->dhost));
	  net_output(conn, buf);
	  if(opt.resolve) {
	    snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_hostname(this_host->dhost));
	    net_output(conn, buf);
	  }
	}

	if(opt.proto) {
	  snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_protocol(this_host->protocol));
	  net_output(conn, buf);
	}

	if(opt.src_port) {
	  snprintf(buf, BUFSIZE, "<td>%d</td>", this_host->sport);
	  net_output(conn, buf);
	  if(opt.sresolve) {
	    snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_service(this->sport, resolve_protocol(this->protocol)));
	    net_output(conn, buf);
	  }
	}

	if(opt.dst_port) {
	  snprintf(buf, BUFSIZE, "<td>%d</td>", this_host->dport);
	  net_output(conn, buf);
	  if(opt.sresolve) {
	    snprintf(buf, BUFSIZE, "<td>%s</td>", resolve_service(this->dport, resolve_protocol(this->protocol)));
	    net_output(conn, buf);
	  }
	}

	snprintf(buf, BUFSIZE, "<td>%d</td></tr>\n", (int)(opt.recent - (now - this_host->time)));
	net_output(conn, buf);
      }

      if (color == 1) {
	color = 2;
      } else {
	color = 1;
      }

      this_host = this_host->next;
    }
    net_output(conn, "</table>\n<br><br>\n");

    snprintf(buf, BUFSIZE, "<small><a href=\"http://cert.uni-stuttgart.de/projects/fwlogwatch/\">%s</a> %s &copy; %s</small>\n", PACKAGE, VERSION, COPYRIGHT);
    net_output(conn, buf);
    net_output(conn, "</font>\n</body>\n</html>\n");
  }

  retval = close(conn);
  if (retval == -1) {
    syslog(LOG_NOTICE, "close: %s", strerror(errno));
  }

  if(opt.verbose)
    syslog(LOG_NOTICE, _("Connection closed"));

  return;
}
