/* $Id: net.c,v 1.8 2002/02/14 21:00:01 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <crypt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "utils.h"
#include "main.h"
#include "output.h"
#include "response.h"

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

int prepare_socket()
{
  int fd, retval, x;
  struct sockaddr_in sa;
  struct in_addr ina;

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd == -1) {
    syslog(LOG_NOTICE, "socket: %s", strerror(errno));
    log_exit();
  }

  retval = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&x, sizeof(x));
  if (retval == -1) {
    syslog(LOG_NOTICE, "setsockopt: %s", strerror(errno));
    log_exit();
  }

  ina.s_addr = inet_addr(opt.listenhost);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(opt.listenport);
  sa.sin_addr = ina;

  retval = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
  if (retval == -1) {
    syslog(LOG_NOTICE, "bind: %s", strerror(errno));
    log_exit();
  }

  retval = listen(fd, 1);
  if (retval == -1) {
    syslog(LOG_NOTICE, "listen: %s", strerror(errno));
    log_exit();
  }

  syslog(LOG_NOTICE, "Listening on %s port %i", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

  return fd;
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
	  syslog(LOG_NOTICE, "decode_base64: input string incomplete");
	  return;
	}
	strncpy(input, buf, strlen(input));
	return;
      }
      if (dtable[c] & 0x80) {
	syslog(LOG_NOTICE, "decode_base64: illegal character '%c' in input string", c);
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

void handshake(int fd)
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

  conn = accept(fd, (struct sockaddr *)&sac, &socks);
  if (conn == -1) {
    syslog(LOG_NOTICE, "accept: %s", strerror(errno));
    return;
  }

  if(opt.verbose)
    syslog(LOG_NOTICE, "Connect from %s port %i", inet_ntoa(sac.sin_addr), ntohs(sac.sin_port));

  secure_read(conn, buf, BUFSIZE);
  while(!(strncmp(buf, "", BUFSIZE) == 0)) {
    if(strncmp(buf, "Authorization: Basic ", 21) == 0) {
      strncpy(password, buf+21, PASSWORDSIZE);
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
    net_output(conn, "HTTP/1.0 401 Authorization Required\r\n");
    snprintf(buf, BUFSIZE, "Server: %s %s (C) %s\r\n", PACKAGE, VERSION, COPYRIGHT);
    net_output(conn, buf);
    net_output(conn, "WWW-Authenticate: Basic realm=\"fwlogwatch\"\r\n");
    net_output(conn, "Connection: close\r\n");
    net_output(conn, "Content-Type: text/html\r\n\r\n");
    net_output(conn, "<html>\n<head>\n<title>Authorization Required</title>\n</head>\n");
    net_output(conn, "<body>\n<h1>Authorization Required</h1>\n</body>\n</html>\n");
  } else {
    net_output(conn, "HTTP/1.0 200 OK\r\n");
    snprintf(buf, BUFSIZE, "Server: %s %s (C) %s\r\n", PACKAGE, VERSION, COPYRIGHT);
    net_output(conn, buf);
    net_output(conn, "Connection: close\r\n");
    net_output(conn, "Content-Type: text/html\r\n\r\n");

    net_output(conn, "<html>\n<head>\n<title>fwlogwatch status</title>\n</head>\n");
    snprintf(buf, BUFSIZE, "<body text=\"#%s\" bgcolor=\"#%s\">\n", opt.textcol, opt.bgcol);
    net_output(conn, buf);
    net_output(conn, "<font face=\"Arial, Helvetica\">\n");
    net_output(conn, "<div align=\"center\">\n<h1>fwlogwatch status</h1>\n</div>\n");
    net_output(conn, "<h2>General info</h2>\n");

    net_output(conn, "<table border=\"0\">\n");
    strftime(nows, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&opt.now));
    snprintf(buf, BUFSIZE, "<tr><td>The daemon was started</td><td>%s</td></tr>\n", nows);
    net_output(conn, buf);

    now = time(NULL);
    strftime(nows, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&now));
    snprintf(buf, BUFSIZE, "<tr><td>Now it's</td><td>%s</td></tr>\n", nows);
    net_output(conn, buf);

    output_timediff(opt.now, now, nows);
    snprintf(buf, BUFSIZE, "<tr><td>Running time:</td><td>%s</td></tr>\n", nows);
    net_output(conn, buf);

    snprintf(buf, BUFSIZE, "<tr><td>Alert threshold:</td><td>%d entries</td></tr>\n<tr><td>Discard timeout:</td><td>%d seconds</td></tr>\n", opt.threshold, opt.recent);
    net_output(conn, buf);

    {
      char buf2[BUFSIZE];

      show_mode_opts(buf2);
      snprintf(buf, BUFSIZE, "<tr><td>Response mode:</td><td>%s</td></tr>\n", buf2);
    }
    net_output(conn, buf);

    net_output(conn, "</table>\n");

    net_output(conn, "<h2>Connection cache</h2>\n");
    net_output(conn, "<table border=\"0\">\n");
    snprintf(buf, BUFSIZE, "<tr bgcolor=\"#%s\" align=\"center\"><td>count</td><td>IP address</td><td>remaining time</td></tr>\n", opt.rowcol1);
    net_output(conn, buf);
    this = first;
    while(this != NULL) {
      time_t remaining;

      if (this->end_time != 0) {
	remaining = opt.recent - (now - this->end_time);
      } else {
	remaining = opt.recent - (now - this->start_time);
      }
      snprintf(buf, BUFSIZE, "<tr bgcolor=\"#%s\" align=\"center\"><td>%d</td><td>%s</td><td>%d</td></tr>\n", (color == 1)?opt.rowcol2:opt.rowcol1, this->count, inet_ntoa(this->shost), (int)remaining);
      if (color == 1) {
	color = 2;
      } else {
	color = 1;
      }
      net_output(conn, buf);
      this = this->next;
    }
    net_output(conn, "</table>\n<br>\n");

    color = 1;
    net_output(conn, "<h2>Host status</h2>\n");
    net_output(conn, "<table border=\"0\">\n");
    snprintf(buf, BUFSIZE, "<tr bgcolor=\"#%s\" align=\"center\"><td>IP address</td><td>status</td><td>remaining time</td></tr>\n", opt.rowcol1);
    net_output(conn, buf);
    this_host = first_host;
    while(this_host != NULL) {
      if (this_host->time == 0) {
	snprintf(buf, BUFSIZE, "<tr bgcolor=\"#%s\" align=\"center\"><td>%s</td><td>Known host</td><td>-</td></tr>\n", (color == 1)?opt.rowcol2:opt.rowcol1, inet_ntoa(this_host->shost));
      } else {
	strftime(nows, TIMESIZE, "%Y-%m-%d %H:%M:%S", localtime(&this_host->time));
	snprintf(buf, BUFSIZE, "<tr bgcolor=\"#%s\" align=\"center\"><td>%s</td><td>Added %s</td><td>%d</td></tr>\n", (color == 1)?opt.rowcol2:opt.rowcol1, inet_ntoa(this_host->shost), nows, (int)(opt.recent - (now - this_host->time)));
      }
      if (color == 1) {
	color = 2;
      } else {
	color = 1;
      }
      net_output(conn, buf);
      this_host = this_host->next;
    }
    net_output(conn, "</table>\n<br><br>\n");

    snprintf(buf, BUFSIZE, "<small>%s %s &copy; %s</small>\n", PACKAGE, VERSION, COPYRIGHT);
    net_output(conn, buf);
    net_output(conn, "</font>\n</body>\n</html>\n");
  }

  retval = close(conn);
  if (retval == -1) {
    syslog(LOG_NOTICE, "close: %s", strerror(errno));
  }

  if(opt.verbose)
    syslog(LOG_NOTICE, "Connection closed");

  return;
}
