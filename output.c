/* $Id: output.c,v 1.28 2003/06/23 15:26:53 bwess Exp $ */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include "output.h"
#include "resolve.h"
#include "utils.h"
#include "whois.h"

extern struct options opt;
extern struct conn_data *first;

void output_timediff(time_t start, time_t end, char *td)
{
  time_t diff;
  int part;
  char tmp[4];

  diff = end - start;
  if (diff <= 0) {
    snprintf(td, 2, "-");
    return;
  }

  part = diff / 86400; /* days */
  snprintf(td, TIMESIZE, "%02d:", part);
  diff = diff % 86400;

  part = diff / 3600; /* hours */
  snprintf(tmp, 4, "%02d:", part);
  strncat(td, tmp, 4);
  diff = diff % 3600;

  part = diff / 60; /* minutes */
  snprintf(tmp, 4, "%02d:", part);
  strncat(td, tmp, 4);

  part = diff % 60; /* seconds */
  snprintf(tmp, 3, "%02d", part);
  strncat(td, tmp, 3);
}

void output_tcp_opts(struct conn_data *input, char *buf)
{
  if ((input->flags & (TCP_ACK|TCP_FIN|TCP_RST|TCP_PSH|TCP_URG)) != 0) {
    if (input->flags & TCP_SYN) { strcpy(buf, "s"); } else { strcpy (buf, "-"); }
    if (input->flags & TCP_ACK) { strcat(buf, "a"); } else { strcat (buf, "-"); }
    if (input->flags & TCP_FIN) { strcat(buf, "f"); } else { strcat (buf, "-"); }
    if (input->flags & TCP_RST) { strcat(buf, "r"); } else { strcat (buf, "-"); }
    if (input->flags & TCP_PSH) { strcat(buf, "p"); } else { strcat (buf, "-"); }
    if (input->flags & TCP_URG) { strcat(buf, "u"); } else { strcat (buf, "-"); }
  } else {
    if (input->flags & TCP_SYN) {
      strcpy(buf, "SYN");
    } else {
      strcpy(buf, "-");
    }
  }
}

void output_html_entry(struct conn_data *input, FILE *fd)
{
  char *proto, time[TIMESIZE], buf[HOSTLEN];

  if (opt.html == 2) {
    fprintf(fd, "<tr class=\"r%d\" align=\"center\"><td>", opt.html);
  } else {
    fprintf(fd, "<tr class=\"r%d\" align=\"center\"><td>", opt.html);
  }

  fprintf(fd, "%d", input->count);

  if(opt.stimes) {
    strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->start_time));
    fprintf(fd, "</td><td>%s", time);
  }

  if(opt.etimes) {
    fprintf(fd, "</td><td>");
    if(input->end_time != 0) {
      strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->end_time));
      fprintf(fd, "%s", time);
    } else {
      fprintf(fd, "-");
    }
  }

  if(opt.duration) {
    output_timediff(input->start_time, input->end_time, time);
    fprintf(fd, "</td><td>%s", time);
  }

  if(opt.loghost)
    fprintf(fd, "</td><td>%s", input->hostname);

  if(opt.chains)
    fprintf(fd, "</td><td>%s", input->chainlabel);

  if(opt.branches)
    fprintf(fd, "</td><td>%s", input->branchname);

  if(opt.ifs)
    fprintf(fd, "</td><td>%s", input->interface);

  proto = resolve_protocol(input->protocol);
  if(opt.proto)
    fprintf(fd, "</td><td>%s", proto);

  if (opt.datalen)
    fprintf(fd, "</td><td>%d", input->datalen);

  if (opt.src_ip) {
    fprintf(fd, "</td><td>%s", inet_ntoa(input->shost));
    if(opt.resolve)
      fprintf(fd, "</td><td>%s", resolve_hostname(input->shost));
    if(opt.whois_lookup) {
      struct whois_entry *we;
      we = whois(input->shost);
      if (we != NULL) {
	snprintf(buf, HOSTLEN, "%s %s AS%d %s", we->ip_route, we->ip_descr, we->as_number, we->as_descr);
      } else {
	snprintf(buf, HOSTLEN, "-");
      }
      fprintf(fd, "</td><td>%s", buf);
    }
  }

  if (opt.src_port) {
    fprintf(fd, "</td><td>%d", input->sport);
    if (opt.sresolve)
      fprintf(fd, "</td><td>%s", resolve_service(input->sport, proto));
  }

  if (opt.dst_ip) {
    fprintf(fd, "</td><td>%s", inet_ntoa(input->dhost));
    if(opt.resolve)
      fprintf(fd, "</td><td>%s", resolve_hostname(input->dhost));
  }

  if (opt.dst_port) {
    fprintf(fd, "</td><td>%d", input->dport);
    if (opt.sresolve)
      fprintf(fd, "</td><td>%s", resolve_service(input->dport, proto));
  }

  if(opt.opts) {
    output_tcp_opts(input, buf);
    fprintf(fd, "</td><td>%s", buf);
  }

  fprintf(fd, "</td></tr>\n");
}

void output_text_entry(struct conn_data *input, FILE *fd)
{
  char *proto, time[TIMESIZE], buf[HOSTLEN];
  unsigned char first = 1;

  if(opt.stimes) {
    strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->start_time));
    fprintf(fd, "%s", time);
    first = 0;
  }

  if(opt.etimes) {
    if(!first)
      fprintf(fd, _(" to "));
    if(input->end_time != 0) {
      strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->end_time));
      fprintf(fd, "%s", time);
    } else {
      fprintf(fd, "-");
    }
    first = 0;
  }

  if(opt.duration) {
    if(!first)
      fprintf(fd, " ");
    output_timediff(input->start_time, input->end_time, time);
    fprintf(fd, "%s", time);
    first = 0;
  }

  if(opt.loghost) {
    if(!first)
      fprintf(fd, " ");
    fprintf(fd, "%s", input->hostname);
    first = 0;
  }

  if(opt.chains) {
    if(!first)
      fprintf(fd, " ");
    fprintf(fd, "%s", input->chainlabel);
    first = 0;
  }

  if(opt.branches) {
    if(!first)
      fprintf(fd, " ");
    fprintf(fd, "%s", input->branchname);
    first = 0;
  }

  if(opt.ifs) {
    if(!first)
      fprintf(fd, " ");
    fprintf(fd, "%s", input->interface);
    first = 0;
  }

  if(!first)
    fprintf(fd, " ");
  fprintf(fd, "%d", input->count);

  proto = resolve_protocol(input->protocol);
  if(opt.proto)
    fprintf(fd, " %s", proto);

  if(input->count == 1) {
    fprintf(fd, _(" packet"));
  } else {
    fprintf(fd, _(" packets"));
  }

  if (opt.datalen)
    fprintf(fd, _(" (%d bytes)"), input->datalen);

  if (opt.src_ip) {
    fprintf(fd, _(" from %s"), inet_ntoa(input->shost));
    if(opt.resolve)
      fprintf(fd, " (%s)", resolve_hostname(input->shost));
    if(opt.whois_lookup) {
      struct whois_entry *we;
      we = whois(input->shost);
      if (we != NULL) {
	snprintf(buf, HOSTLEN, "%s %s AS%d %s", we->ip_route, we->ip_descr, we->as_number, we->as_descr);
      } else {
	snprintf(buf, HOSTLEN, "-");
      }
      fprintf(fd, " [%s]", buf);
    }
  }

  if (opt.src_port) {
    fprintf(fd, _(" port %d"), input->sport);
    if (opt.sresolve)
      fprintf(fd, " (%s)", resolve_service(input->sport, proto));
  }

  if (opt.dst_ip) {
    fprintf(fd, _(" to %s"), inet_ntoa(input->dhost));
    if(opt.resolve) {
      fprintf(fd, " (%s)", resolve_hostname(input->dhost));
    }
  }

  if (opt.dst_port) {
    fprintf(fd, _(" port %d"), input->dport);
    if (opt.sresolve)
      fprintf(fd, " (%s)", resolve_service(input->dport, proto));
  }

  if(opt.opts) {
      output_tcp_opts(input, buf);
      fprintf(fd, " %s", buf);
  }

  fprintf(fd, "\n");
}

void output_html_table(FILE *fd)
{
  fprintf(fd, "</p>\n");
  fprintf(fd, "<table border=\"0\" cellspacing=\"1\" cellpadding=\"3\">\n");
  fprintf(fd, "<tr align=\"center\"><th>#</th>");

  if(opt.stimes)
    fprintf(fd, _("<th>start</th>"));

  if(opt.etimes)
    fprintf(fd, _("<th>end</th>"));

  if(opt.duration)
    fprintf(fd, _("<th>interval</th>"));

  if(opt.loghost)
    fprintf(fd, _("<th>loghost</th>"));

  if(opt.chains)
    fprintf(fd, _("<th>chain</th>"));

  if(opt.branches)
    fprintf(fd, _("<th>target</th>"));

  if(opt.ifs)
    fprintf(fd, _("<th>interface</th>"));

  if(opt.proto)
    fprintf(fd, _("<th>proto</th>"));

  if(opt.datalen)
    fprintf(fd, _("<th>bytes</th>"));

  if(opt.src_ip) {
    fprintf(fd, _("<th>source</th>"));
    if(opt.resolve)
      fprintf(fd, _("<th>hostname</th>"));
    if(opt.whois_lookup)
      fprintf(fd, _("<th>whois information</th>"));
  }

  if (opt.src_port) {
    fprintf(fd, _("<th>port</th>"));
    if (opt.sresolve)
      fprintf(fd, _("<th>service</th>"));
  }

  if(opt.dst_ip) {
    fprintf(fd, _("<th>destination</th>"));
    if(opt.resolve)
      fprintf(fd, _("<th>hostname</th>"));
  }

  if (opt.dst_port) {
    fprintf(fd, _("<th>port</th>"));
    if (opt.sresolve)
      fprintf(fd, _("<th>service</th>"));
  }

  if (opt.opts)
    fprintf(fd, _("<th>opts</th>"));

  fprintf(fd, "</tr>\n");
}

void output_html_header(int fd) {
  char time[TIMESIZE];

  fdprintf(fd, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n");
  strftime(time, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&opt.now));
  fdprintf(fd, "<html>\n<head>\n<title>%s - %s</title>\n", opt.title, time);
  fdprintf(fd, "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n");
  fdprintf(fd, "<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
  fdprintf(fd, "<meta http-equiv=\"expires\" content=\"0\">\n");
  if((opt.mode == REALTIME_RESPONSE) && (opt.refresh > 0)) {
    fdprintf(fd, "<meta http-equiv=\"refresh\" content=\"%d\">\n", opt.refresh);
  }
  if (opt.stylesheet[0] != '\0') {
    if ((opt.mode != REALTIME_RESPONSE) || (strncmp(opt.stylesheet, "http", 4) == 0)) {
      fdprintf(fd, "<link rel=\"stylesheet\" href=\"%s\" type=\"text/css\">\n", opt.stylesheet);
    } else {
      char buf[BUFSIZE];
      FILE *cssfd;
      int retval;

      cssfd = fopen(opt.stylesheet, "r");
      if (cssfd == NULL) {
	syslog(LOG_NOTICE, "fopen %s: %s", opt.stylesheet, strerror(errno));
      } else {
	fdprintf(fd, "<style type=\"text/css\">\n<!--\n");
	while (fgets(buf, BUFSIZE, cssfd)) fdprintf(fd, buf);
	fdprintf(fd, "-->\n</style>\n");
	retval = fclose(cssfd);
	if (retval == EOF)
	  syslog(LOG_NOTICE, "fclose %s: %s", opt.stylesheet, strerror(errno));
      }
    }
  } else {
    fdprintf(fd, "<style type=\"text/css\">\n<!--\n");
    fdprintf(fd, "body {font-family: verdana, arial, helvetica, sans-serif; font-size: 11px; color: %s; background: %s}\n", opt.textcol, opt.bgcol);
    fdprintf(fd, "th, td {font-family: verdana, arial, helvetica, sans-serif; font-size: 11px; font-weight: normal; color: %s}\n", opt.textcol);
    fdprintf(fd, ".r1 {background: %s}\n", opt.rowcol1);
    fdprintf(fd, ".r2 {background: %s}\n", opt.rowcol2);
    fdprintf(fd, "a:link, a:active, a:visited {color: %s}\n", opt.textcol);
    fdprintf(fd, "-->\n</style>\n");
  }
  fdprintf(fd, "</head>\n<body>\n<center>\n");
  fdprintf(fd, "<h1>%s</h1>\n", opt.title);
}

void output_html_footer(int fd)
{
  fdprintf(fd, "</table>\n</center>\n");
  fdprintf(fd, "<p><small><a href=\"http://cert.uni-stuttgart.de/projects/fwlogwatch/\">%s</a> %s &copy; %s</small></p>\n", PACKAGE, VERSION, COPYRIGHT);
  fdprintf(fd, "</body>\n</html>\n");
}

void output_raw_data(struct conn_data *input)
{
  struct conn_data *this;

  this = first;
  while (this != NULL) {
#ifndef __OpenBSD__
#ifndef __FreeBSD__
    printf("%d;%ld;%ld;"
	   "%s;%s;%s;"
	   "%s;%d;"
	   "%u;%d;"
	   "%u;%d;"
	   "%d\n",
	   input->count, input->start_time, input->end_time,
	   input->hostname, input->chainlabel, input->branchname,
	   input->interface, input->protocol,
	   ntohl(input->shost.s_addr), input->sport,
	   ntohl(input->dhost.s_addr), input->dport,
	   input->flags);
#else
    printf("%d;%ld;%ld;"
	   "%s;%s;%s;"
	   "%s;%d;"
	   "%ld;%d;"
	   "%ld;%d;"
	   "%d\n",
	   input->count, input->start_time, input->end_time,
	   input->hostname, input->chainlabel, input->branchname,
	   input->interface, input->protocol,
	   ntohl(input->shost.s_addr), input->sport,
	   ntohl(input->dhost.s_addr), input->dport,
	   input->flags);
#endif
#else
    printf("%d;%d;%d;"
	   "%s;%s;%s;"
	   "%s;%d;"
	   "%u;%d;"
	   "%u;%d;"
	   "%d\n",
	   input->count, input->start_time, input->end_time,
	   input->hostname, input->chainlabel, input->branchname,
	   input->interface, input->protocol,
	   ntohl(input->shost.s_addr), input->sport,
	   ntohl(input->dhost.s_addr), input->dport,
	   input->flags);
#endif
    this = this->next;
  }
}
