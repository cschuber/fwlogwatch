/* $Id: output.c,v 1.23 2002/05/08 17:24:09 bwess Exp $ */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "output.h"
#include "resolve.h"
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

void output_html(struct conn_data *input)
{
  char *proto, time[TIMESIZE], buf[HOSTLEN];

  if (opt.html == 1) {
    printf("<tr bgcolor=\"%s\" align=\"center\"><td>", opt.rowcol2);
  } else {
    printf("<tr bgcolor=\"%s\" align=\"center\"><td>", opt.rowcol1);
  }

  printf("%d", input->count);

  if(opt.stimes) {
    strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->start_time));
    printf("</td><td>%s", time);
  }

  if(opt.etimes) {
    printf("</td><td>");
    if(input->end_time != 0) {
      strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->end_time));
      printf("%s", time);
    } else {
      printf("-");
    }
  }

  if(opt.duration) {
    output_timediff(input->start_time, input->end_time, time);
    printf("</td><td>%s", time);
  }

  if(opt.loghost)
    printf("</td><td>%s", input->hostname);

  if(opt.chains)
    printf("</td><td>%s", input->chainlabel);

  if(opt.branches)
    printf("</td><td>%s", input->branchname);

  if(opt.ifs)
    printf("</td><td>%s", input->interface);

  proto = resolve_protocol(input->protocol);
  if(opt.proto)
    printf("</td><td>%s", proto);

  if (opt.datalen)
    printf("</td><td>%d", input->datalen);

  if (opt.src_ip) {
    printf("</td><td>%s", inet_ntoa(input->shost));
    if(opt.resolve)
      printf("</td><td>%s", resolve_hostname(input->shost));
    if(opt.whois_lookup) {
      struct whois_entry *we;
      we = whois(input->shost);
      if (we != NULL) {
	snprintf(buf, HOSTLEN, "%s %s AS%d %s", we->ip_route, we->ip_descr, we->as_number, we->as_descr);
      } else {
	snprintf(buf, HOSTLEN, "-");
      }
      printf("</td><td>%s", buf);
    }
  }

  if (opt.src_port) {
    printf("</td><td>%d", input->sport);
    if (opt.sresolve)
      printf("</td><td>%s", resolve_service(input->sport, proto));
  }

  if (opt.dst_ip) {
    printf("</td><td>%s", inet_ntoa(input->dhost));
    if(opt.resolve)
      printf("</td><td>%s", resolve_hostname(input->dhost));
  }

  if (opt.dst_port) {
    printf("</td><td>%d", input->dport);
    if (opt.sresolve)
      printf("</td><td>%s", resolve_service(input->dport, proto));
  }

  if(opt.opts) {
    output_tcp_opts(input, buf);
    printf("</td><td>%s", buf);
  }

  printf("</td></tr>\n");
}

void output_plain(struct conn_data *input)
{
  char *proto, time[TIMESIZE], buf[HOSTLEN];
  unsigned char first = 1;

  if(opt.stimes) {
    strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->start_time));
    printf("%s", time);
    first = 0;
  }

  if(opt.etimes) {
    if(!first)
      printf(_(" to "));
    if(input->end_time != 0) {
      strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->end_time));
      printf("%s", time);
    } else {
      printf("-");
    }
    first = 0;
  }

  if(opt.duration) {
    if(!first)
      printf(" ");
    output_timediff(input->start_time, input->end_time, time);
    printf("%s", time);
    first = 0;
  }

  if(opt.loghost) {
    if(!first)
      printf(" ");
    printf("%s", input->hostname);
    first = 0;
  }

  if(opt.chains) {
    if(!first)
      printf(" ");
    printf("%s", input->chainlabel);
    first = 0;
  }

  if(opt.branches) {
    if(!first)
      printf(" ");
    printf("%s", input->branchname);
    first = 0;
  }

  if(opt.ifs) {
    if(!first)
      printf(" ");
    printf("%s", input->interface);
    first = 0;
  }

  if(!first)
    printf(" ");
  printf("%d", input->count);

  proto = resolve_protocol(input->protocol);
  if(opt.proto)
    printf(" %s", proto);

  if(input->count == 1) {
    printf(_(" packet"));
  } else {
    printf(_(" packets"));
  }

  if (opt.datalen)
    printf(_(" (%d bytes)"), input->datalen);

  if (opt.src_ip) {
    printf(_(" from %s"), inet_ntoa(input->shost));
    if(opt.resolve)
      printf(" (%s)", resolve_hostname(input->shost));
    if(opt.whois_lookup) {
      struct whois_entry *we;
      we = whois(input->shost);
      if (we != NULL) {
	snprintf(buf, HOSTLEN, "%s %s AS%d %s", we->ip_route, we->ip_descr, we->as_number, we->as_descr);
      } else {
	snprintf(buf, HOSTLEN, "-");
      }
      printf(" [%s]", buf);
    }
  }

  if (opt.src_port) {
    printf(_(" port %d"), input->sport);
    if (opt.sresolve)
      printf(" (%s)", resolve_service(input->sport, proto));
  }

  if (opt.dst_ip) {
    printf(_(" to %s"), inet_ntoa(input->dhost));
    if(opt.resolve) {
      printf(" (%s)", resolve_hostname(input->dhost));
    }
  }

  if (opt.dst_port) {
    printf(_(" port %d"), input->dport);
    if (opt.sresolve)
      printf(" (%s)", resolve_service(input->dport, proto));
  }

  if(opt.opts) {
      output_tcp_opts(input, buf);
      printf(" %s", buf);
  }

  printf("\n");
}

void output_html_header()
{
  char time[TIMESIZE];

  printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n");
  strftime(time, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&opt.now));
  printf("<html>\n<head>\n<title>%s - %s</title>\n", opt.title, time);
  printf("<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">\n");
  printf("<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
  printf("<meta http-equiv=\"expires\" content=\"0\">\n");
  if (opt.stylesheet[0] != '\0') {
    printf("<link rel=\"stylesheet\" href=\"%s\">\n", opt.stylesheet);
  } else {
    printf("<style type=\"text/css\">\n<!--\n");
    printf("BODY {font-family: arial, helvetica, sans-serif; color: %s; background: %s}\n", opt.textcol, opt.bgcol);
    printf("A:link, A:active, A:visited {color: %s; background: %s}\n", opt.textcol, opt.bgcol);
    printf("TH, TD {font-family: arial, helvetica, sans-serif; color: %s}\n", opt.textcol);
    printf("SMALL {font-family: arial, helvetica, sans-serif; color: %s; background: %s}\n", opt.textcol, opt.bgcol);
    printf("-->\n</style>\n");
  }
  printf("</head>\n<body>\n");
  printf("<div align=\"center\">\n");
  printf("<h1>%s</h1>\n", opt.title);
}

void output_html_table()
{
  printf("<br><br>\n");
  printf("<table border=\"0\" cellspacing=\"1\" cellpadding=\"3\">\n");
  printf("<tr bgcolor=\"%s\" align=\"center\"><th>#</th>", opt.rowcol1);

  if(opt.stimes)
    printf(_("<th>start</th>"));

  if(opt.etimes)
    printf(_("<th>end</th>"));

  if(opt.duration)
    printf(_("<th>interval</th>"));

  if(opt.loghost)
    printf(_("<th>loghost</th>"));

  if(opt.chains)
    printf(_("<th>chain</th>"));

  if(opt.branches)
    printf(_("<th>target</th>"));

  if(opt.ifs)
    printf(_("<th>interface</th>"));

  if(opt.proto)
    printf(_("<th>proto</th>"));

  if(opt.datalen)
    printf(_("<th>bytes</th>"));

  if(opt.src_ip) {
    printf(_("<th>source</th>"));
    if(opt.resolve)
      printf(_("<th>hostname</th>"));
    if(opt.whois_lookup)
      printf(_("<th>whois information</th>"));
  }

  if (opt.src_port) {
    printf(_("<th>port</th>"));
    if (opt.sresolve)
      printf(_("<th>service</th>"));
  }

  if(opt.dst_ip) {
    printf(_("<th>destination</th>"));
    if(opt.resolve)
      printf(_("<th>hostname</th>"));
  }

  if (opt.dst_port) {
    printf(_("<th>port</th>"));
    if (opt.sresolve)
      printf(_("<th>service</th>"));
  }

  if (opt.opts)
    printf(_("<th>opts</th>"));

  printf("</tr>\n");
}

void output_html_footer()
{
  printf("</table>\n</div><br>\n");
  printf("<small><a href=\"http://cert.uni-stuttgart.de/projects/fwlogwatch/\">%s</a> %s &copy; %s</small>\n", PACKAGE, VERSION, COPYRIGHT);
  printf("</body>\n</html>\n");
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
