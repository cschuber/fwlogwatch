/* $Id: output.c,v 1.21 2002/02/24 14:27:30 bwess Exp $ */

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
    snprintf(td, 1, "-");
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

void output_html(struct conn_data *input)
{
  char *proto, time[TIMESIZE], buf[HOSTLEN];
  struct whois_entry *we;

  if (opt.html == 1) {
    printf("<tr bgcolor=\"#%s\" align=\"center\"><td>", opt.rowcol2);
  } else {
    printf("<tr bgcolor=\"#%s\" align=\"center\"><td>", opt.rowcol1);
  }

  printf("%d", input->count);

  if(opt.stimes) {
    printf("</td><td>");
    strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->start_time));
    printf("%s", time);
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
    printf("</td><td>");
    output_timediff(input->start_time, input->end_time, time);
    printf("%s", time);
  }

  if(opt.loghost) {
    printf("</td><td>");
    printf("%s", input->hostname);
  }

  if(opt.chains) {
    printf("</td><td>");
    printf("%s", input->chainlabel);
  }

  if(opt.branches) {
    printf("</td><td>");
    printf("%s", input->branchname);
  }

  if(opt.ifs) {
    printf("</td><td>");
    printf("%s", input->interface);
  }

  proto = resolve_protocol(input->protocol);
  if(opt.proto) {
    printf("</td><td>");
    printf("%s", proto);
  }

  if (opt.datalen) {
    printf("</td><td>");
    printf("%d", input->datalen);
  }

  if (opt.src_ip) {
    printf("</td><td>");
    printf("%s", inet_ntoa(input->shost));

    if(opt.resolve) {
      printf("</td><td>");
      printf("%s", resolve_hostname(input->shost));
    }

    if(opt.whois_lookup) {
      printf("</td><td>");
      we = whois(input->shost);
      if (we != NULL) {
	snprintf(buf, HOSTLEN, "%s %s AS%d %s", we->ip_route, we->ip_descr, we->as_number, we->as_descr);
      } else {
	snprintf(buf, HOSTLEN, "-");
      }
      printf("%s", buf);
    }
  }

  if (opt.src_port) {
    printf("</td><td>");
    printf("%d", input->sport);

    if (opt.sresolve) {
      printf("</td><td>");
      printf("%s", resolve_service(input->sport, proto));
    }
  }

  if (opt.dst_ip) {
    printf("</td><td>");
    printf("%s", inet_ntoa(input->dhost));

    if(opt.resolve) {
      printf("</td><td>");
      printf("%s", resolve_hostname(input->dhost));
    }
  }

  if (opt.dst_port) {
    printf("</td><td>");
    printf("%d", input->dport);

    if (opt.sresolve) {
      printf("</td><td>");
      printf("%s", resolve_service(input->dport, proto));
    }
  }

  if(opt.opts) {
    printf("</td><td>");
    if ((input->flags & (TCP_ACK|TCP_FIN|TCP_RST|TCP_PSH|TCP_URG)) != 0) {
      if (input->flags & TCP_SYN) { printf("s"); } else { printf ("-"); }
      if (input->flags & TCP_ACK) { printf("a"); } else { printf ("-"); }
      if (input->flags & TCP_FIN) { printf("f"); } else { printf ("-"); }
      if (input->flags & TCP_RST) { printf("r"); } else { printf ("-"); }
      if (input->flags & TCP_PSH) { printf("p"); } else { printf ("-"); }
      if (input->flags & TCP_URG) { printf("u"); } else { printf ("-"); }
    } else {
      if (input->flags & TCP_SYN) {
	printf("SYN");
      } else {
	printf("-");
      }
    }
  }

  printf("</td></tr>\n");
}

void output_plain(struct conn_data *input)
{
  char *proto, time[TIMESIZE], buf[HOSTLEN];
  struct whois_entry *we;
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
    if(strlen(time) > 0) {
      printf("%s", time);
    } else {
      printf("-");
    }
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
  if(opt.proto) {
    printf(" %s", proto);
  }

  if(input->count == 1) {
    printf(_(" packet"));
  } else {
    printf(_(" packets"));
  }

  if (opt.datalen) {
    printf(_(" (%d bytes)"), input->datalen);
  }

  if (opt.src_ip) {
    printf(_(" from %s"), inet_ntoa(input->shost));

    if(opt.resolve) {
      printf(" (%s)", resolve_hostname(input->shost));
    }

    if(opt.whois_lookup) {
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
    if ((input->flags & (TCP_ACK|TCP_FIN|TCP_RST|TCP_PSH|TCP_URG)) != 0) {
      printf(" ");

      if (input->flags & TCP_SYN) { printf("s"); } else { printf ("-"); }
      if (input->flags & TCP_ACK) { printf("a"); } else { printf ("-"); }
      if (input->flags & TCP_FIN) { printf("f"); } else { printf ("-"); }
      if (input->flags & TCP_RST) { printf("r"); } else { printf ("-"); }
      if (input->flags & TCP_PSH) { printf("p"); } else { printf ("-"); }
      if (input->flags & TCP_URG) { printf("u"); } else { printf ("-"); }
    } else {
      if (input->flags & TCP_SYN) {
	printf(" SYN");
      } else {
	printf(" -");
      }
    }
  }

  printf("\n");
}

void output_html_header()
{
  char time[TIMESIZE];

  strftime(time, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&opt.now));
  printf("<html><head><title>%s - %s</title>\n", opt.title, time);
  printf("<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
  printf("<meta http-equiv=\"expires\" content=\"0\">\n");
  printf("</head>\n");
  printf("<body text=\"#%s\" bgcolor=\"#%s\" link=\"#%s\" alink=\"#%s\" vlink=\"#%s\">\n", opt.textcol, opt.bgcol, opt.textcol, opt.textcol, opt.textcol);
  printf("<font face=\"Arial, Helvetica\">");
  printf("<div align=\"center\">\n");
  printf("<h1>%s</h1>\n", opt.title);
}

void output_html_table()
{
  printf("<br><br>\n");
  printf("<table border=\"0\">\n");
  printf("<tr bgcolor=\"#%s\" align=\"center\"><td>#</td>", opt.rowcol1);

  if(opt.stimes)
    printf(_("<td>start</td>"));

  if(opt.etimes)
    printf(_("<td>end</td>"));

  if(opt.duration)
    printf(_("<td>interval</td>"));

  if(opt.loghost)
    printf(_("<td>loghost</td>"));

  if(opt.chains)
    printf(_("<td>chain</td>"));

  if(opt.branches)
    printf(_("<td>target</td>"));

  if(opt.ifs)
    printf(_("<td>interface</td>"));

  if(opt.proto)
    printf(_("<td>proto</td>"));

  if(opt.datalen)
    printf(_("<td>bytes</td>"));

  if(opt.src_ip) {
    printf(_("<td>source</td>"));
    if(opt.resolve)
      printf(_("<td>hostname</td>"));
    if(opt.whois_lookup)
      printf(_("<td>whois information</td>"));
  }

  if (opt.src_port) {
    printf(_("<td>port</td>"));
    if (opt.sresolve)
      printf(_("<td>service</td>"));
  }

  if(opt.dst_ip) {
    printf(_("<td>destination</td>"));
    if(opt.resolve)
      printf(_("<td>hostname</td>"));
  }

  if (opt.dst_port) {
    printf(_("<td>port</td>"));
    if (opt.sresolve)
      printf(_("<td>service</td>"));
  }

  if (opt.opts)
    printf(_("<td>opts</td>"));

  printf("</tr>\n");
}

void output_html_footer()
{
  printf("</table></div><br>\n");
  printf("<small><a href=\"http://cert.uni-stuttgart.de/projects/fwlogwatch/\">%s</a> %s &copy; %s</small>\n", PACKAGE, VERSION, COPYRIGHT);
  printf("</font></body></html>\n");
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
