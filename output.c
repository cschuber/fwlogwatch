/* $Id: output.c,v 1.13 2002/02/14 21:09:41 bwess Exp $ */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "output.h"
#include "resolve.h"

extern struct options opt;
extern struct conn_data *first;

void separate(char space)
{
  if (opt.html) {
    printf("</td><td>");
  } else {
    if (space) {
      printf(" ");
    }
  }
}

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

  part = diff / 86400; // days
  snprintf(td, TIMESIZE, "%02d:", part);
  diff = diff % 86400;

  part = diff / 3600; // hours
  snprintf(tmp, 4, "%02d:", part);
  strncat(td, tmp, 4);
  diff = diff % 3600;

  part = diff / 60; // minutes
  snprintf(tmp, 4, "%02d:", part);
  strncat(td, tmp, 4);

  part = diff % 60;
  snprintf(tmp, 3, "%02d", part); // seconds
  strncat(td, tmp, 3);
}

void output_res_common(char *text)
{
  separate(NOSPACE);

  if (strncmp(text, "-", 1) != 0) {
    if (opt.html) {
      printf("%s", text);
    } else {
      printf(" (%s)", text);
    }
  } else {
    if (opt.html) {
      printf("-");
    }
  }
}

void output_resolved(struct conn_data *input)
{
  char *proto;
  char time[TIMESIZE];

  if (opt.html) {
    if (opt.html == 1) {
      printf("<tr bgcolor=\"#%s\" align=\"center\"><td>", opt.rowcol2);
    } else {
      printf("<tr bgcolor=\"#%s\" align=\"center\"><td>", opt.rowcol1);
    }
  }
  printf("%d", input->count);

  if(opt.times) {
    separate(SPACE);

    if(!opt.html)
      printf("[");

    strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->start_time));
    printf("%s", time);

    separate(SPACE);

    if(!opt.html)
      printf("to ");

    if(input->end_time != 0) {
      strftime(time, TIMESIZE, "%b %d %H:%M:%S", localtime(&input->end_time));
      printf("%s", time);
    } else {
      printf("-");
    }

    if(!opt.html)
      printf("]");
  }

  if(opt.duration) {

    separate(SPACE);

    if(!opt.html)
      printf("(");

    output_timediff(input->start_time, input->end_time, time);
    if(strlen(time) > 0) {
      printf("%s", time);
    } else {
      printf("-");
    }

    if(!opt.html)
      printf(")");
  }

  if(opt.loghost) {
    separate(SPACE);

    printf("%s", input->hostname);
  }

  if(opt.chains) {
    separate(SPACE);

    printf("%s", input->chainlabel);
  }

  if(opt.branches) {
    separate(SPACE);

    printf("%s", input->branchname);
  }

  if(opt.ifs) {
    separate(SPACE);

    printf("%s", input->interface);
  }

  proto = resolve_protocol(input->protocol);
  if(opt.proto) {
    separate(SPACE);

    printf("%s", proto);
  }

  if (!opt.html)
    printf(" packet%s", (input->count == 1) ? "" : "s");

  if (opt.src_ip) {
    separate(SPACE);

    if (!opt.html)
      printf("from ");

    printf("%s", inet_ntoa(input->shost));

    if(opt.resolve) {
      output_res_common(resolve_hostname(input->shost));
    }
  }

  if (opt.src_port) {
    separate(SPACE);

    if (!opt.html)
      printf("port ");

    printf("%d", input->sport);

    output_res_common(resolve_service(input->sport, proto));
  }

  if (opt.dst_ip) {
    separate(SPACE);

    if (!opt.html)
      printf("to ");

    printf("%s", inet_ntoa(input->dhost));

    if(opt.resolve) {
      output_res_common(resolve_hostname(input->dhost));
    }
  }

  if (opt.dst_port) {
    separate(SPACE);

    if (!opt.html)
      printf("port ");

    printf("%d", input->dport);

    output_res_common(resolve_service(input->dport, proto));
  }

  if(opt.opts) {
    separate(NOSPACE);

    if ((input->flags & (TCP_ACK|TCP_FIN|TCP_RST|TCP_PSH|TCP_URG)) != 0) {
      if (!opt.html)
	printf(" ");

      if (input->flags & TCP_SYN) { printf("s"); } else { printf ("-"); }
      if (input->flags & TCP_ACK) { printf("a"); } else { printf ("-"); }
      if (input->flags & TCP_FIN) { printf("f"); } else { printf ("-"); }
      if (input->flags & TCP_RST) { printf("r"); } else { printf ("-"); }
      if (input->flags & TCP_PSH) { printf("p"); } else { printf ("-"); }
      if (input->flags & TCP_URG) { printf("u"); } else { printf ("-"); }
    } else {
      if (input->flags & TCP_SYN) {
	if (!opt.html)
	  printf(" ");
	printf("SYN");
      } else {
	if (opt.html)
	  printf("-");
      }
    }
  }

  if(opt.html) {
    printf("</td></tr>\n");
  } else {
    printf("\n");
  }
}

void output_html_header()
{
  char time[TIMESIZE];
  
  strftime(time, TIMESIZE, "%a %b %d %H:%M:%S %Z %Y", localtime(&opt.now));
  printf("<html><head><title>fwlogwatch output: %s</title>\n", time);
  printf("<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
  printf("<meta http-equiv=\"expires\" content=\"0\">\n");
  printf("</head>\n");
  printf("<body text=\"#%s\" bgcolor=\"#%s\" link=\"#%s\" alink=\"#%s\" vlink=\"#%s\">\n", opt.textcol, opt.bgcol, opt.textcol, opt.textcol, opt.textcol);
  printf("<font face=\"Arial, Helvetica\">");
  printf("<div align=\"center\">\n");
  printf("<h1>fwlogwatch output</h1>\n");
}

void output_html_table()
{
  printf("<br><br>\n");
  printf("<table border=\"0\">\n");
  printf("<tr bgcolor=\"#%s\" align=\"center\"><td>#</td>", opt.rowcol1);

  if(opt.times)
    printf("<td>start</td><td>end</td>");

  if(opt.duration)
    printf("<td>interval</td>");

  if(opt.loghost)
    printf("<td>loghost</td>");

  if(opt.chains)
    printf("<td>chain</td>");

  if(opt.branches)
    printf("<td>target</td>");

  if(opt.ifs)
    printf("<td>interface</td>");

  if(opt.proto)
    printf("<td>proto</td>");

  if(opt.src_ip) {
    printf("<td>source</td>");
    if(opt.resolve)
      printf("<td>hostname</td>");
  }

  if (opt.src_port)
    printf("<td>port</td><td>service</td>");

  if(opt.dst_ip) {
    printf("<td>destination</td>");
    if(opt.resolve)
      printf("<td>hostname</td>");
  }

  if (opt.dst_port)
    printf("<td>port</td><td>service</td>");

  if (opt.opts)
    printf("<td>opts</td>");

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
    this = this->next;
  }
}
