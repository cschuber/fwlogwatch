/* $Id: output.c,v 1.2 2002/02/14 20:09:16 bwess Exp $ */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "output.h"
#include "resolve.h"

extern struct options opt;

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

void output_time(time_t time, char *stime)
{
  struct tm *tm;

  tm = gmtime(&time);
  strftime(stime, TIMESIZE, "%b %d %H:%M:%S", tm);
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
      printf("<tr bgcolor=\"#%s\" align=\"center\"><td>", ROWCOLOR2);
    } else {
      printf("<tr bgcolor=\"#%s\" align=\"center\"><td>", ROWCOLOR1);
    }
  }
  printf("%d", input->count);

  if(opt.times) {
    separate(SPACE);

    if(!opt.html)
      printf("[");

    output_time(input->start_time, time);
    printf("%s", time);

    separate(SPACE);

    if(!opt.html)
      printf("to ");

    if(input->end_time != 0) {
      output_time(input->end_time, time);
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
    printf(" connect%s", (input->count == 1) ? "" : "s");

  if (opt.src_ip) {
    separate(SPACE);

    if (!opt.html)
      printf("from ");

    printf("%s", input->shost);

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

    printf("%s", input->dhost);

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

    if (input->syn == 1) {
      if (opt.html) {
	printf("SYN");
      } else {
	printf(" SYN");
      }
    } else {
      if (opt.html)
	printf("-");
    }
  }

  if(opt.html) {
    printf("</td></tr>\n");
  } else {
    printf(".\n");
  }
}

void output_html_header()
{
  printf("<html><head><title>fwlogwatch output</title></head>\n");
  printf("<body text=\"#%s\" bgcolor=\"#%s\">\n", TEXTCOLOR, BGCOLOR);
  printf("<font face=\"Arial, Helvetica\">\n");
  printf("<div align=\"center\">\n");
  printf("<h1>fwlogwatch output</h1>\n");
}

void output_html_table()
{
  printf("<br><br>\n");
  printf("<table border=\"0\">\n");
  printf("<tr bgcolor=\"#%s\" align=\"center\"><td>#</td>", ROWCOLOR1);

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

  if(opt.src_ip)
    printf("<td>source</td>");

  if(opt.resolve)
    printf("<td>hostname</td>");

  if (opt.src_port)
    printf("<td>port</td><td>service</td>");

  if(opt.dst_ip)
    printf("<td>destination</td>");

  if(opt.resolve)
    printf("<td>hostname</td>");

  if (opt.dst_port)
    printf("<td>port</td><td>service</td>");

  if (opt.opts)
    printf("<td>opts</td>");

  printf("</tr>\n");
}

void output_html_footer()
{
  printf("</table></div><br>\n");
  printf("<small>%s %s &copy; %s</small>\n", PACKAGE, VERSION, COPYRIGHT);
  printf("</font></body></html>\n");
}
