/* $Id: report.c,v 1.3 2002/02/14 20:25:35 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "main.h"
#include "resolve.h"
#include "output.h"
#include "response.h"
#include "utils.h"

extern struct options opt;
extern struct conn_data *first;

void generate_header(FILE *fd, struct report_data *data, unsigned char options)
{
  if(options & OPT_MODIFY)
    fprintf(fd, " 1 ");
  fprintf(fd, "From: %s\n", data->sender);

  if(options & OPT_MODIFY)
    fprintf(fd, " 2 ");
  fprintf(fd, "To: %s\n", data->recipient);

  if((strlen(data->cc) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, " 3 ");
    fprintf(fd, "Cc: %s\n", data->cc);
  }

  if(options & OPT_MODIFY)
    fprintf(fd, " 4 ");
  fprintf(fd, "Subject: %s\n", data->subject);

  if(options & OPT_GENERATOR)
    fprintf(fd, "X-Generator: %s %s (C) %s\n", PACKAGE, VERSION, COPYRIGHT);

  fprintf(fd, "\n");
}

void generate_report(FILE *fd, struct report_data *data, unsigned char options)
{
  if(options & OPT_MODIFY)
    fprintf(fd, " 5 ");
  fprintf(fd, "Offending IP address:      %s\n", data->shost);

  if((strlen(data->shostname) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, " 6 ");
    fprintf(fd, "Offending IP name:         %s\n", data->shostname);
  }

  if(options & OPT_MODIFY)
    fprintf(fd, " 7 ");
  fprintf(fd, "Target IP address:         %s\n", data->dhost);

  if((strlen(data->dhostname) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, " 8 ");
    fprintf(fd, "Target IP name:            %s\n", data->dhostname);
  }

  if(options & OPT_MODIFY)
    fprintf(fd, " 9 ");
  fprintf(fd, "Number of logged attempts: %s\n", data->count);

  if((strlen(data->t_start) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "10 ");
    fprintf(fd, "Start time:                %s\n", data->t_start);
  }

  if((strlen(data->t_end) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "11 ");
    fprintf(fd, "End time:                  %s\n", data->t_end);
  }

  if((strlen(data->timezone) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "12 ");
    fprintf(fd, "Timezone:                  %s\n", data->timezone);
  }

  if((strlen(data->duration) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "13 ");
    fprintf(fd, "Duration:                  %s\n", data->duration);
  }

  if((strlen(data->protocol) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "14 ");
    fprintf(fd, "Protocol:                  %s\n", data->protocol);
  }

  if((strlen(data->sport) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "15 ");
    fprintf(fd, "Source port:               %s\n", data->sport);
  }

  if((strlen(data->dport) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "16 ");
    fprintf(fd, "Destination port:          %s\n", data->dport);
  }

  if((strlen(data->syn) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "17 ");
    fprintf(fd, "TCP options:               %s\n", data->syn);
  }

  if((strlen(data->tracking) > 0) || (options & OPT_MODIFY)) {
    if(options & OPT_MODIFY)
      fprintf(fd, "18 ");
    fprintf(fd, "Tracking number:           %s\n", data->tracking);
  }
}

void show_with_template(struct report_data *data)
{
  FILE *template;
  char buf[BUFSIZE];
  int retval;

  generate_header(stdout, data, OPT_NONE);

  template = fopen(opt.templatefile, "r");
  if (template == NULL) {
    fprintf(stderr, "fopen %s: %s\n", opt.templatefile, strerror(errno));
    exit(EXIT_FAILURE);
  }
  while (fgets(buf, BUFSIZE, template)) {
    if(strncmp(buf, INSERTREPORT, strlen(INSERTREPORT)) == 0) {
      generate_report(stdout, data, OPT_NONE);
    } else {
      fputs(buf, stdout);
    }
  }
  retval = fclose(template);
  if (retval == EOF) {
    perror("fclose");
  }
}

void unlink_tmp(char *file)
{
  if (unlink(file) == -1)
    perror("unlink");
}

void generate_with_template(struct report_data *data)
{
  FILE *fd, *template;
  char buf[BUFSIZE], *file, *tmpdir;
  int filedes, retval;

  tmpdir = getenv("TMPDIR");
  if (tmpdir == NULL) {
    file = xmalloc(strlen(FILENAME) + strlen("/tmp/") + 1);
    sprintf(file, "/tmp/%s", FILENAME);
  } else {
    file = xmalloc(strlen(FILENAME) + strlen(tmpdir) + 1);
    sprintf(file, "%s%s", tmpdir, FILENAME);
  }

  filedes = mkstemp(file);
  if(filedes == -1) {
    perror("mkstemp");
    exit(EXIT_FAILURE);
  }
  fd = fdopen(filedes, "w");
  if(fd == NULL) {
    perror("fdopen");
    unlink_tmp(file);
    exit(EXIT_FAILURE);
  }

  generate_header(fd, data, OPT_GENERATOR);

  template = fopen(opt.templatefile, "r");
  if (template == NULL) {
    fprintf(stderr, "fopen %s: %s\n", opt.templatefile, strerror(errno));
    unlink_tmp(file);
    exit(EXIT_FAILURE);
  }
  while (fgets(buf, BUFSIZE, template)) {
    if(strncmp(buf, INSERTREPORT, strlen(INSERTREPORT)) == 0) {
      generate_report(fd, data, OPT_NONE);
    } else {
      fputs(buf, fd);
    }
  }
  retval = fclose(template);
  if (retval == EOF) {
    perror("fclose");
  }

  retval = fclose(fd);
  if (retval == EOF) {
    perror("fclose");
  }

  printf("Sending...\n");

  snprintf(buf, BUFSIZE, "%s %s | %s -t", CAT, file, SENDMAIL);
  run_command(buf);

  unlink_tmp(file);
  free(file);
}

void fill_report(struct conn_data *this, struct report_data *data)
{
  time_t now;
  char stime[TIMESIZE], *proto, *serv;

  strncpy(data->sender, opt.sender, EMAILSIZE);

  strncpy(data->recipient, opt.recipient, EMAILSIZE);

  strncpy(data->cc, opt.cc, EMAILSIZE);

  strftime(stime, TIMESIZE, "%Y%m%d", gmtime(&this->start_time));
  snprintf(data->subject, EMAILSIZE, "Incident report %s-%s", stime, this->shost);

  if(opt.src_ip)
    strncpy(data->shost, this->shost, IPLEN);
  else
    data->shost[0] = '\0';

  if(opt.src_ip && opt.resolve)
    strncpy(data->shostname, resolve_hostname(this->shost), REPORTLEN);
  else
    data->shostname[0] = '\0';

  if(opt.dst_ip)
    strncpy(data->dhost, this->dhost, IPLEN);
  else
    data->dhost[0] = '\0';

  if(opt.dst_ip && opt.resolve)
    strncpy(data->dhostname, resolve_hostname(this->dhost), REPORTLEN);
  else
    data->dhostname[0] = '\0';

  snprintf(data->count, SHORTLEN, "%d", this->count);

  if(opt.times) {
    output_time(this->start_time, stime);
    strncpy(data->t_start, stime, TIMESIZE);

    output_time(this->end_time, stime);
    strncpy(data->t_end, stime, TIMESIZE);

    now = time(NULL);
    strftime(stime, SHORTLEN, "%Z", localtime(&now));
    strncpy(data->timezone, stime, SHORTLEN);
  } else {
    data->t_start[0] = '\0';
    data->t_end[0] = '\0';
    data->timezone[0] = '\0';
  }

  if(opt.duration) {
    output_timediff(this->start_time, this->end_time, stime);
    snprintf(data->duration, TIMESIZE, "%s (dd:hh:mm:ss)", stime);
  } else {
    data->duration[0] = '\0';
  }

  proto = resolve_protocol(this->protocol);

  if(opt.proto)
    strncpy(data->protocol, proto, SHORTLEN);
  else
    data->protocol[0] = '\0';

  if (opt.src_port) {
    serv = resolve_service(this->sport, proto);
    if (strncmp(serv, "-", 1) != 0) {
      snprintf(data->sport, SHORTLEN, "%d (%s)", this->sport, serv);
    } else {
      snprintf(data->sport, SHORTLEN, "%d", this->sport);
    }
  } else {
    data->sport[0] = '\0';
  }

  if (opt.dst_port) {
    serv = resolve_service(this->dport, proto);
    if (strncmp(serv, "-", 1) != 0) {
      snprintf(data->dport, SHORTLEN, "%d (%s)", this->dport, serv);
    } else {
      snprintf(data->dport, SHORTLEN, "%d", this->dport);
    }
  } else {
    data->dport[0] = '\0';
  }

  if (opt.opts) {
    if (this->syn == 0) {
      strncpy(data->syn, "ACKs only", SHORTLEN);
    } else {
      strncpy(data->syn, "SYNs only", SHORTLEN);
    }
  } else {
    data->syn[0] = '\0';
  }

  strftime(stime, TIMESIZE, "%Y%m%d", gmtime(&this->start_time));
  snprintf(data->tracking, REPORTLEN, "%s-%s", stime, this->shost);
}

void modify_report(struct report_data *data)
{
  char buf[BUFSIZE], *pnt;
  int num;

  while(1) {
    printf("\n----------------------------------------------------------------------\n");
    generate_header(stdout, data, OPT_MODIFY);
    generate_report(stdout, data, OPT_MODIFY);
    printf("----------------------------------------------------------------------\n");
    printf("\nWhat do you want to change? [1-18/(o)k] ");
    fgets(buf, BUFSIZE, stdin);
    if(buf[0] == 'o' || buf[0] == 'O') {
      break;
    }
    num = atoi(buf);
    if((num < 1) || (num > 18)) {
      continue;
    }
    printf("New value: ");
    fgets(buf, BUFSIZE, stdin);
    pnt = buf;
    while ((*pnt != '\n') && (*pnt != '\0')) pnt++;
    *pnt = '\0';
    switch(num) {
    case 1:
      strncpy(data->sender, buf, EMAILSIZE);
      break;
    case 2:
      strncpy(data->recipient, buf, EMAILSIZE);
      break;
    case 3:
      strncpy(data->cc, buf, EMAILSIZE);
      break;
    case 4:
      strncpy(data->subject, buf, EMAILSIZE);
      break;
    case 5:
      strncpy(data->shost, buf, REPORTLEN);
      break;
    case 6:
      strncpy(data->shostname, buf, REPORTLEN);
      break;
    case 7:
      strncpy(data->dhost, buf, REPORTLEN);
      break;
    case 8:
      strncpy(data->dhostname, buf, REPORTLEN);
      break;
    case 9:
      strncpy(data->count, buf, REPORTLEN);
      break;
    case 10:
      strncpy(data->t_start, buf, REPORTLEN);
      break;
    case 11:
      strncpy(data->t_end, buf, REPORTLEN);
      break;
    case 12:
      strncpy(data->timezone, buf, REPORTLEN);
      break;
    case 13:
      strncpy(data->duration, buf, REPORTLEN);
      break;
    case 14:
      strncpy(data->protocol, buf, REPORTLEN);
      break;
    case 15:
      strncpy(data->sport, buf, REPORTLEN);
      break;
    case 16:
      strncpy(data->dport, buf, REPORTLEN);
      break;
    case 17:
      strncpy(data->syn, buf, REPORTLEN);
      break;
    case 18:
      strncpy(data->tracking, buf, REPORTLEN);
      break;
    }
  }
}

void report()
{
  struct conn_data *this;
  struct report_data *data;
  unsigned char smq;

  printf("\n");

  data = xmalloc(sizeof(struct report_data));

  this = first;
  while (this != NULL) {
    if (this->count >= opt.threshold) {
      fill_report(this, data);
      while(1) {
	printf("----------------------------------------------------------------------\n");
	show_with_template(data);
	printf("----------------------------------------------------------------------\n");
	printf("\nShould this report be sent? [(s)end/(m)odify/(q)uit] ");
	smq = getchar();
	while(getchar() != '\n');
	if(smq == 's' || smq == 'S') {
	  generate_with_template(data);
	  break;
	}
	if(smq == 'm' || smq == 'M') {
	  modify_report(data);
	}
	if(smq == 'q' || smq == 'Q') {
	  break;
	}
	printf("\n");
      }
    }
    this = this->next;
  }

  free(data);
}