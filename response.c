/* $Id: response.c,v 1.1 2002/02/14 19:43:03 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include "response.h"
#include "output.h"
#include "utils.h"

extern struct conn_data *first;
extern struct options opt;
struct known_hosts *first_host = NULL;

void modify_firewall(unsigned char action)
{
  char buf[BUFSIZE];
  unsigned char found_label = 0;
  FILE *fd;
  int retval;

  fd = fopen("/proc/net/ip_fwnames", "r");
  if (fd == NULL) {
    syslog(LOG_NOTICE, "fopen /proc/net/ip_fwnames: %s", strerror(errno));
    log_exit();
  }

  while (fgets(buf, BUFSIZE, fd)) {
    if(strncmp(buf, CHAINLABEL, strlen(CHAINLABEL)) == 0) {
      found_label = 1;
    }
  }

  retval = fclose(fd);
  if (retval == EOF) {
    syslog(LOG_NOTICE, "fclose /proc/net/ip_fwnames: %s", strerror(errno));
  }

  if (action == ADD_CHAIN) {
    if(!found_label) {
      syslog(LOG_NOTICE, "Adding %s chain.", CHAINLABEL);

      snprintf(buf, BUFSIZE, "%s -N %s", IPCHAINS, CHAINLABEL);
      run_command(buf);

      snprintf(buf, BUFSIZE, "%s -I input -j %s", IPCHAINS, CHAINLABEL);
      run_command(buf);
    }
  }
  if (action == REMOVE_CHAIN) {
    if(found_label) {
      syslog(LOG_NOTICE, "Removing %s chain.", CHAINLABEL);

      snprintf(buf, BUFSIZE, "%s -D input -j %s", IPCHAINS, CHAINLABEL);
      run_command(buf);

      snprintf(buf, BUFSIZE, "%s -F %s", IPCHAINS, CHAINLABEL);
      run_command(buf);

      snprintf(buf, BUFSIZE, "%s -X %s", IPCHAINS, CHAINLABEL);
      run_command(buf);
    }
  }
}

void add_rule(char *ip)
{
  char buf[BUFSIZE];

  syslog(LOG_NOTICE, "Adding block for %s.", ip);

  snprintf(buf, BUFSIZE, "%s -A %s -s %s -j DENY", IPCHAINS, CHAINLABEL, ip);
  run_command(buf);
}

void remove_rule(char *ip)
{
  char buf[BUFSIZE];

  syslog(LOG_NOTICE, "Removing block for %s.", ip);

  snprintf(buf, BUFSIZE, "%s -D %s -s %s -j DENY", IPCHAINS, CHAINLABEL, ip);
  run_command(buf);
}

unsigned char is_known(char *shost)
{
  struct known_hosts *this_host;

  this_host = first_host;
  while (this_host != NULL) {
    if (strncmp(this_host->shost, shost, IPLEN) != 0) {
      return 1;
    }
    this_host = this_host->next;
  }
  return 0;
}

void remove_old()
{
  struct conn_data *this, *temp;
  struct known_hosts *this_host, *temp_host;
  time_t now, diff;

  now = time(NULL);
  this = first;
  while (this != NULL) {
    if (this->next != NULL) {
      if (this->next->end_time != 0) {
	diff = now - this->next->end_time;
      } else {
	diff = now - this->next->start_time;
      }
      if (diff > opt.recent) {
	syslog(LOG_NOTICE, "Deleting old entry (timediff: %d).", (int)diff);
	temp = this->next;
	this->next = this->next->next;
	free(temp);
	continue;
      }
    } else {
      if (this->end_time != 0) {
	diff = now - this->end_time;
      } else {
	diff = now - this->start_time;
      }
      if (diff > opt.recent) {
	syslog(LOG_NOTICE, "Deleting last entry (timediff: %d).", (int)diff);
	first = NULL;
	free(this);
	break;
      }
    }
    this = this->next;
  }

  this_host = first_host;
  while (this_host != NULL) {
    if (this_host->next != NULL) {
      if (this_host->next->time == 0) {
	this_host = this_host->next;
	continue;
      }
      diff = now - this_host->next->time;
      if (diff > opt.recent) {
	if(opt.response == BLOCK)
	  remove_rule(this_host->shost);
	syslog(LOG_NOTICE, "Deleting old hosts entry (timediff: %d).", (int)diff);
	temp_host = this_host->next;
	this_host->next = this_host->next->next;
	free(temp_host);
	continue;
      }
    } else {
      if (this_host->time == 0) {
	this_host = this_host->next;
	continue;
      }
      diff = now - this_host->time;
      if (diff > opt.recent) {
	if(opt.response == BLOCK)
	  remove_rule(this_host->shost);
	syslog(LOG_NOTICE, "Deleting last hosts entry (timediff: %d).", (int)diff);
	first_host = NULL;
	free(this_host);
	break;
      }
    }
    this = this->next;
  }
}

void look_for_log_rules()
{
  char buf[BUFSIZE];
  unsigned int found = 0;
  FILE *fd;
  int retval;

  char chain[10], src_dst[36], interface[16];
  unsigned int fw_flg, fw_invflg, protocol;
  char rest[80];

  fd = fopen("/proc/net/ip_fwchains", "r");
  if (fd == NULL) {
    syslog(LOG_NOTICE, "fopen /proc/net/ip_fwchains: %s", strerror(errno));
    log_exit();
  }

  while (fgets(buf, BUFSIZE, fd)) {
    retval = sscanf(buf, "%10s %36s %16s %6X %6X %5u %80s\n",
		    chain, src_dst, interface,
		    &fw_flg,
		    &fw_invflg, &protocol, rest);
    if (retval == 7) {
      if(fw_flg & IP_FW_F_PRN) {
	found++;
      }
    }
  }

  retval = fclose(fd);
  if (retval == EOF) {
    syslog(LOG_NOTICE, "fclose /proc/net/ip_fwchains: %s", strerror(errno));
  }

  if (found > 0) {
    syslog(LOG_NOTICE, "%u logging firewall rule%s defined.", found, (found == 1)?"":"s");
  } else {
    syslog(LOG_NOTICE, "No logging firewall rules defined, exiting.");
    exit(EXIT_FAILURE);
  }
}

void look_for_alert()
{
  struct conn_data *this;
  struct known_hosts *host;
  char buf[BUFSIZE];

  this = first;
  while (this != NULL) {
    if ((this->count >= opt.threshold) && (!is_known(this->shost))) {
      syslog(LOG_NOTICE, "ALERT: %d attempts from %s", this->count, this->shost);

      host = xmalloc(sizeof(struct known_hosts));

      host->time = time(NULL);
      strncpy(host->shost, this->shost, IPLEN);
      host->next = first_host;
      first_host = host;

      switch(opt.response) {
      case BLOCK:
	add_rule(this->shost);
	break;
      case NOTIFY_SMB:
	snprintf(buf, BUFSIZE, "%s -N -M %s 'Alert: %d connection attempts from %s'", SMBCLIENT, opt.action, this->count, this->shost);
	run_command(buf);
	break;
      case CUSTOM_ACTION:
	run_command(opt.action);
	break;
      }
    }
    this = this->next;
  }
}
