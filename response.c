/* $Id: response.c,v 1.9 2002/02/14 20:54:34 bwess Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "response.h"
#include "output.h"
#include "utils.h"

extern struct options opt;
extern struct conn_data *first;
struct known_hosts *first_host = NULL;

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
    syslog(LOG_NOTICE, "%u logging firewall rule%s defined", found, (found == 1)?"":"s");
  } else {
    syslog(LOG_NOTICE, "No logging firewall rules defined, exiting");
    exit(EXIT_FAILURE);
  }
}

void show_mode_opts(char *buf)
{
  if (opt.response & OPT_NOTIFY_EMAIL) {
    if (strstr(opt.recipient, "%")) {
      strncpy(opt.recipient, "[invalid]", EMAILSIZE);
      syslog (LOG_NOTICE, "Warning, format character in email string");
    }
  }
  if (opt.response & OPT_NOTIFY_SMB) {
    if (strstr(opt.smb_host, "%")) {
      strncpy(opt.smb_host, "[invalid]", SHOSTLEN);
      syslog (LOG_NOTICE, "Warning, format character in smb string");
    }
  }
  if (opt.response & OPT_CUSTOM_ACTION) {
    if (strstr(opt.action, "%")) {
      strncpy(opt.action, "[invalid]", ACTIONSIZE);
      syslog (LOG_NOTICE, "Warning, format character in action string");
    }
  }
  snprintf(buf, BUFSIZE, "log%s%s%s%s%s%s%s%s",
	   (opt.response & OPT_BLOCK)?", block host":"",
	   (opt.response & OPT_NOTIFY_EMAIL)?", email notification to ":"",
	   (opt.response & OPT_NOTIFY_EMAIL)?opt.recipient:"",
	   (opt.response & OPT_NOTIFY_SMB)?", winpopup notification on host ":"",
	   (opt.response & OPT_NOTIFY_SMB)?opt.smb_host:"",
	   (opt.response & OPT_CUSTOM_ACTION)?", custom action '":"",
	   (opt.response & OPT_CUSTOM_ACTION)?opt.action:"",
	   (opt.response & OPT_CUSTOM_ACTION)?"'":"");
}

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
      syslog(LOG_NOTICE, "Adding %s chain", CHAINLABEL);

      snprintf(buf, BUFSIZE, "%s -N %s", P_IPCHAINS, CHAINLABEL);
      run_command(buf);

      snprintf(buf, BUFSIZE, "%s -I input -j %s", P_IPCHAINS, CHAINLABEL);
      run_command(buf);
    }
  }
  if (action == REMOVE_CHAIN) {
    if(found_label) {
      syslog(LOG_NOTICE, "Removing %s chain", CHAINLABEL);

      snprintf(buf, BUFSIZE, "%s -D input -j %s", P_IPCHAINS, CHAINLABEL);
      run_command(buf);

      snprintf(buf, BUFSIZE, "%s -F %s", P_IPCHAINS, CHAINLABEL);
      run_command(buf);

      snprintf(buf, BUFSIZE, "%s -X %s", P_IPCHAINS, CHAINLABEL);
      run_command(buf);
    }
  }
}

void add_rule(char *ip)
{
  char buf[BUFSIZE];

  syslog(LOG_NOTICE, "Adding block for %s", ip);

  snprintf(buf, BUFSIZE, "%s -A %s -s %s -j DENY", P_IPCHAINS, CHAINLABEL, ip);
  run_command(buf);
}

void remove_rule(char *ip)
{
  char buf[BUFSIZE];

  syslog(LOG_NOTICE, "Removing block for %s", ip);

  snprintf(buf, BUFSIZE, "%s -D %s -s %s -j DENY", P_IPCHAINS, CHAINLABEL, ip);
  run_command(buf);
}

void remove_old()
{
  struct conn_data *prev, *this;
  struct known_hosts *prev_host, *this_host;
  time_t now, diff;
  unsigned char is_first;

  now = time(NULL);

  prev = this = first;
  is_first = 1;
  while (this != NULL) {
    if (this->end_time != 0)
      diff = now - this->end_time;
    else
      diff = now - this->start_time;
    if (diff >= opt.recent) {
      if(opt.verbose == 2)
	syslog(LOG_NOTICE, "Deleting connection cache entry (%s)", this->shost);
      if (is_first == 1) {
	prev = this->next;
	free(this);
	first = this = prev;
      } else {
	this = this->next;
	free(prev->next);
	prev->next = this;
      }
    } else {
      prev = this;
      this = this->next;
      is_first = 0;
    }
  }

  prev_host = this_host = first_host;
  is_first = 1;
  while (this_host != NULL) {
    if ((this_host->time != 0) && ((now - this_host->time) >= opt.recent)) {
      if (opt.verbose == 2)
	syslog(LOG_NOTICE, "Deleting host status entry (%s)", this_host->shost);
      if (opt.response & OPT_BLOCK)
	remove_rule(inet_ntoa(this_host->shost));
      if (is_first == 1) {
	prev_host = this_host->next;
	free(this_host);
	first_host = this_host = prev_host;
      } else {
	this_host = this_host->next;
	free(prev_host->next);
	prev_host->next = this_host;
      }
    } else {
      prev_host = this_host;
      this_host = this_host->next;
      is_first = 0;
    }
  }
}

unsigned char is_known(struct in_addr shost)
{
  struct known_hosts *this_host;

  this_host = first_host;
  while (this_host != NULL) {
    if (this_host->shost.s_addr == shost.s_addr) {
      return 1;
    }
    this_host = this_host->next;
  }
  return 0;
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
      host->shost.s_addr = this->shost.s_addr;
      host->next = first_host;
      first_host = host;

      if(opt.response & OPT_BLOCK) {
	add_rule(inet_ntoa(this->shost));
      }
      if(opt.response & OPT_NOTIFY_EMAIL) {
	snprintf(buf, BUFSIZE,
		 "%s | %s -s 'fwlogwatch alert: %d connection attempt%s from %s' %s",
		 P_ECHO, P_MAIL,
		 this->count, (this->count == 1)?"":"s",
		 inet_ntoa(this->shost), opt.recipient);
	run_command(buf);
      }
      if(opt.response & OPT_NOTIFY_SMB) {
	snprintf(buf, BUFSIZE,
		 "%s 'fwlogwatch alert: %d connection attempts from %s' | %s -M %s",
		 P_ECHO,
		 this->count, inet_ntoa(this->shost),
		 P_SMBCLIENT, opt.smb_host);
	run_command(buf);
      }
      if(opt.response & OPT_CUSTOM_ACTION) {
	run_command(opt.action);
      }
      this->end_time = 1;
      remove_old();
    }
    this = this->next;
  }
}
