/* $Id: main.h,v 1.2 2002/02/14 20:09:16 bwess Exp $ */

#ifndef _MAIN_H
#define _MAIN_H

#define PACKAGE "fwlogwatch"
#define VERSION "0.0.22"
#define COPYRIGHT "2000-10-22 Boris Wesslowski, RUS-CERT"

/* Data sizes */

#define BUFSIZE 1024
#define FILESIZE 256
#define TIMESIZE 32
#define HOSTLEN 256
#define SHOSTLEN 32
#define IPLEN 16
#define EMAILSIZE 80
#define ACTIONSIZE 128
#define SHORTLEN 10
#define REPORTLEN 52

/* Files */

#define INFILE "/var/log/messages"
#define RCFILE "/etc/fwlogwatch.config"

/* Modes */

enum {
  LOG_SUMMARY,
  INTERACTIVE_REPORT,
  REALTIME_RESPONSE,
  SHOW_LOG_TIMES
};

/* Sorting */

enum {
  SMALLERFIRST,
  BIGGERFIRST
};

enum {
  COUNT,
  SOURCEHOST,
  DESTHOST,
  SOURCEPORT,
  DESTPORT,
  START_TIME,
  DELTA_TIME
};

/* Log summary mode */

#define TEXTCOLOR "FFFFFF"
#define BGCOLOR "000000"
#define ROWCOLOR1 "555555"
#define ROWCOLOR2 "333333"

enum {
  NOSPACE,
  SPACE
};

/* Interactive report mode */

#define CERT "[Insert address of abuse contact or CERT here]"
#define TEMPLATE "/etc/fwlogwatch.template"
#define FILENAME "fwlogwatchXXXXXX"
#define INSERTREPORT "# insert report here"
#define CAT "/bin/cat"
#define SENDMAIL "/usr/sbin/sendmail"

enum {
  OPT_NONE,
  OPT_GENERATOR,
  OPT_MODIFY
};

/* Realtime response mode */

#define ALERT 5
#define FORGET 86400
#define IPCHAINS "/sbin/ipchains"
#define CHAINLABEL "flwblock"
#define SMBCLIENT "/usr/bin/smbclient"

enum {
  BLOCK,
  NOTIFY_SMB,
  CUSTOM_ACTION
};

enum {
  ADD_CHAIN,
  REMOVE_CHAIN
};

/* Data structures */

struct log_line {
  time_t time;
  char hostname[SHOSTLEN];
  char chainlabel[SHORTLEN];
  char branchname[SHORTLEN];
  char interface[SHORTLEN];
  int protocol;
  char shost[IPLEN];
  int sport;
  char dhost[IPLEN];
  int dport;
  unsigned char syn;
};

struct conn_data {
  int count;
  time_t start_time;
  time_t end_time;
  char hostname[SHOSTLEN];
  char chainlabel[SHORTLEN];
  char branchname[SHORTLEN];
  char interface[SHORTLEN];
  int protocol;
  char shost[IPLEN];
  int sport;
  char dhost[IPLEN];
  int dport;
  unsigned char syn;
  struct conn_data *next;
};

struct dns_cache {
  char ip[IPLEN];
  char fqdn[HOSTLEN];
  struct dns_cache *next;
};

struct report_data {
  char sender[EMAILSIZE];
  char recipient[EMAILSIZE];
  char cc[EMAILSIZE];
  char subject[EMAILSIZE];
  char shost[REPORTLEN];
  char shostname[REPORTLEN];
  char dhost[REPORTLEN];
  char dhostname[REPORTLEN];
  char count[REPORTLEN];
  char t_start[REPORTLEN];
  char t_end[REPORTLEN];
  char timezone[REPORTLEN];
  char duration[REPORTLEN];
  char protocol[REPORTLEN];
  char sport[REPORTLEN];
  char dport[REPORTLEN];
  char syn[REPORTLEN];
  char tracking[REPORTLEN];
};

struct known_hosts {
  time_t time;
  char shost[IPLEN];
  struct known_hosts *next;
};

struct options {
  unsigned char mode;

  unsigned char verbose;
  unsigned char resolve;
  char inputfile[FILESIZE];

  unsigned char src_ip;
  unsigned char dst_ip;
  unsigned char proto;
  unsigned char src_port;
  unsigned char dst_port;
  unsigned char opts;

  unsigned char times;
  unsigned char duration;
  unsigned char html;
  unsigned char use_out;
  char outputfile[FILESIZE];

  unsigned char loghost;
  char hostname[SHOSTLEN];

  unsigned char chains;
  char chainlabel[SHOSTLEN];

  unsigned char branches;
  char branchname[SHORTLEN];

  unsigned char ifs;
  char interface[SHORTLEN];

  time_t now;
  int recent;

  int threshold;
  char sender[EMAILSIZE];
  char recipient[EMAILSIZE];
  char cc[EMAILSIZE];
  char templatefile[FILESIZE];

  unsigned char response;
  char action[ACTIONSIZE];
};

#endif
