/* $Id: main.h,v 1.8 2002/02/14 20:48:49 bwess Exp $ */

#ifndef _MAIN_H
#define _MAIN_H

#define PACKAGE "fwlogwatch"
#define VERSION "0.0.28"
#define COPYRIGHT "2000-12-26 Boris Wesslowski, RUS-CERT"

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
#define COLORSIZE 7
#define MAXSORTSIZE 16
#define USERSIZE 16
#define PASSWORDSIZE 76

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

/* Parser */

enum {
  PARSE_OK,
  PARSE_ERROR,
  PARSE_NO_HIT,
  PARSE_WRONG_FORMAT,
  PARSE_TOO_OLD
};

/* ipchains support */

#define IPCHAINS_DATE 1
#define IPCHAINS_DATA 2
#define IPCHAINS_IPS 4

/* netfilter support */

#define NF_DATE 1
#define NF_IN 2
#define NF_SRC 4
#define NF_DST 8
#define NF_PROTO 16
#define NF_SPT 32
#define NF_DPT 64
#define NF_TYPE 128

/* cisco support */

#define CISCO_DATE 1
#define CISCO_SRC 2
#define CISCO_DST 4
#define CISCO_PROTO 8
#define CISCO_COUNT 16

enum {
  C_OPT_NONE,
  C_OPT_HOST,
  C_OPT_PORT,
  C_OPT_TYPE
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

#define SORTORDER "tacd"

enum {
  NOSPACE,
  SPACE
};

/* Interactive report mode */

#define CERT "[Insert address of abuse contact or CERT here]"
#define TEMPLATE "/etc/fwlogwatch.template"
#define FILENAME "fwlogwatchXXXXXX"
#define INSERTREPORT "# insert report here"
#define P_CAT "/bin/cat"
#define P_SENDMAIL "/usr/sbin/sendmail"

enum {
  OPT_NONE,
  OPT_GENERATOR,
  OPT_MODIFY
};

/* Realtime response mode */

#define ALERT 5
#define FORGET 86400
#define P_IPCHAINS "/sbin/ipchains"
#define CHAINLABEL "flwblock"
#define P_ECHO "/bin/echo"
#define P_MAIL "/bin/mail"
#define P_SMBCLIENT "/usr/bin/smbclient"
#define LISTENHOST "127.0.0.1"
#define LISTENPORT 888
#define DEFAULT_USER "admin"
#define DEFAULT_PASSWORD "2fi4nEVVz0IXo" /* fwlogwat[ch]
					    DES only supports 8 characters */

#define OPT_LOG 0x01
#define OPT_BLOCK 0x02
#define OPT_NOTIFY_EMAIL 0x04
#define OPT_NOTIFY_SMB 0x08
#define OPT_CUSTOM_ACTION 0x10

enum {
  ADD_CHAIN,
  REMOVE_CHAIN
};

/* Data structures */

#include <time.h>

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
  int count;
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

  struct log_line *line;
  unsigned char parser;

  unsigned char src_ip;
  unsigned char dst_ip;
  unsigned char proto;
  unsigned char src_port;
  unsigned char dst_port;
  unsigned char opts;

  unsigned char times;
  unsigned char duration;

  char sort_order[MAXSORTSIZE];

  unsigned char html;
  unsigned char use_out;
  char outputfile[FILESIZE];
  char textcol[COLORSIZE];
  char bgcol[COLORSIZE];
  char rowcol1[COLORSIZE];
  char rowcol2[COLORSIZE];

  unsigned char loghost;
  char hostname[SHOSTLEN];

  unsigned char chains;
  char chainlabel[SHORTLEN];

  unsigned char branches;
  char branchname[SHORTLEN];

  unsigned char ifs;
  char interface[SHORTLEN];

  time_t now;
  int recent;

  int threshold;
  int least;
  char sender[EMAILSIZE];
  char recipient[EMAILSIZE];
  char cc[EMAILSIZE];
  char templatefile[FILESIZE];

  unsigned char response;
  char action[ACTIONSIZE];
  char smb_host[SHOSTLEN];
  unsigned char status;
  char listenhost[IPLEN];
  int listenport;
  char user[USERSIZE];
  char password[PASSWORDSIZE];
};

#endif
