/* $Id: main.h,v 1.14 2002/02/14 21:15:35 bwess Exp $ */

#ifndef _MAIN_H
#define _MAIN_H

#define PACKAGE "fwlogwatch"
#define VERSION "0.2.1"
#define COPYRIGHT "2001-03-09 Boris Wesslowski, RUS-CERT"

/* Data sizes */

#define BUFSIZE 1024
#define FILESIZE 256
#define TIMESIZE 32
#define HOSTLEN 256
#define SHOSTLEN 32
#define IPLEN 16
#define EMAILSIZE 80
#define ACTIONSIZE 128
#define REPORTLEN 52
#define COLORSIZE 7
#define MAXSORTSIZE 16
#define USERSIZE 16
#define PASSWORDSIZE 76

#ifndef LONG_NAMES
#define SHORTLEN 10
#else
#define SHORTLEN 30
#endif

/* Files */

#define INFILE "/var/log/messages"
#define RCFILE "/etc/fwlogwatch.config"
#define PIDFILE "/var/run/fwlogwatch.pid"

/* Modes */

enum {
  LOG_SUMMARY,
  INTERACTIVE_REPORT,
  REALTIME_RESPONSE,
  SHOW_LOG_TIMES
};

/* Parser */

#define PARSER_IPCHAINS 1
#define PARSER_NETFILTER 2
#define PARSER_CISCO 4
#define PARSER_IPFILTER 8

enum {
  PARSE_OK,
  PARSE_ERROR,
  PARSE_NO_HIT,
  PARSE_WRONG_FORMAT,
  PARSE_TOO_OLD,
  PARSE_EXCLUDED
};

enum {
  IN_ADDR_OK,
  IN_ADDR_ERROR
};

/* TCP flags */

#define TCP_SYN 1
#define TCP_ACK 2
#define TCP_FIN 4
#define TCP_RST 8
#define TCP_PSH 16
#define TCP_URG 32

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
  C_OPT_MSEC,
  C_OPT_PORT,
  C_OPT_MISSING,
  C_OPT_TYPE
};

/* ipfilter support */

#define IPF_DATE 1
#define IPF_DATA 2
#define IPF_PROTO 4
#define IPF_IPS 8
#define IPF_NO_HIT 128

enum {
  IPF_OPT_NONE,
  IPF_OPT_COUNT,
  IPF_OPT_PORTS
};

/* Sorting */

enum {
  SORT_COUNT,
  SORT_START_TIME,
  SORT_DELTA_TIME,
  SORT_CHAINLABEL,
  SORT_PROTOCOL,
  SORT_DATALEN,
  SORT_SOURCEHOST,
  SORT_SOURCEPORT,
  SORT_DESTHOST,
  SORT_DESTPORT
};

enum {
  ORDER_ASCENDING,
  ORDER_DESCENDING
};

/* Log summary mode */

#define TEXTCOLOR "FFFFFF"
#define BGCOLOR "000000"
#define ROWCOLOR1 "555555"
#define ROWCOLOR2 "333333"

#define SORTORDER "cd"

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

#define KNOWN_HOST 0

#define OPT_LOG 1
#define OPT_BLOCK 2
#define OPT_NOTIFY_EMAIL 4
#define OPT_NOTIFY_SMB 8
#define OPT_CUSTOM_ACTION 16

enum {
  ADD_CHAIN,
  REMOVE_CHAIN
};

/* Data structures */

#include <time.h>
#include <netinet/in.h>

struct log_line {
  time_t time;
  char hostname[SHOSTLEN];
  char chainlabel[SHORTLEN];
  char branchname[SHORTLEN];
  char interface[SHORTLEN];
  int protocol;
  int datalen;
  struct in_addr shost;
  int sport;
  struct in_addr dhost;
  int dport;
  unsigned char flags;
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
  int datalen;
  struct in_addr shost;
  int sport;
  struct in_addr dhost;
  int dport;
  unsigned char flags;
  struct conn_data *next;
};

struct dns_cache {
  struct in_addr ip;
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
  struct in_addr shost;
  struct in_addr netmask;
  struct known_hosts *next;
};

struct parser_options {
  unsigned char mode;
  unsigned long int value;
  struct parser_options *next;
};

#define PARSER_MODE_NOT 1
#define PARSER_MODE_HOST 2 /* host or port */
#define PARSER_MODE_SRC 4 /* source or destination */

enum {
  P_MATCH_NONE,
  P_MATCH_EXC,
  P_MATCH_INC
};

struct options {
  unsigned char mode;

  unsigned char verbose;
  unsigned char resolve;
  char inputfile[FILESIZE];

  struct log_line *line;
  char format_sel[SHORTLEN];
  unsigned char format;
  unsigned char parser;

  unsigned char src_ip;
  unsigned char dst_ip;
  unsigned char proto;
  unsigned char src_port;
  unsigned char dst_port;
  unsigned char opts;

  unsigned char datalen;
  unsigned char times;
  unsigned char duration;

  char sort_order[MAXSORTSIZE];
  unsigned char sortfield;
  unsigned char sortmode;

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
