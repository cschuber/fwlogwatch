/* Copyright (C) 2000-2004 Boris Wesslowski */
/* $Id: main.h,v 1.29 2004/04/25 18:56:21 bwess Exp $ */

#ifndef _MAIN_H
#define _MAIN_H

#define PACKAGE "fwlogwatch"
#define VERSION "1.0 2004/04/25"
#define COPYRIGHT "Boris Wesslowski"

/* Paths */

#define INSTALL_DIR "/usr/local"
#define CONF_DIR "/etc"
#define LOCALE_DIR "/usr"

/* i18n */

#ifdef HAVE_GETTEXT
#include <libintl.h>
#define _(String) gettext(String)
#define LOCALEDIR LOCALE_DIR "/share/locale"
#else
#define _(String) String
#endif

/* Data sizes */

#define BUFSIZE 1024
#define BUFSIZE_S "1024"
#define FILESIZE 256
#define TIMESIZE 40
#define HOSTLEN 256
#define SHOSTLEN 32
#define SHOSTLEN_S "32"
#define IPLEN 16
#define IP6LEN 40
#define EMAILSIZE 80
#define REPORTLEN 52
#define COLORSIZE 8
#define MAXSORTSIZE 24
#define USERSIZE 16
#define PASSWORDSIZE 76
#define WHOISCMDLEN 32
#define WHOISDESCLEN 64
#define WHOISROUTELEN 20
#define TITLESIZE 64
#define CSSSIZE 64

#ifndef SHORT_NAMES
#define SHORTLEN 128
#define SHORTLEN_S "128"
#else
#define SHORTLEN 10
#define SHORTLEN_S "10"
#endif

/* Files */

#define INFILE "/var/log/messages"
#define RCFILE CONF_DIR "/fwlogwatch.config"

enum {
  MAY_NOT_EXIST,
  MUST_EXIST
};

enum {
  NO,
  YES
};

enum {
  IGNORE_HASH,
  COMMENT_HASH
};

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
#define PARSER_CISCO_IOS 4
#define PARSER_IPFILTER 8
#define PARSER_CISCO_PIX 16
#define PARSER_WIN_XP 32
#define PARSER_SNORT 64
#define PARSER_NETSCREEN 128
#define PARSER_LANCOM 256
#define PARSER_IPFW 512

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

enum {
  NF_OPT_NOPREFIX,
  NF_OPT_PREFIX,
  NF_OPT_SRC,
  NF_OPT_DST
};

/* cisco ios support */

#define CISCO_IOS_DATE 1
#define CISCO_IOS_SRC 2
#define CISCO_IOS_DST 4
#define CISCO_IOS_PROTO 8
#define CISCO_IOS_COUNT 16

enum {
  CI_OPT_NONE,
  CI_OPT_HOST,
  CI_OPT_MSEC,
  CI_OPT_PORT,
  CI_OPT_MISSING,
  CI_OPT_TYPE
};

/* cisco pix support */

#define CISCO_PIX_DATE 1
#define CISCO_PIX_SRC 2
#define CISCO_PIX_DST 4

enum {
  CP_OPT_NONE,
  CP_OPT_HOST,
  CP_OPT_TCP,
  CP_OPT_TCP_S,
  CP_OPT_UDP,
  CP_OPT_UDP_S,
  CP_OPT_ICMP,
  CP_OPT_DST,
  CP_OPT_DST_S
};

/* ipfilter support */

#define IPF_DATE 1
#define IPF_DATA 2
#define IPF_PROTO 4
#define IPF_SRC_IP 8
#define IPF_DST_IP 16
#define IPF_SRC_PORT 32
#define IPF_DST_PORT 64
#define IPF_NO_HIT 128

#define IPF_OPT_NONE 1
#define IPF_OPT_COUNT 2
#define IPF_OPT_SRC 4
#define IPF_OPT_DST 8
#define IPF_OPT_RES 16
#define IPF_OPT_PORT 32
#define IPF_OPT_RPORT 64

/* ipfw support */

#define IPFW_DATE 1
#define IPFW_CHAIN 2
#define IPFW_BRANCH 4
#define IPFW_PROTO 8
#define IPFW_IPS 16
#define IPFW_PORTS 32
#define IPFW_IF 64

enum {
  IPFW_OPT_NONE,
  IPFW_OPT_ICMP,
  IPFW_OPT_PORTS
};

/* snort support */

#define SNORT_DATE 1
#define SNORT_CHAIN 2
#define SNORT_BRANCH 4
#define SNORT_PROTO 8
#define SNORT_SRC 16
#define SNORT_DST 32
#define SNORT_NO_HIT 64

#define SNORT_OPT_SRC 1
#define SNORT_OPT_DST 2
#define SNORT_OPT_PORT 4

/* netscreen support */

#define NS_DATE 1
#define NS_SRC 2
#define NS_DST 4
#define NS_SPORT 8
#define NS_DPORT 16
#define NS_BN 32
#define NS_PROTO 64

enum {
  NETSCREEN_OPT_SRC,
  NETSCREEN_OPT_DST
};

/* Sorting */

enum {
  SORT_COUNT,
  SORT_START_TIME,
  SORT_END_TIME,
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

/* WHOIS lookup */

#define RADB "whois.radb.net"
#define WHOIS 43

/* HTML output */

#define TEXTCOLOR "black"
#define BGCOLOR "white"
#define ROWCOLOR1 "#EEEEEE"
#define ROWCOLOR2 "#DDDDDD"

/* Log summary mode */

#define SUMMARY_TITLE _("fwlogwatch summary")
#define SORTORDER "cd"

/* Interactive report mode */

#define CERT "[Insert address of abuse contact or CERT here]"
#define TEMPLATE CONF_DIR "/fwlogwatch.template"
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
#define FWLW_NOTIFY INSTALL_DIR "/sbin/fwlw_notify"
#define FWLW_RESPOND INSTALL_DIR "/sbin/fwlw_respond"
#define STATUS_TITLE _("fwlogwatch status")
#ifndef HAVE_IPV6
#define LISTENIF "127.0.0.1"
#else
#define LISTENIF "::1"
#endif
#define LISTENPORT 888
#define DEFAULT_USER "admin"
#define DEFAULT_PASSWORD "2fi4nEVVz0IXo" /* fwlogwat[ch]
					    DES only supports 8 characters */

#define OPT_LOG 1
#define OPT_NOTIFY 2
#define OPT_RESPOND 4

#define EX_NOTIFY 1
#define EX_RESPOND_ADD 2
#define EX_RESPOND_REMOVE 3

#define RESP_REMOVE_OPC 1
#define RESP_REMOVE_OHS 2

enum {
  FW_START,
  FW_STOP
};

enum {
  NO_NET_OPTS_PC,
  NET_OPTS_PC,
  NO_SORTING,
  SORTING
};

enum {
  STATUS_OFF,
  STATUS_OK,
  FD_ERROR
};

enum {
  HEADER_COMPLETE,
  HEADER_CONTINUES
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
  char *hostname;
  char *chainlabel;
  char *branchname;
  char *interface;
  int protocol;
  int datalen;
  struct in_addr shost;
  int sport;
  struct in_addr dhost;
  int dport;
  unsigned char flags;
  int id;
  struct conn_data *next;
};

struct input_file {
  char *name;
  struct input_file *next;
};

struct dns_cache {
  struct in_addr ip;
  char *fqdn;
  struct dns_cache *next;
};

struct whois_entry {
  char *ip_route;
  int as_number;
  char *ip_descr;
  char *as_descr;
  struct whois_entry *next;
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
  int count;
  struct in_addr shost;
  struct in_addr netmask;
  struct in_addr dhost;
  int protocol;
  int sport;
  int dport;
  int id;
  struct known_hosts *next;
};

struct parser_options {
  unsigned char mode;
  unsigned long int value;
  struct in_addr netmask;
  char *svalue;
  struct parser_options *next;
};

#define PARSER_MODE_DEFAULT 0
#define PARSER_MODE_NOT 1
#define PARSER_MODE_HOST 2
#define PARSER_MODE_PORT 4
#define PARSER_MODE_SRC 8
#define PARSER_MODE_CHAIN 16
#define PARSER_MODE_BRANCH 32

enum {
  P_MATCH_NONE,
  P_MATCH_EXC,
  P_MATCH_INC
};

struct options {
  unsigned char mode;
  FILE *inputfd;
  unsigned char std_in;

  unsigned char verbose;
  unsigned char resolve;
  unsigned char sresolve;
  unsigned char whois_lookup;
  int whois_sock;
  int filecount;
  char rcfile[FILESIZE];

  struct log_line *line;
  char format_sel[SHORTLEN];
  unsigned int format;
  unsigned char parser;
  unsigned char repeated;
  int orig_count;

  unsigned char src_ip;
  unsigned char dst_ip;
  unsigned char proto;
  unsigned char src_port;
  unsigned char dst_port;
  unsigned char opts;

  unsigned char datalen;
  unsigned char stimes;
  unsigned char etimes;
  unsigned char duration;

  char sort_order[MAXSORTSIZE];
  unsigned char sortfield;
  unsigned char sortmode;

  unsigned char html;
  unsigned char use_out;
  char outputfile[FILESIZE];

  char title[TITLESIZE];
  char stylesheet[CSSSIZE];
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
  int max;
  char sender[EMAILSIZE];
  char recipient[EMAILSIZE];
  char cc[EMAILSIZE];
  char templatefile[FILESIZE];

  unsigned char response;
  unsigned char ipchains_check;
  char pidfile[FILESIZE];
  char notify_script[FILESIZE];
  char respond_script[FILESIZE];
  char run_as[USERSIZE];
  unsigned char status;
  unsigned char stateful_start;
  int sock;
  char listenif[IP6LEN];
  int listenport;
  char listento[IPLEN];
  char user[USERSIZE];
  char password[PASSWORDSIZE];
  int refresh;
  unsigned char webpage;
  int global_id;
};

#endif
