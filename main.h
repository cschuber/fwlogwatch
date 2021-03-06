/* Copyright (C) 2000-2016 Boris Wesslowski */
/* $Id: main.h,v 1.34 2016/02/19 16:09:27 bwess Exp $ */

#ifndef _MAIN_H
#define _MAIN_H

#define PACKAGE "fwlogwatch"
#define VERSION "1.5 2016-02-19"
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
#define TIMESIZE 64
#define HOSTLEN 256
#define HOSTLEN_M1_S "255"
#define SHOSTLEN 32
#define SHOSTLEN_S "32"
#define IPLEN 16
#define IP6LEN 40
#define EMAILSIZE 80
#define COLORSIZE 8
#define MAXSORTSIZE 24
#define USERSIZE 16
#define PASSWORDSIZE 76
#define WHOISCMDLEN 64
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

#ifndef SOLARIS
#define INFILE "/var/log/messages"
#else
#define INFILE "/var/adm/messages"
#endif
#define RCFILE CONF_DIR "/fwlogwatch.config"

/* Includes */

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef HAVE_GEOIP
#include <GeoIP.h>
#endif

enum {
  MAY_NOT_EXIST,
  MUST_EXIST
};

enum {
  NO,
  YES
};

enum {
  HASH_IGNORE,
  HASH_ENDS_INPUT
};

/* Modes */

enum {
  LOG_SUMMARY,
  REALTIME_RESPONSE,
  SHOW_LOG_TIMES
};

/* Parser */

#define PARSER_IPCHAINS 1
#define PARSER_NETFILTER 2
#define PARSER_CISCO_IOS 4
#define PARSER_IPFILTER 8
#define PARSER_CISCO_PIX 16
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

enum {
  RCFILE_CF,
  RCFILE_DNS
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
#define NF_CODE 256

enum {
  NF_OPT_NOPREFIX,
  NF_OPT_PREFIX,
  NF_OPT_PREFIX_KTIME,
  NF_OPT_SRC,
  NF_OPT_DST,
  NF_OPT_SRC6,
  NF_OPT_DST6
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
#define CISCO_PIX_NO_HIT 8

enum {
  CP_OPT_NONE,
  CP_OPT_HOST,
  CP_OPT_TCP,
  CP_OPT_TCP_S,
  CP_OPT_TCP_S2,
  CP_OPT_TCP_N,
  CP_OPT_TCP_N2,
  CP_OPT_UDP,
  CP_OPT_UDP_S,
  CP_OPT_UDP_S2,
  CP_OPT_UDP_N,
  CP_OPT_UDP_N2,
  CP_OPT_UDP_NOPORT,
  CP_OPT_ICMP,
  CP_OPT_ICMP_S,
  CP_OPT_ICMP_S2,
  CP_OPT_ICMP_N2,
  CP_OPT_DST,
  CP_OPT_DST_S,
  CP_OPT_DST_S2,
  CP_OPT_DST_N,
  CP_OPT_DST_N2,
  CP_OPT_DST_I
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
#define NS_NO_HIT 128

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
#define P_SENDMAIL "/usr/sbin/sendmail"

/* Realtime response mode */

#define ALERT 5
#define FORGET 86400
#define FWLW_NOTIFY INSTALL_DIR "/sbin/fwlw_notify"
#define FWLW_RESPOND INSTALL_DIR "/sbin/fwlw_respond"
#define STATUS_TITLE _("fwlogwatch status")
#define LISTENIF "::1"
#define LISTENPORT 888
#define DEFAULT_USER "admin"
#define DEFAULT_PASSWORD "2fi4nEVVz0IXo"	/* fwlogwat[ch]
						   DES only supports 8 characters */

#define OPT_LOG 1
#define OPT_NOTIFY 2
#define OPT_RESPOND 4

#define EX_NOTIFY 1
#define EX_RESPOND_ADD 2
#define EX_RESPOND_REMOVE 3

#define RESP_REMOVE_OPC 1
#define RESP_REMOVE_OHS 2

/* GeoIP */

#define GEOIP_DB_V4 "/var/lib/GeoIP/GeoIP.dat"
#define GEOIP_DB_V6 "/var/lib/GeoIP/GeoIPv6.dat"


enum {
  FW_START,
  FW_STOP
};

enum {
  NO_NET_OPTS_PC,
  NET_OPTS_PC,
  NO_SORTING,
  SORTING,
  SORT_PC,
  SORT_HS
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
  unsigned long int datalen;
  struct in6_addr shost;
  int sport;
  struct in6_addr dhost;
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
  unsigned long int datalen;
  struct in6_addr shost;
  int sport;
  struct in6_addr dhost;
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
  struct in6_addr ip;
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

struct known_hosts {
  time_t time;
  int count;
  struct in6_addr shost;
  struct in6_addr netmask;
  struct in6_addr dhost;
  int protocol;
  int sport;
  int dport;
  int id;
  struct known_hosts *next;
};

struct parser_options {
  unsigned char mode;
  struct in6_addr host;
  struct in6_addr netmask;
  unsigned long int value;
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
#ifdef HAVE_ZLIB
  gzFile gzinputfd;
#endif
  unsigned char std_in;

  unsigned char verbose;
  unsigned char resolve;
  unsigned char sresolve;
  unsigned char whois_lookup;
  int whois_sock;
  int filecount;
  char rcfile[FILESIZE];
  char rcfile_dns[FILESIZE];

  struct log_line *line;
  char format_sel[SHORTLEN];
  unsigned int format;
  unsigned int parser;
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
  char listento[IP6LEN];
  int listenport;
  char user[USERSIZE];
  char password[PASSWORDSIZE];
  int refresh;
  unsigned char webpage;
  int global_id;

  char ntop[INET6_ADDRSTRLEN];

#ifdef HAVE_GEOIP
  unsigned char geoip;
  GeoIP *geoip_v4;
  GeoIP *geoip_v6;
  char geoip_db_v4[FILESIZE];
  char geoip_db_v6[FILESIZE];
#endif
};

#endif
