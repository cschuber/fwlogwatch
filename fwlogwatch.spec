# $Id: fwlogwatch.spec,v 1.22 2002/03/29 11:25:52 bwess Exp $

%define name fwlogwatch
%define version 0.7

Name: %name
Version: %version
Release: 1
Group: Applications/Utilities
Packager: Boris Wesslowski <Wesslowski@CERT.Uni-Stuttgart.DE>
Vendor: RUS-CERT
URL: http://cert.uni-stuttgart.de/projects/fwlogwatch/
License: GPL
Summary: Firewall log analyzer, report generator and realtime response agent
Source: %name-%version.tar.gz
Patch: %name-%version-paths.patch
BuildRoot: /var/tmp/%name-buildroot

%description
fwlogwatch produces Linux ipchains, Linux netfilter/iptables,
Solaris/BSD/Irix/HP-UX ipfilter, Cisco IOS, Cisco PIX and Windows XP
firewall log summary reports in plain text and HTML form and has a lot of
options to analyze and display relevant patterns. It can produce
customizable incident reports and send them to abuse contacts at offending
sites or CERTs. Finally, it can also run as daemon (with web interface)
doing realtime log monitoring and reporting anomalies or starting attack
countermeasures.

%prep

%setup -n %name-%version

%patch -p1

%build
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man8
mkdir -p $RPM_BUILD_ROOT/usr/share/locale/de/LC_MESSAGES
mkdir -p $RPM_BUILD_ROOT/usr/share/locale/pt_BR/LC_MESSAGES
mkdir -p $RPM_BUILD_ROOT/usr/share/locale/sv/LC_MESSAGES
mkdir -p $RPM_BUILD_ROOT/usr/share/locale/zh_CN/LC_MESSAGES
mkdir -p $RPM_BUILD_ROOT/usr/share/locale/zh_TW/LC_MESSAGES
make install INSTALL_DIR=$RPM_BUILD_ROOT/usr
make install-config CONF_DIR=$RPM_BUILD_ROOT/etc
make install-i18n LOCALE_DIR=$RPM_BUILD_ROOT/usr
make install-rhinit CONF_DIR=$RPM_BUILD_ROOT/etc

%files
/usr/sbin/fwlogwatch
/usr/sbin/fwlw_notify
/usr/sbin/fwlw_respond
/usr/share/man/man8/fwlogwatch.8.gz
%config(noreplace) /etc/fwlogwatch.config
%config(noreplace) /etc/fwlogwatch.template
%config(noreplace) /etc/rc.d/init.d/fwlogwatch
%lang(de) /usr/share/locale/de/LC_MESSAGES/fwlogwatch.mo
%lang(pt_BR) /usr/share/locale/pt_BR/LC_MESSAGES/fwlogwatch.mo
%lang(sv) /usr/share/locale/sv/LC_MESSAGES/fwlogwatch.mo
%lang(zh_CN) /usr/share/locale/zh_CN/LC_MESSAGES/fwlogwatch.mo
%lang(zh_TW) /usr/share/locale/zh_TW/LC_MESSAGES/fwlogwatch.mo
%doc AUTHORS COPYING CREDITS ChangeLog README
%doc contrib/fwlogsummary.cgi contrib/fwlogsummary_small.cgi
