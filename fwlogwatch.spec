# $Id: fwlogwatch.spec,v 1.21 2002/02/24 14:27:30 bwess Exp $

%define name fwlogwatch
%define version 0.6

Name: %name
Version: %version
Release: 1
Group: Applications/Utilities
Packager: Boris Wesslowski <Boris.Wesslowski@RUS.Uni-Stuttgart.DE>
Vendor: RUS-CERT
URL: http://cert.uni-stuttgart.de/projects/fwlogwatch/
License: GPL
Summary: Firewall log analyzer, report generator and realtime response agent
Source: %name-%version.tar.gz
Patch: %name-%version-paths.patch
BuildRoot: /var/tmp/%name-buildroot

%description
fwlogwatch produces ipchains, netfilter/iptables, ipfilter, Cisco IOS and
Cisco PIX log summary reports in text and HTML form and has a lot of
options to find and display relevant patterns in connection attempts. With
the data found it can also generate customizable incident reports from a
template and send them to abuse contacts at offending sites or CERT
coordination centers. Finally, it can also run as daemon and report
anomalies or start countermeasures.

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
make install INSTALL_DIR=$RPM_BUILD_ROOT/usr CONF_DIR=$RPM_BUILD_ROOT/etc
make install-config INSTALL_DIR=$RPM_BUILD_ROOT/usr CONF_DIR=$RPM_BUILD_ROOT/etc
make install-i18n INSTALL_DIR=$RPM_BUILD_ROOT/usr CONF_DIR=$RPM_BUILD_ROOT/etc

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
