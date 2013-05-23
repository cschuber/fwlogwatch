# Copyright (C) 2000-2013 Boris Wesslowski
# $Id: fwlogwatch.spec,v 1.33 2013/05/23 15:04:14 bwess Exp $

Name: fwlogwatch
Version: 1.4
Release: 1
Group: Productivity/Networking/Security
Vendor: Boris Wesslowski
URL: http://fwlogwatch.inside-security.de/
License: GPL
Summary: Firewall log analyzer, report generator and realtime response agent
#Source: http://fwlogwatch.inside-security.de/sw/%{name}-%{version}.tar.gz
Source: %{name}-%{version}.tar.gz
BuildRequires: flex
BuildRoot: %_tmppath/%{name}-%{version}-buildroot

%description
fwlogwatch produces Linux ipchains, Linux netfilter/iptables,
Solaris/BSD/IRIX/HP-UX ipfilter, Cisco IOS, Cisco PIX/ASA, NetScreen, Elsa
Lancom router and Snort IDS log summary reports in plain text and HTML form
and has a lot of options to analyze and display relevant patterns. It also
can run as daemon (with web interface) doing realtime log monitoring and
reporting anomalies or starting attack countermeasures.

%prep
%setup

%build
%__make

%install
%__install -d "${RPM_BUILD_ROOT}%{_sbindir}"
%__install -d "${RPM_BUILD_ROOT}%{_sysconfdir}/rc.d/init.d"
%__install -d "${RPM_BUILD_ROOT}%{_mandir}/man8"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/de/LC_MESSAGES"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/ja/LC_MESSAGES"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/pt/LC_MESSAGES"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/sv/LC_MESSAGES"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/zh_CN/LC_MESSAGES"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/zh_TW/LC_MESSAGES"
%__make install INSTALL_DIR="${RPM_BUILD_ROOT}%{_prefix}"
%__make install-config CONF_DIR="${RPM_BUILD_ROOT}%{_sysconfdir}"
%__make install-i18n LOCALE_DIR="${RPM_BUILD_ROOT}%{_prefix}"
%__make install-rhinit CONF_DIR="${RPM_BUILD_ROOT}%{_sysconfdir}"

%clean
[ -n "${RPM_BUILD_ROOT}" ] && %__rm -rf "${RPM_BUILD_ROOT}"
( cd "${RPM_BUILD_DIR}" && %__rm -rf "%{name}-%{version}" )

%preun
%stop_on_removal

%postun
%insserv_cleanup

%files
%defattr(-,root,root)
%doc AUTHORS COPYING CREDITS ChangeLog README
%doc contrib/fwlogsummary.cgi contrib/fwlogsummary_small.cgi
%doc contrib/fwlogwatch.php
%config(noreplace) %{_sysconfdir}/fwlogwatch.config
%config(noreplace) %{_sysconfdir}/rc.d/init.d/fwlogwatch
%config(noreplace) %{_sbindir}/fwlw_notify
%config(noreplace) %{_sbindir}/fwlw_respond
%{_sbindir}/fwlogwatch
%{_mandir}/man8/fwlogwatch.8.gz
%lang(de) %{_datadir}/locale/de/LC_MESSAGES/fwlogwatch.mo
%lang(ja) %{_datadir}/locale/ja/LC_MESSAGES/fwlogwatch.mo
%lang(pt) %{_datadir}/locale/pt/LC_MESSAGES/fwlogwatch.mo
%lang(sv) %{_datadir}/locale/sv/LC_MESSAGES/fwlogwatch.mo
%lang(zh_CN) %{_datadir}/locale/zh_CN/LC_MESSAGES/fwlogwatch.mo
%lang(zh_TW) %{_datadir}/locale/zh_TW/LC_MESSAGES/fwlogwatch.mo
