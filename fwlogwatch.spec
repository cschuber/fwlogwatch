# $Id: fwlogwatch.spec,v 1.25 2002/08/20 21:17:44 bwess Exp $

Name: fwlogwatch
Version: 0.9
Release: 1
Group: Applications/Utilities
Packager: Boris Wesslowski <Wesslowski@CERT.Uni-Stuttgart.DE>
Vendor: RUS-CERT
URL: http://cert.uni-stuttgart.de/projects/fwlogwatch/
License: GPL
Summary: Firewall log analyzer, report generator and realtime response agent
Source: %{name}-%{version}.tar.gz
Patch: %{name}-%{version}-paths.patch
BuildRequires(build): flex
BuildRoot: %_tmppath/%{name}-%{version}-buildroot

%description
fwlogwatch produces Linux ipchains, Linux netfilter/iptables,
Solaris/BSD/Irix/HP-UX ipfilter, Cisco IOS, Cisco PIX, NetScreen,
Windows XP firewall, Elsa Lancom router and Snort IDS log summary reports
in plain text and HTML form and has a lot of options to analyze and display
relevant patterns. It can produce customizable incident reports and send
them to abuse contacts at offending sites or CERTs. Finally, it can also
run as daemon (with web interface) doing realtime log monitoring and
reporting anomalies or starting attack countermeasures.

%prep
%setup
%patch -p1

%build
%__make

%install
[ -n "${RPM_BUILD_ROOT}" ] && %__rm -rf "${RPM_BUILD_ROOT}"
%__install -d "${RPM_BUILD_ROOT}%{_sbindir}"
%__install -d "${RPM_BUILD_ROOT}%{_sysconfdir}/rc.d/init.d"
%__install -d "${RPM_BUILD_ROOT}%{_mandir}/man8"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/de/LC_MESSAGES"
%__install -d "${RPM_BUILD_ROOT}%{_datadir}/locale/pt_BR/LC_MESSAGES"
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

%files
%defattr(-,root,root)
%doc AUTHORS COPYING CREDITS ChangeLog README
%doc contrib/fwlogsummary.cgi contrib/fwlogsummary_small.cgi
%doc contrib/fwlogwatch.php
%config(noreplace) %{_sysconfdir}/fwlogwatch.config
%config(noreplace) %{_sysconfdir}/fwlogwatch.template
%config(noreplace) %{_sysconfdir}/rc.d/init.d/fwlogwatch
%{_sbindir}/fwlogwatch
%{_sbindir}/fwlw_notify
%{_sbindir}/fwlw_respond
%{_mandir}/man8/fwlogwatch.8.gz
%lang(de) %{_datadir}/locale/de/LC_MESSAGES/fwlogwatch.mo
%lang(pt_BR) %{_datadir}/locale/pt_BR/LC_MESSAGES/fwlogwatch.mo
%lang(sv) %{_datadir}/locale/sv/LC_MESSAGES/fwlogwatch.mo
%lang(zh_CN) %{_datadir}/locale/zh_CN/LC_MESSAGES/fwlogwatch.mo
%lang(zh_TW) %{_datadir}/locale/zh_TW/LC_MESSAGES/fwlogwatch.mo
