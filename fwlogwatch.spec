# $Id: fwlogwatch.spec,v 1.17 2002/02/14 21:32:47 bwess Exp $

%define name fwlogwatch
%define version 0.4

Name: %name
Version: %version
Release: 1
Group: Applications/Utilities
Packager: Boris Wesslowski <Boris.Wesslowski@RUS.Uni-Stuttgart.DE>
Vendor: RUS-CERT
URL: http://cert.uni-stuttgart.de/projects/fwlogwatch/
Copyright: GPL
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
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man8
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
make install INSTALL_DIR=$RPM_BUILD_ROOT/usr CONF_DIR=$RPM_BUILD_ROOT/etc
make install-config INSTALL_DIR=$RPM_BUILD_ROOT/usr CONF_DIR=$RPM_BUILD_ROOT/etc

%files
/usr/sbin/fwlogwatch
/usr/sbin/fwlw_notify
/usr/sbin/fwlw_respond
/etc/rc.d/init.d/fwlogwatch
/usr/share/man/man8/fwlogwatch.8.gz
%config /etc/fwlogwatch.config
%config /etc/fwlogwatch.template
%doc AUTHORS COPYING CREDITS ChangeLog README
%doc contrib/fwlogsummary.cgi contrib/fwlogsummary_small.cgi
