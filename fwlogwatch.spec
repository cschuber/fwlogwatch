%define name fwlogwatch
%define version 0.1.3

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

%description
fwlogwatch produces ipchains, netfilter/iptables and cisco log summary
reports in text and HTML form and has a lot of options to find and display
relevant patterns in connection attempts. With the data found it can
produce customizable incident reports from a template and send them to
abuse contacts at offending sites or CERT coordination centers. Finally,
it can also run as daemon and report anomalies or start countermeasures.

%prep

%setup -n %name-%version

%build
make

%install
make install-rpm
make install-config

%files
/usr/sbin/fwlogwatch
/usr/share/man/man8/fwlogwatch.8
%config /etc/fwlogwatch.config
%config /etc/fwlogwatch.template
%doc AUTHORS COPYING CREDITS ChangeLog README
%doc contrib/fwlogsummary.cgi contrib/fwlogsummary.small.cgi
