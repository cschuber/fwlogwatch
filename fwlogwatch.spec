Name: fwlogwatch
Version: 0.0.24
Release: 1
Group: Applications/Utilities
Packager: Boris Wesslowski <Boris.Wesslowski@RUS.Uni-Stuttgart.DE>
Vendor: RUS-CERT
URL: http://www.kyb.uni-stuttgart.de/boris/software.shtml
Copyright: GPL
Summary: Firewall log analyzer, report generator and realtime response agent
Source: fwlogwatch-0.0.24.tar.gz

%description
fwlogwatch produces ipchains log summary reports in text and HTML form,
with the data found it can produce customizable incident reports from a
template and send them to abuse contacts at offending sites or CERT
coordination centers. Finally, it can also run as daemon and report
anomalies or start countermeasures.

%prep

%setup -n fwlogwatch-0.0.24

%build
make

%install
make install-rpm
make install-config

%files
/usr/sbin/fwlogwatch
/usr/man/man8/fwlogwatch.8
%config /etc/fwlogwatch.config
%config /etc/fwlogwatch.template
%doc AUTHORS
%doc COPYING
%doc CREDITS
%doc ChangeLog
%doc README
%doc contrib/fwlogsummary.cgi
%doc contrib/fwlogsummary.small.cgi
