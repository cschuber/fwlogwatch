Name: fwlogwatch
Version: 0.0.21
Release: 1
Group: Applications/Utilities
Packager: Boris Wesslowski <Boris.Wesslowski@RUS.Uni-Stuttgart.DE>
URL: http://www.kyb.uni-stuttgart.de/boris/software.shtml
Copyright: GPL
Summary: Firewall log analyzer, report generator and realtime response agent
Source: fwlogwatch-0.0.21.tar.gz

%description
fwlogwatch produces ipchains log summary reports in text and HTML form,
from the data found it can produce customizable incident reports from a
template and send them to abuse contacts at offending sites or CERT
coordination centers. Finally, it can also run as daemon and report
anomalies or start countermeasures.

%prep

%setup -n fwlogwatch-0.0.21

%build
make

%install
make install

%files
/usr/local/sbin/fwlogwatch
/usr/local/man/man1/fwlogwatch.1
%config /etc/fwlogwatch.config
%config /etc/fwlogwatch.template
%doc AUTHORS
%doc COPYING
%doc README
