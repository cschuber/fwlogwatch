#!/bin/sh
# $Id: fwlogsummary.cgi,v 1.24 2002/08/20 21:17:45 bwess Exp $

# This script generates 8 fwlogwatch html summaries in a directory visible
# to your web server.
# The log file to be used can be specified as first parameter, default is
# /var/log/messages
# With respective permissions it can be run as cgi by the webserver.
# You can also invoke this script directly from the command line or from
# cron (you might want to remove the header output).

echo 'Content-type: text/plain'
echo

echo -n 'fwlogsummary invoked '
date

RECENT="-l 1h"
WEBDIR="/var/www/html/fwlogwatch"
FWLOGWATCH="/usr/local/sbin/fwlogwatch"

if [ ! -d $WEBDIR ] ; then
  echo "Directory $WEBDIR does not exist!"
  exit
fi

if [ ! -f $FWLOGWATCH ] ; then
  echo "$FWLOGWATCH not found!"
  exit
fi

if [ -z $1 ]
then
  MESSAGES="-f /var/log/messages"
else
  MESSAGES="-f $1"
fi

$FWLOGWATCH $MESSAGES $RECENT -w -t -z -S                -o $WEBDIR/dst.html
$FWLOGWATCH $MESSAGES $RECENT -w -t -z    -D             -o $WEBDIR/src.html
$FWLOGWATCH $MESSAGES $RECENT -w -t -z                   -o $WEBDIR/src_dst.html
$FWLOGWATCH $MESSAGES $RECENT -w -t -z       -s          -o $WEBDIR/src_dst_sp.html
$FWLOGWATCH $MESSAGES $RECENT -w -t -z          -d       -o $WEBDIR/src_dst_dp.html
$FWLOGWATCH $MESSAGES $RECENT -w -t -z       -s -d       -o $WEBDIR/src_dst_sp_dp.html
$FWLOGWATCH $MESSAGES $RECENT -w -t -z       -s -d -y    -o $WEBDIR/src_dst_sp_dp_op.html
$FWLOGWATCH $MESSAGES $RECENT -w -t -z       -s -d -y -n -o $WEBDIR/all.html


cat <<EOF > $WEBDIR/index.html
<html>
<head>
<title>fwlogwatch</title>
</head>
<body text="#000000" bgcolor="#FFFFFF" >
<font face="Arial, Helvetica">

<div align="center">
<h1>fwlogwatch summaries</h1>
<a href="/cgi-bin/fwlogsummary.cgi">regenerate summaries now</a>
</div>

<h3>Summary by criteria:</h3>
<small>Press the back button of your browser to return here.</small>
<ul>
 <li><a href="src.html">source IP address only</a></li>
 <li><a href="dst.html">destination IP address only</a></li>
 <li><a href="src_dst.html">source and destination IP addresses</a></li>
 <ul>
  <li><a href="src_dst_sp.html">with source port</a></li>
  <li><a href="src_dst_dp.html">with destination port</a></li>
  <li><a href="src_dst_sp_dp.html">with source and destination ports</a></li>
  <ul>
   <li><a href="src_dst_sp_dp_op.html">with tcp options</a></li>
  </ul>
 </ul>
 <li><a href="all.html">everything and name resolution</a></li>
</ul>
<br>
<hr>
<small><a href="http://cert.uni-stuttgart.de/projects/fwlogwatch/">fwlogwatch</a> &copy; Boris Wesslowski, RUS-CERT</small>

</font>
</body>
</html>
EOF

echo -n "Finished "
date

# EOF
