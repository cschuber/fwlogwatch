#!/bin/sh
# $Id: fwlogsummary.cgi,v 1.4 2002/02/14 20:36:55 bwess Exp $

# You could run this from crontab:
# 30 * * * * /path/fwlogsummary

RECENT="-l 1h"
WEBDIR="/home/httpd/html/fwlogwatch";
if [ ! -d $WEBDIR  ]
then
  mkdir $WEBDIR
fi

if [ -z $1  ]
then
  MESSAGES="-f /var/log/messages"
else
  MESSAGES="-f $1"
fi

fwlogwatch $MESSAGES $RECENT -w -t -z -S                -o $WEBDIR/dst.html
fwlogwatch $MESSAGES $RECENT -w -t -z    -D             -o $WEBDIR/src.html
fwlogwatch $MESSAGES $RECENT -w -t -z                   -o $WEBDIR/src_dst.html
fwlogwatch $MESSAGES $RECENT -w -t -z       -s          -o $WEBDIR/src_dst_sp.html
fwlogwatch $MESSAGES $RECENT -w -t -z          -d       -o $WEBDIR/src_dst_dp.html
fwlogwatch $MESSAGES $RECENT -w -t -z       -s -d       -o $WEBDIR/src_dst_sp_dp.html
fwlogwatch $MESSAGES $RECENT -w -t -z       -s -d -y    -o $WEBDIR/src_dst_sp_dp_op.html
fwlogwatch $MESSAGES $RECENT -w -t -z       -s -d -y -n -o $WEBDIR/all.html

cat <<EOF > $WEBDIR/index.html
<html>
<head>
<title>fwlogwatch</title>
</head>
<body text="#000000" bgcolor="#FFFFFF" >
<font face="Arial, Helvetica">
<div align="center">
<h1>fwlogwatch summaries of the last hour</h1>
</div>

<a href="/cgi-bin/fwlogwatch.cgi">Regenerate summaries now</a>

<h3>Summary by criteria:</h3>
<a href="src.html">Source IPs only</a><br>
<a href="dst.html">Destination IPs only</a><br>
<a href="src_dst.html">Both IPs</a><br>
<a href="src_dst_sp.html">With source port</a><br>
<a href="src_dst_dp.html">With destination port</a><br>
<a href="src_dst_sp_dp.html">Both ports</a><br>
<a href="src_dst_sp_dp_op.html">Both ports and tcp options</a><br>
<a href="all.html">All and name resolution</a><br>
<br>
Press the back button of your browser to return here.<br>
<br>
<hr>
\$Id: fwlogsummary.cgi,v 1.4 2002/02/14 20:36:55 bwess Exp $
</font>
</body>
</html>
EOF
