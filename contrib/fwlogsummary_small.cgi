#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.11 2003/03/22 23:16:50 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
