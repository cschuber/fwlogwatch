#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.7 2002/03/29 11:25:52 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
