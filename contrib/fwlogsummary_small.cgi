#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.8 2002/05/08 17:24:10 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
