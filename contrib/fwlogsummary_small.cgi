#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.12 2003/04/08 21:43:04 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
