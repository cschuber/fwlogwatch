#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.13 2003/06/23 15:26:53 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
