#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.10 2002/08/20 21:17:45 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
