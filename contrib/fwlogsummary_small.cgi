#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.9 2002/05/15 22:24:44 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
