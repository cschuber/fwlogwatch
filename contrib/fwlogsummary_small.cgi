#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.3 2002/02/14 21:36:54 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
