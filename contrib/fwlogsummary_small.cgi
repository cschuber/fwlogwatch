#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.6 2002/02/24 14:27:31 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
