#!/bin/sh
# $Id: fwlogsummary.small.cgi,v 1.9 2002/02/14 21:00:01 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
