#!/bin/sh
# $Id: fwlogsummary.small.cgi,v 1.5 2002/02/14 20:42:15 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
