#!/bin/sh
# $Id: fwlogsummary.small.cgi,v 1.4 2002/02/14 20:36:55 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
