#!/bin/sh
# $Id: fwlogsummary.small.cgi,v 1.11 2002/02/14 21:06:11 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
