#!/bin/sh
# $Id: fwlogsummary.small.cgi,v 1.13 2002/02/14 21:15:36 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
