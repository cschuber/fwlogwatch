#!/bin/sh
# $Id: fwlogsummary.small.cgi,v 1.8 2002/02/14 20:54:34 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
