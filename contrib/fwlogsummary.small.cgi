#!/bin/sh
# $Id: fwlogsummary.small.cgi,v 1.1 2002/02/14 20:09:16 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
