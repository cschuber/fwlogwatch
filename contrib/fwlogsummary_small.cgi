#!/bin/sh
# $Id: fwlogsummary_small.cgi,v 1.1 2002/02/14 21:26:30 bwess Exp $

echo "Content-Type: text/html"
echo
fwlogwatch -w -l 1h -z -s -d
