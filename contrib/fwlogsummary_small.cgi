#!/bin/sh
# Copyright (C) 2000-2004 Boris Wesslowski
# $Id: fwlogsummary_small.cgi,v 1.14 2004/04/25 18:56:36 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
