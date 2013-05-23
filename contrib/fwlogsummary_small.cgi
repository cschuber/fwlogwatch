#!/bin/sh
# Copyright (C) 2000-2013 Boris Wesslowski
# $Id: fwlogsummary_small.cgi,v 1.18 2013/05/23 15:04:15 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
