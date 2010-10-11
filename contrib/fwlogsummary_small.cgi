#!/bin/sh
# Copyright (C) 2000-2010 Boris Wesslowski
# $Id: fwlogsummary_small.cgi,v 1.16 2010/10/11 12:28:34 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
