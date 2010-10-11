#!/bin/sh
# Copyright (C) 2000-2006 Boris Wesslowski
# $Id: fwlogsummary_small.cgi,v 1.15 2010/10/11 12:17:44 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
