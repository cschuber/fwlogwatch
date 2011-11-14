#!/bin/sh
# Copyright (C) 2000-2011 Boris Wesslowski
# $Id: fwlogsummary_small.cgi,v 1.17 2011/11/14 12:53:52 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
