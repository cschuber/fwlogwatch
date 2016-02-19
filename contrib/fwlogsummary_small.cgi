#!/bin/sh
# Copyright (C) 2000-2016 Boris Wesslowski
# $Id: fwlogsummary_small.cgi,v 1.19 2016/02/19 16:09:27 bwess Exp $

echo "Content-Type: text/html"
echo
/usr/local/sbin/fwlogwatch -w -l 1h -z -s -d
