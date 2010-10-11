#!/bin/sh

if [ -z "$1" ]
then
  echo "usage: $0 <file containing pix configuration>"
  echo "example: $0 /tftpboot/pix-config.txt >> /etc/hosts"
  exit 1
fi

grep "^name " "$1" | awk '{print $2"	"$3}' | sort -k2

exit 0
