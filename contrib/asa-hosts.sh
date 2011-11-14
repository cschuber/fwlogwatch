#!/bin/sh

if [ -z "$1" ]
then
  echo "usage: $0 <file containing asa configuration>"
  echo "example: $0 /tftpboot/asa-config.txt > hosts.txt"
  exit 1
fi

echo "# names"
grep "^name " "$1" | awk '{print $2"	"$3}' | sort -k2

echo
echo "# host objects"
grep -A1 "^object network " $1 \
| grep -v "^--" \
| sed -e 'N;s/\n / /g' \
| grep " host " \
| awk '{print $5"	"$3}' \
| sort -k2

exit 0
