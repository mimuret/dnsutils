#!/bin/sh

dnssec-keygen -a ED25519 -f ksk -K keys example.jp
dnssec-keygen -a ED25519 -K keys example.jp
dnssec-signzone -S -K keys -x -s 1704067200 -e 1893456000 -O full -o example.jp -f example.jp.nsec example.jp.sign 
dnssec-signzone -S -K keys -x -s 1704067200 -e 1893456000 -3 "" -H 0 -O full -o example.jp -f example.jp.nsec3 example.jp.sign 