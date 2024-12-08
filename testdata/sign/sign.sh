#!/bin/sh

#dnssec-keygen -a ED25519 -f ksk -K keys example.jp
#dnssec-keygen -a ED25519 -K keys example.jp
dnssec-signzone -S -K keys -x -s 1704067200 -e 1893456000 -O full -o example.jp -f example.jp.nsec.bind example.jp.source 
dnssec-signzone -S -K keys -x -s 1704067200 -e 1893456000 -3 "" -H 0 -O full -o example.jp -f example.jp.nsec3.bind example.jp.source 
ldns-signzone -s 1704067200 -e 1893456000 -f example.jp.nsec.ldns example.jp.source keys/Kexample.jp.+015+02290  keys/Kexample.jp.+015+30075
ldns-signzone -s 1704067200 -e 1893456000 -n -t 0 -s "" -f example.jp.nsec3.ldns example.jp.source keys/Kexample.jp.+015+02290  keys/Kexample.jp.+015+30075
rm dsset-example.jp.
