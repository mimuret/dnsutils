#!/bin/sh

#dnssec-keygen -a ED25519 -f ksk -K keys example
#dnssec-keygen -a ED25519 -K keys example
dnssec-signzone -S -K keys -x -s 1704067200 -e 1893456000 -O full -o example -f example.complex.signed.tmp example.complex.valid-zone 
ldns-zone-digest -c -p 1,1 -z keys/Kexample.+015+04770.private -o example.complex.signed-1 example example.complex.signed.tmp