#!/bin/sh

if [ $# -le 3 ]; then echo "usage: sign caname cert"; exit 1; fi

TMP=tmp.x509
# make up a dummy CA keys
./mkca.sh dummy
openssl x509 -CA dummy.x509 -CAkey dummy.pkcs8 -set_serial 1 -force_pubkey ca.pub -out $TMP -in $2 2> /dev/null
rm -f dummy.*
./bftrw sign $1 $TMP
ret=$?
rm -f $TMP
exit $ret
