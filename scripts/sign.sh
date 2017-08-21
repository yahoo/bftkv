#!/bin/bash

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

output=
if [ "$1" == "-o" ]; then shift; output="-o $1"; shift; fi

signer=$1
if [ "$signer" == "" ]; then echo "$0 signer key..."; exit; fi
shift

function e {
    echo $* 1>&2
}

function sign {
    keyid=`gpg --homedir $signer --batch --no-tty --fast-import $1 2>&1 | grep 'gpg: key' | sed 's/.*key \([A-Z0-9]*\):.*/\1/'`
    if [ $? -ne 0 ]; then e "$0: import failed"; return 1; fi
    gpg --homedir $signer --batch --sign-key --yes $keyid > /dev/null 2>&1
    if [ $? -ne 0 ]; then e "$0: sign-key failed"; return 1; fi
    gpg $output --yes --homedir $signer --export $keyid
    if [ $? -ne 0 ]; then e "$0: export failed"; return 1; fi
}

BAK=/tmp/$signer
rm -fr $BAK
cp -prf $signer $BAK
sign $*
RET=$?
cp -prf $BAK .
rm -fr $BAK
exit $RET
