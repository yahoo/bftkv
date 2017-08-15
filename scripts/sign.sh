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
    if [ $? -ne 0 ]; then e "$0: import failed"; exit 1; fi
    gpg --homedir $signer --batch --sign-key --yes $keyid 2>/dev/null
    if [ $? -ne 0 ]; then e "$0: sign-key failed"; exit 1; fi
    gpg $output --yes --homedir $signer --export $keyid
    if [ $? -ne 0 ]; then e "$0: export failed"; exit 1; fi
    e "signed $keyid"
}

if [ $# -eq 0 ]; then
    sign
else
    for i in "$@"; do
	keyid=`gpg --homedir $i --list-secret-keys | grep '^sec' | head -1 | sed 's/^.*\/\([A-Z0-9]*\) .*$/\1/'`
	if [ $? -ne 0 ] || [ "$keyid" == "" ]; then echo "$0: failed to get ID" 1>&2; fi
	TMP=/tmp/$i.pub
	gpg -o $TMP --homedir $i --export $keyid
	sign $TMP
	rm -f $TMP
    done
fi
