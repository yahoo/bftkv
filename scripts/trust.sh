#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

trust=both
if [ "$1" == "-t" ]; then shift; trust=$1; shift; fi

signer=$1
shift

if [ "$signer" == "" ]; then echo "$0 signer signee..."; exit; fi

for i in "$@"; do
    keyid=`gpg --homedir $i --list-secret-keys | grep '^sec' | head -1 | sed 's/^.*\/\([A-Z0-9]*\) .*$/\1/'`
    if [ $? -ne 0 ] || [ "$keyid" == "" ]; then
	echo "$0: failed to get ID" 1>&2
	continue
    fi
    gpg --homedir $i --export $keyid | sign.sh -o /tmp/$i.gpg $signer
    if [ $? -ne 0 ]; then echo "$0: failed to sign $i" 1>&2; fi
done

for i in "$@"; do
    if [ "$trust" == "both" ] || [ "$trust" == "signer" ]; then
	gpg --homedir $signer --batch --no-tty --fast-import /tmp/$i.gpg > /dev/null 2>&1
	if [ $? -ne 0 ]; then echo "$0: failed to import $i"; fi
    fi
    if [ "$trust" == "both" ] || [ "$trust" == "signee" ]; then
	gpg --homedir $i --batch --no-tty --fast-import /tmp/$i.gpg > /dev/null 2>&1
	if [ $? -ne 0 ]; then echo "$0: failed to import $i"; fi
    fi
    rm -f /tmp/$i.gpg
done
