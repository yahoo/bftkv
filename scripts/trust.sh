#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

trust=both
if [ "$1" == "-t" ]; then shift; trust=$1; shift; fi

signer=$1
shift

if [ "$signer" == "" ]; then echo "$0 signer signee..."; exit; fi

for i in "$@"; do
    id=`basename $i`
    gpg2 --homedir .$i --export $id | sign.sh -o /tmp/$id.gpg $signer
    if [ $? -ne 0 ]; then echo "$0: failed to sign $i" 1>&2; fi
done

for i in "$@"; do
    id=`basename $i`
    if [ "$trust" == "both" ] || [ "$trust" == "signer" ]; then
	gpg2 --homedir .$signer --batch --no-tty --fast-import /tmp/$id.gpg > /dev/null 2>&1
	if [ $? -ne 0 ]; then echo "$0: failed to import $i"; fi
    fi
    if [ "$trust" == "both" ] || [ "$trust" == "signee" ]; then
	gpg2 --homedir .$i --batch --no-tty --fast-import /tmp/$id.gpg > /dev/null 2>&1
	if [ $? -ne 0 ]; then echo "$0: failed to import $i"; fi
	gpg2 --homedir .$i --export > $i/pubring.gpg
    fi
    rm -f /tmp/$id.gpg
done

if [ "$trust" == "both" ] || [ "$trust" == "signer" ]; then
    gpg2 --homedir .$signer --batch --no-tty --export > $signer/pubring.gpg
fi
