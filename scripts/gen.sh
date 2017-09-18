#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

url=""
addr=""
port=0
if [ "$1" == "-url" ]; then
    shift; url=$1; shift;
    addr=`expr $url : '\(.*\):[0-9]*$' \| $url`
    port=`expr $url : '.*:\([0-9]*\)$' \| 5601`
fi

uid=""
if [ "$1" == "-uid" ]; then shift; uid=" <$1>"; shift; fi

for i in "$@"; do
    rm -fr $i .$i
    mkdir -p $i .$i
    chmod 700 $i .$i
    url=""
    if [ "$addr" != "" ]; then url=" ($addr:$port)"; port=`expr $port + 1`; fi
    gpg2 --homedir .$i --batch --passphrase "" --quick-gen-key "$i$url$uid" default default never
    gpg2 --homedir .$i --export-secret-key > $i/secring.gpg
    gpg2 --homedir .$i --export > $i/pubring.gpg
done
