#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

port=0
if [ "$1" == "-port" ]; then shift; port=$1; shift; fi

uid=""
if [ "$1" == "-uid" ]; then shift; uid=" <$1>"; shift; fi

for i in "$@"; do
    rm -fr $i .$i
    mkdir -p $i .$i
    chmod 700 $i .$i
    addr=""
    if [ $port -ne 0 ]; then addr=" (http://localhost:$port)"; port=`expr $port + 1`; fi
    gpg2 --homedir .$i --batch --passphrase "" --quick-gen-key "$i$addr$uid" default default never
    gpg2 --homedir .$i --export-secret-key > $i/secring.gpg
    gpg2 --homedir .$i --export > $i/pubring.gpg
done
