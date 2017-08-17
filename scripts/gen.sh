#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

port=0
if [ "$1" == "-port" ]; then shift; port=$1; shift; fi

uid=""
if [ "$1" == "-uid" ]; then shift; uid=" <$1>"; shift; fi

for i in "$@"; do
    mkdir -p $i $i.2
    chmod 700 $i $i.2
    addr=""
    if [ $port -ne 0 ]; then addr=" (http://localhost:$port)"; port=`expr $port + 1`; fi
    gpg2 --homedir $i.2 --batch --passphrase "" --quick-gen-key "$i$addr$uid" default default never
    gpg2 --homedir $i.2 --export-secret-key | gpg --homedir $i --fast-import
    gpg2 --homedir $i.2 --export | gpg --homedir $i --fast-import
    rm -fr $i.2
done
