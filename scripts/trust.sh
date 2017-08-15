#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

signer=$1
shift

if [ "$signer" == "" ]; then echo "$0 signer signee..."; exit; fi

for i in "$@"; do
    sign.sh $signer $i | gpg --homedir $i --batch --no-tty --fast-import > /dev/null 2>&1
    if [ $? -ne 0 ]; then echo "$0: failed" 1>&2; fi
done
