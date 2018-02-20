#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

if [ -x "$(command -v gpg2)" ]; then
    GPG=gpg2
elif [ -x "$(command -v gpg)" ]; then
    gpg --version | head -1 | grep ' 2\.' >/dev/null 2>&1
    if [ $? -ne 0 ]; then echo "gpg needs to be version 2.x"; exit 1; fi
    GPG=gpg
else
    echo "gpg: not found" exit 1
fi
