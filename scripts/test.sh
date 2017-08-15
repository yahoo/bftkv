#!/bin/bash

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

cd run

SRC=../test.go
AOUT=./stresstest

go build -o $AOUT $SRC
if [ $? -ne 0 ]; then echo "build failed"; exit; fi

i=1
for k in gnupg.c*; do
    $AOUT -home $k -key "key2_$i" -n 10 -m 10 &
    i=`expr $i + 1`
done
