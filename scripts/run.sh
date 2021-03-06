#!/bin/bash

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

WS_ADDR=5001
if [ "$1" == "-novisual" ]; then shift; WS_ADDR=0; fi

if [ "$GOPATH" == "" ]; then export GOPATH=~/go; fi

APP=$GOPATH/src/github.com/yahoo/bftkv
MAIN=$APP/cmd/main.go
AOUT=./bftkv

go build -o $AOUT $MAIN
if [ $? -ne 0 ]; then echo "build failed"; exit; fi

FAILURE_NODES=()

function is_failure {
    for n in ${FAILURE_NODES[@]}; do if [ "$n" == "$1" ]; then return 0; fi; done
    return 1
}


API_ADDR=6001
i=1
JOBS=""
for key in keys/{u*,a*,b*,rw*}; do
    GPGHOME=`basename $key`
    if is_failure $GPGHOME; then continue; fi
    DB=db.$GPGHOME
    mkdir -p $DB
    $AOUT -home $key -api $API_ADDR -ws $WS_ADDR -db $DB &
    JOBS="$JOBS %$i"
    API_ADDR=`expr $API_ADDR + 1`
    if [ $WS_ADDR -ne 0 ]; then WS_ADDR=`expr $WS_ADDR + 1`; fi
    i=`expr $i + 1`
done

trap "kill $JOBS; exit" SIGINT SIGTERM

while true; do sleep 60; done
