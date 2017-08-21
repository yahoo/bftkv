#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

for i in "$@"; do
    av=()
    for j in "$@"; do
	if [ $j != $i ]; then av=(${av[@]} $j); fi
    done
    trust.sh -t signee $i ${av[@]}
done

for i in "$@"; do
    av=()
    for j in "$@"; do
	if [ $j != $i ]; then
	    gpg --homedir $j --export $j | gpg --homedir $i --batch --no-tty --fast-import > /dev/null 2>&1
	fi
    done
done
