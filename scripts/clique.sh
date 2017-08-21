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
	    gpg2 --homedir .$j --export `basename $j` | gpg2 --homedir .$i --batch --no-tty --fast-import > /dev/null 2>&1
	fi
    done
    gpg2 --homedir .$i --batch --no-tty --export > $i/pubring.gpg
done
