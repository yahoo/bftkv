#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

export CWD=`pwd`/
export PATH=$CWD:$PATH

HOST=localhost
if [ "$1" == "-host" ]; then shift; HOST=$1; shift; fi

WD="$1"
if [ "$WD" == "" ]; then WD="run"; fi
mkdir -p $WD/keys
cd $WD/keys

gen.sh -uid "foo@example.com" u01 u02 u03 u04
gen.sh -uid "bar@example.com" u11
gen.sh -url http://$HOST:5601 rw01 rw02 rw03 rw04 rw05 rw06
gen.sh -url http://$HOST:5701 a01 a02 a03 a04 a05 a06 a07 a08 a09 a10
gen.sh -url http://$HOST:5801 b01 b02 b03 b04 b05 b06 b07 b08 b09 b10

clique.sh a*
clique.sh b*

trust.sh -t signer rw01 a* b*
trust.sh -t signer rw02 a* b*
trust.sh -t signer rw03 a* b*
trust.sh -t signer rw04 a* b*
trust.sh -t signer rw05 a* b*
trust.sh -t signer rw06 a* b*

trust.sh -t signer u01 a0[1-6] rw*
trust.sh -t signer u02 a0[1-6] rw*
trust.sh -t signer u03 a0[1-6] rw*
trust.sh -t signer u04 a0[1-6] rw*
trust.sh -t signer u11 b0[1-6] rw*

# for client certs (do not sign u04 for TOFU testing)
trust.sh -t signee a07 u01 u02 u03
trust.sh -t signee a08 u01 u02 u03
trust.sh -t signee a09 u01 u02 u03 
trust.sh -t signee a10 u01 u02 u03
trust.sh -t signee b07 u11
trust.sh -t signee b08 u11
trust.sh -t signee b09 u11
trust.sh -t signee b10 u11

# for registration test
gen.sh -uid "test1@example.com" test1
