#!/bin/sh

# Copyright 2017, Yahoo Holdings Inc.
# Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

mkdir -p run
cd run
export PATH=..:$PATH

gen.sh -uid "foo@example.com" bftkv.u01 bftkv.u02 bftkv.u03 bftkv.u99
gen.sh -port 5601 bftkv.rw01 bftkv.rw02 bftkv.rw03 bftkv.rw04 bftkv.rw05 bftkv.rw06
gen.sh -port 5701 bftkv.a01 bftkv.a02 bftkv.a03 bftkv.a04 bftkv.a05 bftkv.a06 bftkv.a07 bftkv.a08 bftkv.a09 bftkv.a10

clique.sh bftkv.a*

trust.sh bftkv.a04 bftkv.rw01
trust.sh bftkv.a05 bftkv.rw02
trust.sh bftkv.a06 bftkv.rw03
trust.sh bftkv.a07 bftkv.rw04
trust.sh bftkv.a08 bftkv.rw05
trust.sh bftkv.a09 bftkv.rw06
trust.sh bftkv.rw01 bftkv.a05 bftkv.a06 bftkv.a07
trust.sh bftkv.rw02 bftkv.a06 bftkv.a07 bftkv.a08
trust.sh bftkv.rw03 bftkv.a07 bftkv.a08 bftkv.a09
trust.sh bftkv.rw04 bftkv.a08 bftkv.a09 bftkv.a10
trust.sh bftkv.rw05 bftkv.a09 bftkv.a10 bftkv.a01
trust.sh bftkv.rw06 bftkv.a10 bftkv.a01 bftkv.a02

trust.sh -t signer bftkv.u01 bftkv.a01
trust.sh -t signer bftkv.u02 bftkv.a02
trust.sh -t signer bftkv.u03 bftkv.a03
trust.sh -t signer bftkv.u99 bftkv.a04

# for client certs
trust.sh -t signee bftkv.a04 bftkv.u01 bftkv.u02 bftkv.u03
trust.sh -t signee bftkv.a05 bftkv.u01 bftkv.u02 bftkv.u03
trust.sh -t signee bftkv.a06 bftkv.u01 bftkv.u02 bftkv.u03 
trust.sh -t signee bftkv.a07 bftkv.u01 bftkv.u02 bftkv.u03
# do not sign bftkv.u99 for testing
