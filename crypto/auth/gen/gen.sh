#!/bin/sh

openssl gendh 2048 | ./dhdump
