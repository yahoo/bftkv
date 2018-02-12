#!/bin/sh

NAME=$1
if [ "$NAME" == "" ]; then NAME="ca"; fi
openssl req -x509 -newkey RSA:2048 -subj '/CN=testca.example.com' -nodes -keyout $NAME.pkcs8 -out $NAME.x509 2> /dev/null
openssl x509 -pubkey -in $NAME.x509 -noout -out $NAME.pub
