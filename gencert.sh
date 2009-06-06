#!/bin/bash

cd `dirname $0`
openssl genrsa 1024 > server.key
openssl req -batch -new -x509 -nodes -sha1 -days 365 -key server.key > server.cert

