#!/bin/sh
openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365
openssl req -x509 -newkey rsa:4096 -nodes -out selfclient.crt -keyout selfclient.key -days 365

openssl req -new -newkey rsa:1024 -nodes -out caclient.csr -keyout caclient.key
openssl x509 -trustout -signkey caclient.key -days 365 -req -in caclient.csr -out caclient.crt

openssl genrsa -out client.key 1024
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA caclient.crt -CAkey caclient.key -set_serial 01 -out client.crt
