#! /bin/sh

openssl req -out my.crt -outform PEM -x509 -newkey rsa -sha256 -days 3650 -extensions v3_ca -config mycert-req.txt

