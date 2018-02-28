#!/bin/bash

#Sample script to verify ServerKeyExcahnge SSL packet's signature
#more info at https://security.stackexchange.com/questions/143213/how-to-verify-a-server-key-exchange-packet

#Required Files in start
#temp1.raw //ClientHello.Random
#temp2.raw //ServerHello.Random
#temp3.raw //ServerKeyExchange Message Exported from wireshark(bytes written to file)
#tempk.raw //subjectPublicKeyInfo from certificate
#temp.sig  //Signature

#Steps
openssl pkey -inform der -in tempk.raw -pubin >tempk.pem
cat temp[12].raw >temp.dat
dd if=temp3.raw bs=1 skip=4 count=36 status=none >>temp.dat
openssl sha256 <temp.dat -verify tempk.pem -signature temp.sig

rm -f temp.dat tempk.pem