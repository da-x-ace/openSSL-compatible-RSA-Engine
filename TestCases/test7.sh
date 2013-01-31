./mySSL -s -key server_private.key -in plainText -out mySignText

./mySSL -v -crt server.crt -signature mySignText plainText

rm -rf mySignText

openssl dgst -sha1 -sign server_private.key -out mySignText plainText

./mySSL -v -crt server.crt -signature mySignText plainText
rm -rf *.pem *.der mySignText


