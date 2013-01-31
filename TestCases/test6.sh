./mySSL genrsa private.pem public.pem


./mySSL -s -key private.pem -in plainText -out mySignText

openssl dgst -sha1 -verify public.pem -signature mySignText plainText

rm -rf mySignText

openssl dgst -sha1 -sign private.pem -out mySignText plainText

./mySSL -v -key public.pem -signature mySignText plainText

rm -rf *.pem *.der mySignText


