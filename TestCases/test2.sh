openssl genrsa -out private.pem 1024
openssl rsa -inform PEM -in private.pem -out public.pem -pubout


./mySSL -e -key public.pem -in plainText -out myCipherText

./mySSL -d -key private.pem -in myCipherText -out myDecipheredText

diff plainText myDecipheredText

rm -rf *.pem *.der myCipherText myDecipheredText
