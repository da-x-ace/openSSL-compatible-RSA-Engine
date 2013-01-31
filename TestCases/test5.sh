./mySSL -e -crt server.crt -in plainText -out myCipherText

openssl rsautl -decrypt -inkey server_private.key -in myCipherText -out myDecipheredText

diff plainText myDecipheredText
