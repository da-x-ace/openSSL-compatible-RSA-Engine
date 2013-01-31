./mySSL genrsa private.pem public.pem

./mySSL -e -key public.pem -in plainText -out myCipherText

./mySSL -d -key private.pem -in myCipherText -out myDecipheredText

diff plainText myDecipheredText

rm -rf *.pem *.der myCipherText myDecipheredText
