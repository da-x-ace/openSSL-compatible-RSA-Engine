./mySSL genrsa private.pem public.pem


./mySSL -e -key public.pem -in plainText -out myCipherText

openssl rsautl -decrypt -inkey private.pem -in myCipherText -out myDecipheredText

diff plainText myDecipheredText
rm -rf myCipherText myDecipheredText
openssl rsautl -encrypt -inkey public.pem -pubin -in plainText -out myCipherText

./mySSL -d -key private.pem -in myCipherText -out myDecipheredText

diff plainText myDecipheredText
rm -rf *.pem *.der myCipherText myDecipheredText


