all:
	g++ -g main.cpp -o mySSL -lgmp -lcrypto

clean:
	rm -rf encode *.der *.pem
