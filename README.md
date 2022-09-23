# OpenSSL-Encyption-Decryption

###File encryption/decryption/transmission suite akin to scp (using gcrypt libraries).

####Setup:

Primarily, you ought to have the openssl and libssl-dev library installed on your machine - I used an Ubuntu machine. On Ubuntu, open Terminal and run
sudo apt-get install libgcrypt11 libgcrypt11-dev gcc

Once you've installed the library, you can navigate to the folder where you have cloned this repo.
Run make on Terminal

The tool runs in two modes: local (-l) and network (-d) mode.

####Working in local mode: In local mode, you encrypt and store encrypted file(s) locally - in the same path where your source file is present. In local mode, the encrypted file will be stored in the following format : file_name.ufsec (Assuming the source file is named file_name.)

In order to encrypt file:

./ufsend file_name -l

In order to decrypt file:

./ufrec file_name.gt -l

####Working in network mode: In network mode, you must first run the decryption routine - it has to work like a daemon process before it can be in a position to accept request(s) (using sockets).

In order to run the decryption daemon:

./ufrec -d port_number

Once the decryption daemon is up, you can transmit the file via:

./ufsend file_name -d IP-address:port_number
