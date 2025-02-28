# Secure-Files
 A way to store files securely
 
All files are encrypted using AES-256
AES-256 key derivation is done from the user password

User password (Cleartext)
Argon2 Hash of the Password [16 iterations, 4 threads, 65536 kibibytes memory cost, 1024 bits random salt, 512 bits hash size, 4 threads)
SHA3-256 Hash with a seperate salt of the Argon2 Hash (USED AS THE KEY)
It takes ~400ms to obtain a single key (tested on intel i5 8th gen 3.4 ghz)

There is a file overhead of ~396 bytes for every file which is for storing the salts and nonce used in key derivation and AES encryption







