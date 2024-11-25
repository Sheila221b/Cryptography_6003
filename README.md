Code for a hands on assignment

Step 1 : choose a  plaintext_file

Step 2 : hash plaintext_file using sha-512, output digest_file.hex in hexadecimal format

Step 3 : generate rsa-4096 key pair, output RSA_public_key.pem & RSA_private_key.pem

Step 4 : sign plaintext_file with RSA_private_key above and output signed_file, then verify by using public key

Step 5 : generate AES-256 key and output the binary string as AES_key.txt

Step 6 : encrypt AES key using RSA public key and output as encrypted_AES_key.txt

Step 7 :  decrypt encrypted_AES_key.txt using RSA private key and output as a binary string "decrypted_AES_key.txt"

Step 8 : encrypt plaintext_file using AES key with any mode(GCM)

Step 9 : output ciphertext_file and specify chosen mode of operation

Step 10 : decrypt ciphertext_file and save as decrypted_file

Step 11 : output sha-512 digest of decrypted_file in hexadecimal, as digest_decrypted_file.hex

