# coding:utf-8
"""
Author  : XINRAN HU
Student ID  : G2403080B
Time    : 2024/10/25
Desc:
"""
import os

from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.Cipher.AES import MODE_GCM
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_v1_5

CURRENT_WORK_DIR = os.getcwd()
OUTPUT_DIR = os.path.join(CURRENT_WORK_DIR)


def hash_file_sha_512(file_name):
    with open(os.path.join(CURRENT_WORK_DIR,file_name), "rb") as f:
        digest = SHA512.new(f.read())
    with open(os.path.join(OUTPUT_DIR, "digest_file.hex"), "w") as f:
        f.write(digest.hexdigest())
    return digest.hexdigest()

#   hash_file_sha_512("plaintext_file.pdf")

def generate_rsa_key_pair_4096():
    random_generator = Random.new().read
    rsa = RSA.generate(4096, random_generator)
    public_key = rsa.publickey().exportKey("PEM")
    private_key = rsa.exportKey("PEM")
    with open(os.path.join(OUTPUT_DIR, "RSA_private_key.pem"), "wb") as f:
        f.write(private_key)
    with open(os.path.join(OUTPUT_DIR, "RSA_public_key.pem"), "wb") as f:
        f.write(public_key)
    return private_key, public_key

#   generate_rsa_key_pair_4096()

def generate_aes_key_256():
    aes_key_bytes = Random.get_random_bytes(32)
    binary_list = []
    for num in list(aes_key_bytes):
        binary_list.append(bin(num)[2:].zfill(8))
    aes_key = ''.join(binary_list)
    with open(os.path.join(OUTPUT_DIR, "AES_key.txt"), "w") as f:
        f.write(aes_key)
    return aes_key_bytes

#   generate_aes_key_256()

def rsa_sign_and_verify(plaintext_file, rsa_pub_key_file, rsa_pri_key_file):
    private_key = RSA.importKey(open(rsa_pri_key_file).read())
    public_key = RSA.importKey(open(rsa_pub_key_file).read())
    signer = PKCS1_v1_5.new(private_key)
    with open(os.path.join(CURRENT_WORK_DIR, plaintext_file), "rb") as f:
        hashed_text = SHA512.new(f.read())
    signature = signer.sign(hashed_text)
    with open(os.path.join(OUTPUT_DIR, "signed_file"), "wb") as f:
        f.write(signature)
    verifier = PKCS1_v1_5.new(public_key)
    if verifier.verify(hashed_text, signature):
        print("Signature verified")
        return True
    print("Failed to verify signature")
    return False


def rsa_encrypt_aes_key(aes_key, rsa_pub_key_file):
    public_key = RSA.importKey(open(rsa_pub_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    with open(os.path.join(OUTPUT_DIR, "encrypted_AES_key.txt"), "wb") as f:
        f.write(encrypted_aes_key)
    return encrypted_aes_key


#print(rsa_encrypt_aes_key(AES_KEY, "RSA_public_key.pem"))

def rsa_decrypt_aes_key(encrypted_aes_key, rsa_pri_key_file):
    private_key = RSA.importKey(open(rsa_pri_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_aes_key_byte = cipher_rsa.decrypt(encrypted_aes_key)
    binary_list = []
    for num in list(decrypted_aes_key_byte):
        binary_list.append(bin(num)[2:].zfill(8))
    decrypted_aes_key = ''.join(binary_list)
    with open(os.path.join(OUTPUT_DIR, "decrypted_AES_key.txt"), "w") as f:
        f.write(decrypted_aes_key)
    return decrypted_aes_key

#   print(rsa_decrypt_aes_key(open("encrypted_AES_key.txt", "rb").read(), "RSA_private_key.pem"))

#   nonce = Random.get_random_bytes(12)

def aes_encrypt_plaintext_file(plaintext_file, aes_key, nonce):
    cipher_aes = AES.new(aes_key, MODE_GCM, nonce)           #GCM MODE
    cipher_text = cipher_aes.encrypt(open(plaintext_file, "rb").read())
    with open(os.path.join(OUTPUT_DIR, "ciphertext_file"), "wb") as f:
        f.write(cipher_text)
    return cipher_text

#   aes_encrypt_plaintext_file("plaintext_file.pdf", aes_key, nonce)

def aes_decrypt(ciphertext_file, aes_key, nonce):
    with open(ciphertext_file, "rb") as f:
        cipher_text = f.read()
    cipher_aes = AES.new(aes_key, MODE_GCM, nonce)
    plain_text = cipher_aes.decrypt(cipher_text)
    with open(os.path.join(OUTPUT_DIR, "decrypted_file.pdf"), "wb") as f:
        f.write(plain_text)
    with open(os.path.join(OUTPUT_DIR, "digest_decrypted_file.hex"), "w") as f:
        f.write(SHA512.new(plain_text).hexdigest())
    return plain_text

#   aes_decrypt("ciphertext_file.txt", aes_key, nonce)



if  '__main__' == __name__:


    '''
    Step 1 Hash plaintext_file using sha-512
    Output: digest_file.hex
    '''
    hash_file_sha_512("plaintext_file.pdf")

    '''
    Step 2 generate rsa key pair
    Output: RSA_private_key.pem， RSA_public_key.pem
    '''
    generate_rsa_key_pair_4096()

    '''
    Step 3 rsa sign and verify
    Output: signed_file
    Print: Verification Result(
    "Signature verified" if succeed, else"Failed to verify signature")
    '''
    rsa_sign_and_verify("plaintext_file.pdf", os.path.join(OUTPUT_DIR, "RSA_public_key.pem"),
                        os.path.join(OUTPUT_DIR, "RSA_private_key.pem"))

    '''
    Step 4 generate aes key 256
    Output: AES_key.txt (Binary string)
    Return: AES_KEY(32 Bytes)
    '''
    AES_KEY = generate_aes_key_256()

    '''
    Step 5 RSA encrypt AES key (Exchange Session Key)
    Param: AES_KEY, rsa_pub_key_file
    Output: encrypted_AES_key.txt
    Return: cipher_text
    '''
    cipher_text = rsa_encrypt_aes_key(AES_KEY, os.path.join(OUTPUT_DIR, "RSA_public_key.pem"))

    '''
    Step 6 RSA decrypt AES key (Exchange Session Key)
    Param: encrypted_AES_key, rsa_pri_key_file
    Output: decrypted_AES_key.txt(Binary string)
    Return: decrypted_AES_key
    '''
    decrypted_AES_key = rsa_decrypt_aes_key(open(os.path.join(OUTPUT_DIR, "encrypted_AES_key.txt"), "rb").read(),
                                            os.path.join(OUTPUT_DIR, "RSA_private_key.pem"))

    '''
    Step 7 AES encrypt plain text file
    Param: plaintext_file, aes_key, nonce(MODE, GCM)
    Output: ciphertext_file.txt
    Return: cipher_text
    '''
    NONCE = Random.get_random_bytes(12)
    aes_cipher_text = aes_encrypt_plaintext_file(os.path.join(CURRENT_WORK_DIR, "plaintext_file.pdf"), AES_KEY, NONCE)

    '''
    Step 8 AES decrypt ciphertext file
    Param: ciphertext_file, aes_key, nonce
    Output: decrypted_file.pdf, digest_decrypted_file.hex
    Return plain_text
    '''
    plain_text = aes_decrypt(os.path.join(OUTPUT_DIR, "ciphertext_file"), AES_KEY, NONCE)