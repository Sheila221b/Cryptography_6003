# GCD IMPLEMENT - EUCLIDEAN ALGORITHM
def findgcd(a, b):
    while a % b != 0:
        a = max(abs(a-b), min(a, b))
        b = min(abs(a-b), min(a, b))
    print(b)

def mainGcd():
    [A, B] = [int(i) for i in input("Please enter 2 numbers which you want to find gcd.").split()]
    if A % B == 0:
        print(B)
    elif B % A == 0:
        print(A)
    else:
        findgcd(A, B)

# Vignere for alphabet substitution
class Vigenere:
    def __init__(self, key):
        self.key = key.upper()
        self.length = len(key)
    def encrypt(self, message):
        cipher = ""
        temp_message = message.upper()
        for i, m in enumerate(temp_message):
            new_mes_ind = (ord(self.key[i % self.length]) + ord(m)-128) % 26 + 64
            if new_mes_ind == 64:
                new_mes_ind = 90
            flag = message[i].isupper()
            if flag:
                cipher += chr(new_mes_ind)
            else:
                cipher += chr(new_mes_ind).lower()
        return cipher
    def decrypt(self, cipher):
        message = ""
        temp_cipher = cipher.upper()
        for i, c in enumerate(temp_cipher):
            new_cip_ind = (-ord(self.key[i % self.length]) + ord(c)) % 26 + 64
            if new_cip_ind == 64:
                new_cip_ind = 90
            flag = cipher[i].isupper()
            if flag:
                message += chr(new_cip_ind)
            else:
                message += chr(new_cip_ind).lower()
        return message

def mainVigenere():
    key = "begformercy"
    testV = Vigenere(key)
    enc = testV.encrypt("SherlockHolmes")
    dec = testV.decrypt(enc)
    print("key: ", key)
    print("encryption: ", enc)
    print("decryption: ", dec)
