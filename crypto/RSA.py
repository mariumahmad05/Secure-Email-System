import math
from Crypto.Util import number
import random
import ast
import os


#Generate Random Prime numbers
def generate_prime (bits):
    prime = number.getPrime(bits)
    return prime

# Square and Multiply
def sqm(a, e, m):
    base = a
    power = e
    mod = m
    exBin = bin(power)[2:]
    result = 1
    for i in exBin:
        if i == "1" :
            result = ((result**2) * base) % mod
        else:
            result = (result**2) % mod
    return result


def extendedGCD(a,b):
    coef_2=(1,0)
    coef_1=(0,1)
    while b!=0:
        quotient=a//b
        (a,b)=(b,a%b)
        (coef_2,coef_1)=(coef_1,(coef_2[0]-quotient*coef_1[0],coef_2[1]-quotient*coef_1[1]))
    return a,coef_2[0],coef_2[1]

def inverseMod(a,m):
    gcd,inv,_=extendedGCD(a,m)
    if gcd != 1:
        raise Exception("Error, "+str(a)+" does not admit an inverse mod "+str(m))
    return inv%m

def create_keys(name):
    p = generate_prime(1024)
    q = generate_prime(1024)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = random.randint(3,phi_n - 1)
    while math.gcd(e, phi_n) != 1:
        e = random.randint(3,phi_n - 1)
    d = inverseMod(e, phi_n)

    pk= (n,e)
    sk = (n,d)
    return name,pk,sk

# RSA Encryption for string and AES key
# return list of strings
def rsa_encryption(msg,pub_key):
    if type(msg) is str:
        msg_encoded = [ord(c) for c in msg]
        cipher = [sqm(c,pub_key[1],pub_key[0]) for c in msg_encoded]
        return cipher
    else:
        msg_to_str = str(msg)
        msg_encoded = [ord(c) for c in msg_to_str]
        cipher = [sqm(c, pub_key[1], pub_key[0]) for c in msg_encoded]
        return cipher

# RSA Decryption for AES key
def rsa_aes_decrypt(cipher, priv_key):
    cipher_encoded = [sqm(c, priv_key[1], private_key[0]) for c in cipher]
    decrypted_text = "".join (chr(ch) for ch in cipher_encoded)
    decrypted_key = ast.literal_eval(decrypted_text)
    return decrypted_key

# RSA Decryption for String
def rsa_str_decrypt(cipher, priv_key):
    cipher_encoded = [sqm(c, priv_key[1], private_key[0]) for c in cipher]
    decrypted_text = "".join (chr(ch) for ch in cipher_encoded)
    return decrypted_text

# for registration, the client will create variable in its dictionary that
# will take 3 variable, the username , the public key and private key
user_name, public_key, private_key = create_keys("sam")

# creating an random AES key of size 32 bytes = AES-256
def aes_key_creation():
    aes_key = os.urandom(32)
    return aes_key

#Testing AES key encryption / decryption and making sure the decryption function returns a type(Byte)
data = aes_key_creation()
print(data)
encrypted_aes_key_rsa = rsa_encryption(data,public_key)
print(encrypted_aes_key_rsa)
decrypted_aes_key_rsa = rsa_aes_decrypt(encrypted_aes_key_rsa,private_key)
print(decrypted_aes_key_rsa)

#Testing String encryption / decryption and making sure the decryption function returns the original String

data_string = "some random words"
print(data_string)
encrypted_string_rsa = rsa_encryption(data_string,public_key)
print(encrypted_string_rsa)
decrypted_string_rsa = rsa_str_decrypt(encrypted_string_rsa,private_key)
print(decrypted_string_rsa)

#msg1 = "Insert you msg here"
#print(msg1)
#cipherMsg = rsa_str_encryption(msg1,public_key)
#print(cipherMsg)

#leplain = rsa_str_decrypt(cipherMsg,private_key)
#print(leplain)