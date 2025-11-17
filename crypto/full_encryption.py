
import os # to access .urandom() to create random bytes for more security
from Crypto.Cipher import AES

import math
from Crypto.Util import number
import random
import ast

from Crypto.Hash import SHA256


# ================================================== AES Encryption ==================================================

# AES key generator
# create a random AES key 32 bytes - 256 bits, takes nothing ---> returns the key
def aes_key_creation():
    aes_key = os.urandom(32)
    return aes_key

# AES encryption
# takes the message AND the AES key ---> returns the cipher text and a nonce that is needed for decryption
def aes_encryption_of_msg(msg,key):
    msg = msg.encode()
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(msg)
    return ciphertext , cipher.nonce

# AES Decryption
# takes the cipher text, nonce AND the AES key ---> returns the Original text - message -
def aes_decryption_of_msg(ciphertext, nonce, key):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    message = cipher.decrypt(ciphertext)
    return message.decode()
# ====================================================================================================================

# ================================================== RSA Encryption ==================================================

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

# Extended GCD
def extendedGCD(a,b):
    coef_2=(1,0)
    coef_1=(0,1)
    while b!=0:
        quotient=a//b
        (a,b)=(b,a%b)
        (coef_2,coef_1)=(coef_1,(coef_2[0]-quotient*coef_1[0],coef_2[1]-quotient*coef_1[1]))
    return a,coef_2[0],coef_2[1]

# Inverse for private key
def inverseMod(a,m):
    gcd,inv,_=extendedGCD(a,m)
    if gcd != 1:
        raise Exception("Error, "+str(a)+" does not admit an inverse mod "+str(m))
    return inv%m

# RSA key generator
# takes the user-name ---> returns the user-name, the Public key and the private key
# public key = (n,e)
# private key = (n,d), while private key should only = d, I added n for easier decryption and it won't compromise security since n is public

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
# takes the message, public key ---> return ciper text type(list|string) for decryption
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
# takes the ciper text AND private key ---> return the original AES key type(bytes)
def rsa_aes_decrypt(cipher, priv_key):
    cipher_encoded = [sqm(c, priv_key[1], priv_key[0]) for c in cipher]
    decrypted_text = "".join (chr(ch) for ch in cipher_encoded)
    decrypted_key = ast.literal_eval(decrypted_text)
    return decrypted_key

# RSA Decryption for String
# takes the ciper text AND key ---> return the original message type(string)
def rsa_str_decrypt(cipher, key):
    cipher_encoded = [sqm(c, key[1], key[0]) for c in cipher]
    decrypted_text = "".join (chr(ch) for ch in cipher_encoded)
    return decrypted_text

# ====================================================================================================================

# ================================================== Hash function ===================================================

# Hash SHA256
# takes the message ---> returns the digest
def hash_string_sha256(string):
    h = SHA256.new()
    h.update(string.encode('utf-8'))
    return h.hexdigest()

''' 
====================================================================================================================
=================================================== Instructions ===================================================
====================================================================================================================

* for Registration: 
1. use create_keys( user-name ).
2. save user-name, public and private key at client for easier encryption/decryption later.
3. send the user-name and public key to the Server.

--------------------------------------------------------------------------------------------------------------------

* for Sending a message:
1. use aes_key_creation() to generate an AES session key.
2. use aes_encryption_of_msg() to encrypt the message using that AES key, and keep the nonce for decryption.
3. use rsa_encryption() with the Receivers Public key to encrypt the AES session key. 
4. use hash_string_sha256() to hash the message.
5. use rsa_encryption() with the Senders Private key to encrypt the digest of the hashed message.
6. client sends to the server : 
                a) AES key encrypted by Receivers public key to be decrypted by the Receivers private key.
                b) nonce.
                c) encrypted message by the AES key.
                d) Digital signature (steps 4 and 5).
                e) Metadata (sender, recipient, timestamp, etc.).

--------------------------------------------------------------------------------------------------------------------

* for Receiving a message:
1. Receiver use rsa_aes_decrypt() using their private key to get the AES session key.
2. Receiver use aes_decryption_of_msg() to decrypt the message using that AES key AND nonce.<------
3. to verify integrity and authenticity:
                a) use hash_string_sha256() to hash the received message to get digest-1.
                b) use rsa_str_decrypt() using the Senders public key to get digest-2.
                c) compare digest-1 with digest-2.
                d) if the digests match, then the message is verified (authentic and untampered).
                e) if the digests do not match, then signature is  invalid or the there is a message tampering.
'''