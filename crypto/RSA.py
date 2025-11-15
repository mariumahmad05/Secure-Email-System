import math
from pydoc import plain

from Crypto.Util import number
import random

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

def rsa_encryption(msg,pub_key):
    msg_encoded = [ord(c) for c in msg]
    cipher = [sqm(c,pub_key[1],pub_key[0]) for c in msg_encoded]
    return cipher

def rsa_decrypt(cipher, private_key):
    cipher_encoded = [sqm(c, private_key[1], private_key[0]) for c in cipher]
    decrypted_text = "".join (chr(ch) for ch in cipher_encoded)
    return decrypted_text

# for registration, the client will create variable in its dictionary that
# will take 3 variable, the username , the public key and private key
user_name,pub_key,priv_key = create_keys("sam")

# for testing, will remove in the end
msg1 = "Insert you msg here"
print(msg1)
cipherMsg = rsa_encryption(msg1,pub_key)
print(cipherMsg)

leplain = rsa_decrypt(cipherMsg,priv_key)

print(leplain)
