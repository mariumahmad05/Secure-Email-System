import os
from Crypto.Cipher import AES

def aes_key_creation():
    aes_key = os.urandom(32)
    return aes_key

def aes_encryption_of_msg(msg,key):
    msg = msg.encode()
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(msg)
    return ciphertext , cipher.nonce

def aes_decryption_of_msg(ciphertext, nonce, key):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

leKey = aes_key_creation()
print("the key is: ")
print(leKey)

leData = "some more random words"
print(leData)
encrypted_text = aes_encryption_of_msg(leData,leKey)
print(encrypted_text)
decrypted_text = aes_decryption_of_msg(encrypted_text[0],encrypted_text[1],leKey)
print(decrypted_text)





