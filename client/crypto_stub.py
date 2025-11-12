# crypto_stub.py
def encrypt_aes(plaintext):
    iv = "fake_iv"
    ciphertext = "encrypted(" + plaintext + ")"
    return iv, ciphertext

def decrypt_aes(iv, ciphertext):
    return ciphertext.replace("encrypted(", "").replace(")", "")

def rsa_encrypt(data, public_key):
    return "rsa_encrypted_key"

def rsa_decrypt(data, private_key):
    return "aes_key"

def sign_message(data, private_key):
    return "signature123"

def verify_signature(data, signature, public_key):
    return True
