from Crypto.Hash import SHA256

hash_word = "the last random thing"

def hash_string_sha256(string):
    h = SHA256.new()
    h.update(string.encode('utf-8'))
    return h.hexdigest()

# Testing to check if both results are the same
print(hash_string_sha256(hash_word))
h_test = SHA256.new()
h_test.update(b"the last random thing")
print(h_test.hexdigest())