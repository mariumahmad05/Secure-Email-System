import requests
from crypto_stub import *  

SERVER_URL = "http://127.0.0.1:5000" 

#  Register a new user
def register_user(username, public_key):
    data = {"username": username, "pubkey": public_key}
    try:
        r = requests.post(f"{SERVER_URL}/register", json=data)
        if r.status_code == 200:
            print(f"[+] {username} registered successfully.")
        else:
            print("[!] Registration failed:", r.text)
    except Exception as e:
        print("Error connecting to server:", e)


#  Get recipient's public key
def get_public_key(recipient):
    try:
        r = requests.get(f"{SERVER_URL}/pubkey/{recipient}")
        if r.status_code == 200:
            return r.json().get("pubkey")
        else:
            print("[!] Could not find user:", recipient)
            return None
    except Exception as e:
        print("Error connecting to server:", e)
        return None


#  Send encrypted message
def send_message(sender, recipient, subject, message, private_key, public_key):
    recipient_pub = get_public_key(recipient)
    if recipient_pub is None:
        print("[-] Cannot send. Recipient not found.")
        return

    # Encrypt the message (fake)
    iv, ciphertext = encrypt_aes(message)

    # Encrypt AES key (fake)
    encrypted_aes_key = rsa_encrypt("aes_key", recipient_pub)

    # Sign the message (fake)
    signature = sign_message(message, private_key)

    # Prepare JSON packet
    data = {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "iv": iv,
        "ciphertext": ciphertext,
        "enc_aes_key": encrypted_aes_key,
        "signature": signature,
        "timestamp": "now"
    }

    #  Send to server
    try:
        r = requests.post(f"{SERVER_URL}/send", json=data)
        if r.status_code == 200:
            print("[+] Message sent successfully!")
        else:
            print("[!] Failed to send message:", r.text)
    except Exception as e:
        print("Error sending message:", e)


#  Fetch inbox messages
def fetch_inbox(username, private_key):
    try:
        r = requests.get(f"{SERVER_URL}/inbox/{username}")
        if r.status_code != 200:
            print("[!] Failed to fetch inbox:", r.text)
            return

        inbox = r.json().get("inbox", [])
        if not inbox:
            print("[i] Inbox is empty.")
            return

        print(f"\n=== Inbox of {username} ===")
        for i, msg in enumerate(inbox, start=1):
            print(f"\nMessage #{i}")
            print(f"From: {msg['sender']}")
            print(f"Subject: {msg['subject']}")

            # Decrypt and verify (fake)
            plaintext = decrypt_aes(msg['iv'], msg['ciphertext'])
            verified = verify_signature(plaintext, msg['signature'], "sender_public_key")

            print("Message:", plaintext)
            print("Signature OK:", verified)

    except Exception as e:
        print("Error connecting to server:", e)



# demo
print("=== Secure Email System (Simplified Client) ===")

# Keys (fake)
private_key = "my_private_key"
public_key = "my_public_key"

# Register two users
register_user("alice", public_key)
register_user("bob", public_key)

# Alice sends a message to Bob
print("\n[Demo] Alice -> Bob")
send_message("alice", "bob", "Hello Bob", "This is a secret message!", private_key, public_key)

# Bob checks inbox
print("\n[Demo] Bob checks inbox")
fetch_inbox("bob", private_key)
