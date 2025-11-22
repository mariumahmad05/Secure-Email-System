import sys
import os
import json
import base64
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests

# Import crypto functions
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
from crypto.full_encryption import *

# Files & Server
SERVER_URL = "http://127.0.0.1:5000"
USER_STORE = os.path.join(PROJECT_ROOT, "client", "users.json")


#   AES encryption for PRIVATE KEY STORAGE

def encrypt_private_key(sk, password):
    """
    Encrypt the RSA private key (sk) using a key derived from the password.
    - Derive AES key from SHA-256(password) hex digest -> 32 bytes
    - Use the aes_encryption_of_msg (AES-CTR) to encrypt JSON(sk)
    - Store nonce and ciphertext as base64 strings
    """
    # SHA-256(password) returns hex string (64 chars -> 32 bytes)
    key_hex = hash_string_sha256(password)        
    aes_key = bytes.fromhex(key_hex)             

    # Convert private key tuple to JSON string
    plaintext = json.dumps(sk)                    

    # Encrypt using your AES wrapper
    ciphertext, nonce = aes_encryption_of_msg(plaintext, aes_key)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "cipher": base64.b64encode(ciphertext).decode()
    }


def decrypt_private_key(enc, password):
    """
    Decrypt the RSA private key encrypted with encrypt_private_key.
    - Derive AES key again from SHA-256(password)
    - Base64 decode nonce and ciphertext
    - Decrypt using aes_decryption_of_msg
    - Parse JSON back to Python object (sk)
    """
    key_hex = hash_string_sha256(password)
    aes_key = bytes.fromhex(key_hex)

    nonce = base64.b64decode(enc["nonce"])
    cipher_bytes = base64.b64decode(enc["cipher"])

    plaintext = aes_decryption_of_msg(cipher_bytes, nonce, aes_key)  
    return json.loads(plaintext)


#   LOCAL USER STORAGE
def load_users():
    if not os.path.exists(USER_STORE):
        return {}
    return json.load(open(USER_STORE))


def save_users(data):
    json.dump(data, open(USER_STORE, "w"), indent=4)


#   SERVER API CALLS
def api_register(username, password, pubkey):
    body = {"username": username, "password": password, "pubkey": pubkey}
    try:
        r = requests.post(f"{SERVER_URL}/register", json=body)
        return r.status_code
    except:
        return None


def api_login(username, password):
    try:
        r = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
        if r.status_code == 200:
            return r.json().get("pubkey")
        return None
    except:
        return None


def api_get_pubkey(username):
    try:
        r = requests.get(f"{SERVER_URL}/pubkey/{username}")
        if r.status_code == 200:
            return r.json()["pubkey"]
        return None
    except:
        return None


def api_send(data):
    try:
        r = requests.post(f"{SERVER_URL}/send", json=data)
        return r.status_code == 200
    except:
        return False


def api_inbox(username):
    try:
        r = requests.get(f"{SERVER_URL}/inbox/{username}")
        if r.status_code == 200:
            return r.json()["inbox"]
        return []
    except:
        return []


#   SESSION VARIABLES
LOGGED_IN = None
PRIVATE_KEY = None
PUBLIC_KEY = None


def get_username():
    return LOGGED_IN if LOGGED_IN else ""


#   REGISTER / LOGIN / LOGOUT
def register_user(username, password):
    """
    - Generate RSA keys (create_keys)
    - Encrypt private key with password (AES-CTR + SHA-256)
    - Store encrypted private key + public key in users.json
    - Send username + password + pubkey to server
    """
    global LOGGED_IN, PRIVATE_KEY, PUBLIC_KEY

    users = load_users()
    if username in users:
        return False, "Already registered locally."

    # create RSA keys
    _, pk, sk = create_keys(username)

    # encrypt private key locally
    encrypted_sk = encrypt_private_key(sk, password)
    users[username] = {
        "public_key": pk,
        "encrypted_private_key": encrypted_sk
    }
    save_users(users)

    result = api_register(username, password, pk)
    if result == 200:
        LOGGED_IN = username
        PRIVATE_KEY = sk
        PUBLIC_KEY = pk
        return True, "Registration successful."

    return False, "Server error."


def login_user(username, password):
    """
    - Check user exists locally
    - Ask server to verify username + password
    - Decrypt private key from users.json using password
    """
    global LOGGED_IN, PRIVATE_KEY, PUBLIC_KEY

    users = load_users()
    if username not in users:
        return False, "User not registered locally."

    server_pub = api_login(username, password)
    if server_pub is None:
        return False, "Wrong password or user not on server."

    # decrypt local private key
    try:
        PRIVATE_KEY = decrypt_private_key(users[username]["encrypted_private_key"], password)
    except Exception:
        return False, "Incorrect password (local decryption failed)."

    PUBLIC_KEY = users[username]["public_key"]
    LOGGED_IN = username

    return True, "Login successful."


def logout_user():
    global LOGGED_IN, PRIVATE_KEY, PUBLIC_KEY
    LOGGED_IN = None
    PRIVATE_KEY = None
    PUBLIC_KEY = None


#   SECURE EMAIL SYSTEM
def send_secure_message(to_user, subject, msg_text):
    """
    - Get recipient's public key from server
    - Generate AES session key
    - Encrypt message with AES 
    - Encrypt AES key with RSA (recipient's pk)
    - Create digital signature = RSA_encrypt(hash(msg), sender sk)
    - Send everything to server
    """
    recipient_pub = api_get_pubkey(to_user)
    if not recipient_pub:
        return False, "Recipient not found."

    # AES key for message
    aes_key = aes_key_creation()

    # encrypt message
    ciphertext, nonce = aes_encryption_of_msg(msg_text, aes_key)

    # encrypt AES key with RSA
    enc_key = rsa_encryption(aes_key, recipient_pub)

    # sign message
    digest = hash_string_sha256(msg_text)
    signature = rsa_encryption(digest, PRIVATE_KEY)

    packet = {
        "sender": LOGGED_IN,
        "recipient": to_user,
        "subject": subject,
        "iv": list(nonce),
        "ciphertext": list(ciphertext),
        "enc_aes_key": enc_key,
        "signature": signature,
        "timestamp": "now"
    }

    ok = api_send(packet)
    return ok, "Sent." if ok else "Failed."


def fetch_user_inbox():
    """
    For each message:
    - Decrypt AES key using RSA (recipient's sk)
    - Decrypt ciphertext using AES 
    - Verify digital signature:
        hash(plaintext) == RSA_decrypt(signature, sender pk)
    """
    inbox = api_inbox(LOGGED_IN)
    output = ""

    for msg in inbox:
        sender = msg["sender"]
        subject = msg["subject"]

        ciphertext = bytes(msg["ciphertext"])
        nonce = bytes(msg["iv"])

        # Decrypt AES key
        aes_key = rsa_aes_decrypt(msg["enc_aes_key"], PRIVATE_KEY)

        # Decrypt message
        plaintext = aes_decryption_of_msg(ciphertext, nonce, aes_key)

        # Verify signature
        sender_pub = api_get_pubkey(sender)
        digest_local = hash_string_sha256(plaintext)
        digest_sender = rsa_str_decrypt(msg["signature"], sender_pub)

        verified = (digest_local == digest_sender)

        output += (
            f"\nFrom: {sender}\nSubject: {subject}\nVerified: {verified}\n"
            f"Message:\n{plaintext}\n{'-'*40}\n"
        )

    return output


#   GUI (Page-based Navigation)

class App:
    def __init__(self, root):
        self.root = root
        root.title("Secure Email System")
        root.geometry("500x500")

        self.frames = {}
        for F in (HomePage, RegisterPage, LoginPage, DashboardPage, SendPage, InboxPage):
            page = F(root, self)
            self.frames[F] = page
            page.grid(row=0, column=0, sticky="nsew")

        self.show(HomePage)

    def show(self, page):
        frame = self.frames[page]
        if hasattr(frame, "on_show"):
            frame.on_show()
        frame.tkraise()


# ---------------- HOME PAGE ----------------
class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        tk.Label(self, text="Secure Email System", font=("Arial", 18)).pack(pady=60)
        ttk.Button(self, text="Register", command=lambda: controller.show(RegisterPage)).pack(pady=10)
        ttk.Button(self, text="Login", command=lambda: controller.show(LoginPage)).pack(pady=10)


# ---------------- REGISTER PAGE ----------------
class RegisterPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        tk.Label(self, text="Register", font=("Arial", 16)).pack(pady=20)

        tk.Label(self, text="Username").pack()
        self.e_user = tk.Entry(self)
        self.e_user.pack()

        tk.Label(self, text="Password").pack()
        self.e_pass = tk.Entry(self, show="*")
        self.e_pass.pack()

        ttk.Button(self, text="Register", command=self.register).pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show(HomePage)).pack()

        self.controller = controller

    def on_show(self):
        self.e_user.delete(0, tk.END)
        self.e_pass.delete(0, tk.END)

    def register(self):
        u, p = self.e_user.get(), self.e_pass.get()
        ok, msg = register_user(u, p)
        if ok:
            messagebox.showinfo("Success", msg)
            self.controller.show(DashboardPage)
        else:
            messagebox.showerror("Error", msg)


# ---------------- LOGIN PAGE ----------------
class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        tk.Label(self, text="Login", font=("Arial", 16)).pack(pady=20)

        tk.Label(self, text="Username").pack()
        self.e_user = tk.Entry(self)
        self.e_user.pack()

        tk.Label(self, text="Password").pack()
        self.e_pass = tk.Entry(self, show="*")
        self.e_pass.pack()

        ttk.Button(self, text="Login", command=self.login).pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show(HomePage)).pack()

        self.controller = controller

    def on_show(self):
        self.e_user.delete(0, tk.END)
        self.e_pass.delete(0, tk.END)

    def login(self):
        u, p = self.e_user.get(), self.e_pass.get()
        ok, msg = login_user(u, p)
        if ok:
            messagebox.showinfo("Success", msg)
            self.controller.show(DashboardPage)
        else:
            messagebox.showerror("Error", msg)


# ---------------- DASHBOARD ----------------
class DashboardPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        self.lbl_user = tk.Label(self, text="", font=("Arial", 14))
        self.lbl_user.pack(pady=20)

        ttk.Button(self, text="Send Email", command=lambda: controller.show(SendPage)).pack(pady=10)
        ttk.Button(self, text="Inbox", command=lambda: controller.show(InboxPage)).pack(pady=10)
        ttk.Button(self, text="Logout", command=self.logout).pack(pady=10)

        self.controller = controller

    def on_show(self):
        self.lbl_user.config(text=f"Logged in as: {get_username()}")

    def logout(self):
        logout_user()
        messagebox.showinfo("Logout", "You are logged out.")
        self.controller.show(HomePage)


# ---------------- SEND PAGE ----------------
class SendPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        self.lbl_user = tk.Label(self, text="", font=("Arial", 14))
        self.lbl_user.pack(pady=10)

        tk.Label(self, text="Recipient").pack()
        self.e_to = tk.Entry(self)
        self.e_to.pack()

        tk.Label(self, text="Subject").pack()
        self.e_sub = tk.Entry(self)
        self.e_sub.pack()

        tk.Label(self, text="Message").pack()
        self.t_msg = scrolledtext.ScrolledText(self, width=45, height=10)
        self.t_msg.pack()

        ttk.Button(self, text="Send", command=self.send_it).pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show(DashboardPage)).pack()

        self.controller = controller

    def on_show(self):
        self.lbl_user.config(text=f"Logged in as: {get_username()}")
        self.e_to.delete(0, tk.END)
        self.e_sub.delete(0, tk.END)
        self.t_msg.delete("1.0", tk.END)

    def send_it(self):
        to = self.e_to.get()
        sub = self.e_sub.get()
        msg = self.t_msg.get("1.0", tk.END).strip()

        ok, info = send_secure_message(to, sub, msg)
        if ok:
            messagebox.showinfo("Success", info)
            self.controller.show(DashboardPage)
        else:
            messagebox.showerror("Error", info)


# ---------------- INBOX PAGE ----------------
class InboxPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        self.lbl_user = tk.Label(self, text="", font=("Arial", 14))
        self.lbl_user.pack(pady=10)

        self.box = scrolledtext.ScrolledText(self, width=50, height=18)
        self.box.pack()

        ttk.Button(self, text="Refresh", command=self.load_inbox).pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show(DashboardPage)).pack()

        self.controller = controller

    def on_show(self):
        self.lbl_user.config(text=f"Logged in as: {get_username()}")
        self.load_inbox()

    def load_inbox(self):
        self.box.delete("1.0", tk.END)
        self.box.insert(tk.END, fetch_user_inbox())


#  Run
root = tk.Tk()
App(root)
root.mainloop()
