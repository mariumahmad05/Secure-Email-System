import sys
import os
import json
import base64
import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# ---------------------------------------------
# IMPORT CRYPTO MODULE
# ---------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
from crypto.full_encryption import *

SERVER_URL = "http://127.0.0.1:5000"
USER_STORE = os.path.join(PROJECT_ROOT, "client", "users.json")

# ===================================================
# AES UTILS FOR PASSWORD-ENCRYPTING PRIVATE KEY
# ===================================================
def encrypt_private_key(sk, password):
    key = SHA256.new(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR)
    enc = cipher.encrypt(json.dumps(sk).encode())
    return {"nonce": base64.b64encode(cipher.nonce).decode(),
            "cipher": base64.b64encode(enc).decode()}

def decrypt_private_key(enc_data, password):
    key = SHA256.new(password.encode()).digest()
    nonce = base64.b64decode(enc_data["nonce"])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted = cipher.decrypt(base64.b64decode(enc_data["cipher"]))
    return json.loads(decrypted.decode())

# ===================================================
# LOAD / SAVE USERS
# ===================================================
def load_users():
    if not os.path.exists(USER_STORE):
        return {}
    return json.load(open(USER_STORE))

def save_users(users):
    json.dump(users, open(USER_STORE, "w"), indent=4)

# ===================================================
# SERVER API
# ===================================================
def api_register(username, pubkey):
    try:
        r = requests.post(f"{SERVER_URL}/register", json={"username": username, "pubkey": pubkey})
        return r.status_code
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
        return requests.post(f"{SERVER_URL}/send", json=data).status_code == 200
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

# ===================================================
# GLOBAL SESSION
# ===================================================
LOGGED_IN = None
PRIVATE_KEY = None
PUBLIC_KEY = None

def get_username():
    return LOGGED_IN if LOGGED_IN else ""

# ===================================================
# REGISTER / LOGIN / LOGOUT FUNCTIONS
# ===================================================
def register_user(username, password):
    global LOGGED_IN, PRIVATE_KEY, PUBLIC_KEY
    users = load_users()
    if username in users:
        return False, "User already registered."
    name, pk, sk = create_keys(username)
    PUBLIC_KEY = pk
    PRIVATE_KEY = sk
    users[username] = {"public_key": pk, "encrypted_private_key": encrypt_private_key(sk, password)}
    save_users(users)
    status = api_register(username, pk)
    if status == 200:
        LOGGED_IN = username
        return True, "Registration successful."
    return False, "Server error."

def login_user(username, password):
    global LOGGED_IN, PRIVATE_KEY, PUBLIC_KEY
    users = load_users()
    if username not in users:
        return False, "User not found."
    PUBLIC_KEY = users[username]["public_key"]
    try:
        PRIVATE_KEY = decrypt_private_key(users[username]["encrypted_private_key"], password)
    except:
        return False, "Wrong password."
    LOGGED_IN = username
    return True, "Logged in."

def logout_user():
    global LOGGED_IN, PRIVATE_KEY, PUBLIC_KEY
    LOGGED_IN = None
    PRIVATE_KEY = None
    PUBLIC_KEY = None

# ===================================================
# SEND EMAIL
# ===================================================
def send_secure_message(to_user, subject, msg_text):
    recipient_pub = api_get_pubkey(to_user)
    if not recipient_pub:
        return False, "Recipient not found."
    aes_key = aes_key_creation()
    ciphertext, nonce = aes_encryption_of_msg(msg_text, aes_key)
    enc_aes_key = rsa_encryption(aes_key, recipient_pub)
    digest = hash_string_sha256(msg_text)
    signature = rsa_encryption(digest, PRIVATE_KEY)
    packet = {
        "sender": LOGGED_IN,
        "recipient": to_user,
        "subject": subject,
        "iv": list(nonce),
        "ciphertext": list(ciphertext),
        "enc_aes_key": enc_aes_key,
        "signature": signature,
        "timestamp": "now",
    }
    return api_send(packet), "Sent."

# ===================================================
# INBOX
# ===================================================
def fetch_user_inbox():
    inbox = api_inbox(LOGGED_IN)
    out = ""
    for msg in inbox:
        sender = msg["sender"]
        subject = msg["subject"]
        ciphertext = bytes(msg["ciphertext"])
        nonce = bytes(msg["iv"])
        aes_key = rsa_aes_decrypt(msg["enc_aes_key"], PRIVATE_KEY)
        plaintext = aes_decryption_of_msg(ciphertext, nonce, aes_key)
        sender_pub = api_get_pubkey(sender)
        valid = (hash_string_sha256(plaintext) == rsa_str_decrypt(msg["signature"], sender_pub))
        out += f"\nFrom: {sender}\nSubject: {subject}\nVerified: {valid}\nMessage:\n{plaintext}\n{'-'*40}\n"
    return out

# ===================================================
# GUI WITH PAGE SWITCHING
# ===================================================
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Email System")
        self.root.geometry("500x500")
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

# ---------------- PAGES ----------------
class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Label(self, text="Secure Email System", font=("Arial", 18)).pack(pady=50)
        ttk.Button(self, text="Register", command=lambda: controller.show(RegisterPage)).pack(pady=10)
        ttk.Button(self, text="Login", command=lambda: controller.show(LoginPage)).pack(pady=10)

class RegisterPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
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
        u, p = self.e_user.get().strip(), self.e_pass.get().strip()
        ok, msg = register_user(u, p)
        if ok:
            messagebox.showinfo("Success", msg)
            self.controller.show(DashboardPage)
        else:
            messagebox.showerror("Error", msg)

class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
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
        u, p = self.e_user.get().strip(), self.e_pass.get().strip()
        ok, msg = login_user(u, p)
        if ok:
            messagebox.showinfo("Success", msg)
            self.controller.show(DashboardPage)
        else:
            messagebox.showerror("Error", msg)

class DashboardPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.lbl_user = tk.Label(self, text="", font=("Arial", 12))
        self.lbl_user.pack(pady=10)
        ttk.Button(self, text="Send Email", command=lambda: controller.show(SendPage)).pack(pady=10)
        ttk.Button(self, text="Inbox", command=lambda: controller.show(InboxPage)).pack(pady=10)
        ttk.Button(self, text="Logout", command=self.logout).pack(pady=10)
        self.controller = controller
    def on_show(self):
        self.lbl_user.config(text=f"Logged in as: {get_username()}")
    def logout(self):
        logout_user()
        messagebox.showinfo("Logout", "Logged out.")
        self.controller.show(HomePage)

class SendPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.lbl_user = tk.Label(self, text="", font=("Arial", 12))
        self.lbl_user.pack(pady=5)
        tk.Label(self, text="Recipient").pack()
        self.e_to = tk.Entry(self)
        self.e_to.pack()
        tk.Label(self, text="Subject").pack()
        self.e_sub = tk.Entry(self)
        self.e_sub.pack()
        tk.Label(self, text="Message").pack()
        self.t_msg = scrolledtext.ScrolledText(self, width=40, height=8)
        self.t_msg.pack()
        ttk.Button(self, text="Send", command=self.send_email).pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show(DashboardPage)).pack()
        self.controller = controller
    def on_show(self):
        self.lbl_user.config(text=f"Logged in as: {get_username()}")
        self.e_to.delete(0, tk.END)
        self.e_sub.delete(0, tk.END)
        self.t_msg.delete("1.0", tk.END)
    def send_email(self):
        to, sub, msg = self.e_to.get().strip(), self.e_sub.get().strip(), self.t_msg.get("1.0", tk.END).strip()
        ok, info = send_secure_message(to, sub, msg)
        if ok:
            messagebox.showinfo("Success", "Email sent.")
            self.controller.show(DashboardPage)
        else:
            messagebox.showerror("Error", info)

class InboxPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.lbl_user = tk.Label(self, text="", font=("Arial", 12))
        self.lbl_user.pack(pady=5)
        self.box = scrolledtext.ScrolledText(self, width=50, height=15)
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

# ===================================================
# RUN APP
# ===================================================
root = tk.Tk()
App(root)
root.mainloop()
