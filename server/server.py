from flask import Flask, request, jsonify
from Crypto.Hash import SHA256

app = Flask(__name__)

# In-memory "database"
users = []       # now stores username + password_hash + pubkey
inbox = {}

def validate_body(data, required):
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    missing = [field for field in required if field not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    return None

def find_user(username):
    for u in users:
        if u["username"] == username:
            return u
    return None

# 🔹 Added SHA-256 password hashing
def hash_password(password):
    h = SHA256.new()
    h.update(password.encode())
    return h.hexdigest()


# 🔹 UPDATED: Registration now needs username + password + pubkey
@app.route("/register", methods=["POST"])
def register_user():
    """
    Required JSON:
    {
        "username": "...",
        "password": "...",
        "pubkey": [...]
    }
    """
    try:
        data = request.get_json()
        err = validate_body(data, ["username", "password", "pubkey"])
        if err:
            return err

        username = data["username"]
        password = data["password"]
        pubkey = data["pubkey"]

        if find_user(username):
            return jsonify("User already exists"), 409

        users.append({
            "username": username,
            "password_hash": hash_password(password),   # 🔥 saved hashed
            "pubkey": pubkey
        })

        return jsonify("User registered"), 200
    except Exception:
        return jsonify("Internal server error"), 500

# 🔹 NEW ENDPOINT: Login
@app.route("/login", methods=["POST"])
def login():
    """
    Required JSON:
    {
        "username": "...",
        "password": "..."
    }
    Returns public key on success.
    """
    try:
        data = request.get_json()
        err = validate_body(data, ["username", "password"])
        if err:
            return err

        username = data["username"]
        password = data["password"]

        user = find_user(username)
        if not user:
            return jsonify({"error": "User not found"}), 404

        if user["password_hash"] != hash_password(password):
            return jsonify({"error": "Wrong password"}), 403

        return jsonify({
            "status": "ok",
            "pubkey": user["pubkey"]
        }), 200

    except:
        return jsonify("Internal server error"), 500

# PUBLIC KEY FETCH (unchanged)
@app.route("/pubkey/<recipient>", methods=["GET"])
def get_public_key(recipient):
    try:
        user = find_user(recipient)
        if not user:
            return jsonify("User not found"), 404

        return jsonify({"pubkey": user["pubkey"]}), 200
    except Exception:
        return jsonify("Internal server error"), 500

# SEND MESSAGE (unchanged)
@app.route("/send", methods=["POST"])
def send_message():
    try:
        data = request.get_json()
        required = [
            "sender",
            "recipient",
            "subject",
            "iv",
            "ciphertext",
            "enc_aes_key",
            "signature",
            "timestamp",
        ]
        err = validate_body(data, required)
        if err:
            return err

        if not find_user(data["recipient"]):
            return jsonify("Recipient not found"), 404

        inbox.setdefault(data["recipient"], []).append({
            "sender": data["sender"],
            "subject": data["subject"],
            "iv": data["iv"],
            "ciphertext": data["ciphertext"],
            "enc_aes_key": data["enc_aes_key"],
            "signature": data["signature"],
            "timestamp": data["timestamp"],
        })

        return jsonify("Message sent"), 200
    except Exception:
        return jsonify("Internal server error"), 500

# INBOX 
@app.route("/inbox/<username>", methods=["GET"])
def fetch_inbox(username):
    try:
        if not find_user(username):
            return jsonify("User not found"), 404

        user_inbox = inbox.get(username, [])
        return jsonify({"inbox": user_inbox}), 200
    except Exception as e:
        return jsonify("Internal server error"), 500

# RUN SERVER
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
