from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory "database"
users = []
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


@app.route("/register", methods=["POST"])
def register_user():
    try:
        data = request.get_json()
        err = validate_body(data, ["username", "pubkey"])
        if err:
            return err

        username = data["username"]
        pubkey = data["pubkey"]

        if find_user(username):
            return jsonify("User already exists"), 409

        users.append({
            "username": username, 
            "pubkey": pubkey
        })

        return jsonify("User registered"), 200
    except Exception:
        return jsonify("Internal server error"), 500


@app.route("/pubkey/<recipient>", methods=["GET"])
def get_public_key(recipient):
    try:
        user = find_user(recipient)
        if not user:
            return jsonify("User not found"), 404

        return jsonify({"pubkey": user["pubkey"]}), 200
    except Exception:
        return jsonify("Internal server error"), 500


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


@app.route("/inbox/<username>", methods=["GET"])
def fetch_inbox(username):
    try:
        if not find_user(username):
            return jsonify("User not found"), 404

        user_inbox = inbox.get(username, [])
        return jsonify({"inbox": user_inbox}), 200
    except Exception as e:
        return jsonify("Internal server error"), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

