# server_fake.py
# -------------------------------------------------
# Very simple fake server for testing Person B's client
# -------------------------------------------------
from flask import Flask, request, jsonify

app = Flask(__name__)

users = {}
inboxes = {}

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    pubkey = data.get("pubkey")
    users[username] = pubkey
    inboxes.setdefault(username, [])
    print(f"[SERVER] Registered {username}")
    return jsonify({"status": "ok"}), 200

@app.route("/pubkey/<username>", methods=["GET"])
def get_pubkey(username):
    if username in users:
        return jsonify({"pubkey": users[username]})
    return jsonify({"error": "user not found"}), 404

@app.route("/send", methods=["POST"])
def send():
    data = request.get_json()
    recipient = data.get("recipient")
    if recipient not in inboxes:
        return jsonify({"error": "recipient not found"}), 404
    inboxes[recipient].append(data)
    print(f"[SERVER] Stored message for {recipient}")
    return jsonify({"status": "message stored"}), 200

@app.route("/inbox/<username>", methods=["GET"])
def inbox(username):
    return jsonify({"inbox": inboxes.get(username, [])}), 200

if __name__ == "__main__":
    app.run(port=5000)
