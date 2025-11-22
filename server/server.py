from flask import Flask, request, jsonify
from Crypto.Hash import SHA256
import json
import os
from threading import Lock

app = Flask(__name__)

DATA_FILE = "data.json"
file_lock = Lock()

def load_data():
	"""Load users and inbox from JSON file"""
	if not os.path.exists(DATA_FILE):
		return {"users": [], "inbox": {}}
	
	with file_lock:
		with open(DATA_FILE, 'r') as f:
			return json.load(f)

def save_data(data):
	"""Save users and inbox to JSON file"""
	with file_lock:
		with open(DATA_FILE, 'w') as f:
			json.dump(data, f, indent=2)

def validate_body(data, required):
	if not data:
		return jsonify({"error": "Request body is required"}), 400

	missing = [field for field in required if field not in data]
	if missing:
		return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

	return None

def find_user(username, users):
	"""Find user by username in users list"""
	for u in users:
		if u["username"] == username:
			return u
	return None

def hash_password(password):
	"""Hash password using SHA-256"""
	h = SHA256.new()
	h.update(password.encode())
	return h.hexdigest()

@app.route("/register", methods=["POST"])
def register_user():
	"""
	Register new user with username, password, and public key
	Body: {username, password, pubkey}
	"""
	try:
		data = request.get_json()
		err = validate_body(data, ["username", "password", "pubkey"])
		if err:
			return err

		username = data["username"]
		password = data["password"]
		pubkey = data["pubkey"]

		db = load_data()
		users = db["users"]

		if find_user(username, users):
			return jsonify("User already exists"), 409

		users.append({
			"username": username,
			"password_hash": hash_password(password),
			"pubkey": pubkey
		})

		save_data(db)
		return jsonify("User registered"), 200
	except Exception:
		return jsonify("Internal server error"), 500

@app.route("/login", methods=["POST"])
def login():
	"""
	Login with username and password
	Body: {username, password}
	Returns: {status: "ok", pubkey: [...]}
	"""
	try:
		data = request.get_json()
		err = validate_body(data, ["username", "password"])
		if err:
			return err

		username = data["username"]
		password = data["password"]

		db = load_data()
		user = find_user(username, db["users"])
		
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

@app.route("/pubkey/<recipient>", methods=["GET"])
def get_public_key(recipient):
	"""Get public key for recipient"""
	try:
		db = load_data()
		user = find_user(recipient, db["users"])
		
		if not user:
			return jsonify("User not found"), 404

		return jsonify({"pubkey": user["pubkey"]}), 200
	except Exception:
		return jsonify("Internal server error"), 500

@app.route("/send", methods=["POST"])
def send_message():
	"""
	Send encrypted message to recipient
	Body: {sender, recipient, subject, iv, ciphertext, enc_aes_key, signature, timestamp}
	"""
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

		db = load_data()
		
		if not find_user(data["recipient"], db["users"]):
			return jsonify("Recipient not found"), 404

		inbox = db["inbox"]
		if data["recipient"] not in inbox:
			inbox[data["recipient"]] = []

		inbox[data["recipient"]].append({
			"sender": data["sender"],
			"subject": data["subject"],
			"iv": data["iv"],
			"ciphertext": data["ciphertext"],
			"enc_aes_key": data["enc_aes_key"],
			"signature": data["signature"],
			"timestamp": data["timestamp"],
		})

		save_data(db)
		return jsonify("Message sent"), 200
	except Exception:
		return jsonify("Internal server error"), 500

@app.route("/inbox/<username>", methods=["GET"])
def fetch_inbox(username):
	"""Get all messages for username"""
	try:
		db = load_data()
		
		if not find_user(username, db["users"]):
			return jsonify("User not found"), 404

		user_inbox = db["inbox"].get(username, [])
		return jsonify({"inbox": user_inbox}), 200
	except Exception as e:
		return jsonify("Internal server error"), 500

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000, debug=True)
