from flask import Flask, request, jsonify

app = Flask(__name__)

#########################################################

users = []

#########################################################

def validate_body(data, required):
    # Validate payload existence
    if not data:
        return jsonify("Request body is required"), 400

    # Check required fields
    missing = [field for field in required if field not in data]
    if missing:
        return jsonify(f"Missing fields: {', '.join(missing)}"), 400
    
    return None

#########################################################

@app.route("/register", methods=["POST"])
def register_user():
    try:
        data = request.get_json()

        # Validate payload
        error = validate_body(data=data, required=["username", "pubkey"])
        if error:
            return error

        # Check duplicates
        if any(u["username"] == data["username"] for u in users):
            return jsonify("User already exists"), 409

        # Add user
        users.append({
            "username": data["username"],
            "pubkey": data["pubkey"]
        })

        return jsonify("User registered"), 200
    except Exception as e:
        print("Error:", e)
        return jsonify("An internal server error occurred."), 500

#########################################################

@app.route("/pubkey/<recipient>", methods=["GET"])
def get_public_key(recipient):
    # Check if user exists in the "database"
    pubkey = users.get(recipient)

    if pubkey:
        return jsonify({"pubkey": pubkey}), 200
    else:
        return jsonify({"error": "User not found"}), 404


#########################################################

MESSAGES = []

@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()

    # Validate request body
    error = validate_body(data=data, required=["sender", "recepient","message"])
    if error:
        return error

    # Store the message
    MESSAGES.append(data)

    print(f"[+] Message stored: {data}")  # server log

    return jsonify({"status": "Message received"}), 200

#########################################################
if __name__ == "__main__":
    app.run()