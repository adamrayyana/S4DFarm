from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post("/api/flag")
def submit_flag():
    return jsonify({"message": "accepted"}), 200

@app.get("/api/user")
def user_list():
    data = [
        {"host_ip": f"IP{i}_TEST", "id": i, "username": f"Team{i}"}
        for i in range(20)
    ]
    return jsonify(data), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3232)
