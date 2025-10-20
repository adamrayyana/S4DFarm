from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post("/api/flag")
def submit_flag():
    return jsonify({"message": "accepted"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3232)
