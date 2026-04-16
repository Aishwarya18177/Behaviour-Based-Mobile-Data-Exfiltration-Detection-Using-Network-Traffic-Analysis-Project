from flask import Flask, jsonify, request
app = Flask(__name__)

@app.route('/exfil', methods=['POST'])
def exfil():
    data = request.json
    print(f"💀 STOLEN DATA: {data}")
    return "OK"

@app.route('/')
def home():
    return "<h1>C2 Server Active</h1><p>Waiting for exfiltration...</p>"

if __name__ == "__main__":
    print("🌐 C2 Server: http://localhost:5000")
    app.run(port=5000)