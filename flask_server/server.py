from flask import Flask, jsonify, request
app = Flask(__name__)

@app.route('/exfil', methods=['POST'])
def exfil():
    data = request.json
    print(f"💀 STOLEN DATA RECEIVED: {data}")
    return "OK"

@app.route('/')
def home():
    return """
    <h1>🚨 C2 EXFILTRATION SERVER</h1>
    <p>✅ Server active - waiting for stolen Android contacts...</p>
    <p>Open Terminal 3: python simulate_attack.py</p>
    """

@app.route('/dashboard')
def dashboard():
    return """
    <h1>🚨 LIVE EXFILTRATION DETECTOR</h1>
    <h2>100+ contacts stolen from Android → C2 Server!</h2>
    <p><b>Terminal 2 (main.py):</b> Check HIGH_VOLUME_UPLOAD alerts firing!</p>
    <p><b>Demo complete ✅</b></p>
    """

if __name__ == "__main__":
    print("🌐 C2 Server LIVE: http://localhost:5000")
    print("Waiting for malicious app exfiltration...")
    app.run(host='0.0.0.0', port=5000, debug=False)