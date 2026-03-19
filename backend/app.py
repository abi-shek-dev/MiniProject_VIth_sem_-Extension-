import os
import numpy as np
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# 1. LOAD THE MODERN NATIVE KERAS MODEL
try:
    # Make sure you renamed your file to .keras in train_deep_model.py!
    model = load_model('models/deep_shield_model.keras')
    tokenizer = joblib.load('models/tokenizer.pkl')
    print("✅ Deep Learning Engine Online (.keras format)")
except Exception as e:
    print(f"❌ Model Load Error: {e}")

CLASS_MAP = {0: "Safe", 1: "Defacement", 2: "Phishing", 3: "Malware"}
WHITELIST = ["google.com", "whatsapp.com", "snapchat.com", "facebook.com", "youtube.com"]

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    # SAFETY CHECK: Extract 'dna' if it exists, otherwise use empty dict
    dna = data.get('dna', {})
    
    # Get URL from 'dna' or directly from 'url' key
    url = dna.get('url') or data.get('url')
    
    if not url:
        return jsonify({"error": "No URL found in request"}), 400

    domain = urlparse(url).netloc.lower().replace('www.', '')

    # --- LAYER 1: WHITELIST ---
    if any(white in domain for white in WHITELIST):
        return jsonify({"url": url, "status": "Safe", "method": "Whitelist"})

    # --- LAYER 2: DEEP LEARNING URL SCAN ---
    seq = tokenizer.texts_to_sequences([url.lower()])
    padded = pad_sequences(seq, maxlen=150)
    ai_prediction = model.predict(padded, verbose=0)
    ai_idx = np.argmax(ai_prediction[0])
    ai_status = CLASS_MAP.get(ai_idx, "Safe")
    ai_confidence = float(np.max(ai_prediction[0]))

    # --- LAYER 3: BEHAVIORAL ANALYSIS ---
    # We only run this if the DNA was actually sent by the extension
    risk_score = 0
    if dna:
        if dna.get('has_password_field') and ai_status != "Safe":
            risk_score += 50
        if dna.get('suspicious_forms', 0) > 0:
            risk_score += 40
        if dna.get('has_hidden_elements'):
            risk_score += 20

    # Final Decision Logic
    final_status = ai_status
    if risk_score >= 70:
        final_status = "Malicious" 
    elif risk_score < 20 and ai_confidence < 0.8:
        final_status = "Safe"

    print(f"🔬 Analyzed: {url[:40]}... | Result: {final_status}")

    return jsonify({
        "url": url,
        "status": final_status,
        "confidence": ai_confidence,
        "behavior_score": risk_score
    })

if __name__ == '__main__':
    app.run(port=5000, debug=False)