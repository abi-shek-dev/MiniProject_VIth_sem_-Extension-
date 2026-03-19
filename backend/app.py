import os
import numpy as np
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

# --- THE MISSING IMPORTS ---
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

app = Flask(__name__)
CORS(app)

# 1. LOAD THE DEEP LEARNING BRAIN
try:
    # Use .keras as we discussed to avoid the quantization error
    model = load_model('models/deep_shield_model.keras')
    tokenizer = joblib.load('models/tokenizer.pkl')
    print("✅ Deep Learning Engine & Hunter Logic Online")
except Exception as e:
    print(f"❌ Critical Load Error: {e}")

# Configuration
CLASS_MAP = {0: "Safe", 1: "Defacement", 2: "Phishing", 3: "Malicious"}
WHITELIST = ["google.com", "whatsapp.com", "snapchat.com", "facebook.com", "youtube.com", "linkedin.com"]

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data:
        return jsonify({"status": "Error", "message": "No data received"}), 400

    # Get DNA from Extension (Behavioral features)
    dna = data.get('dna', {})
    url = dna.get('url') or data.get('url')
    
    if not url:
        return jsonify({"status": "Error", "message": "No URL provided"}), 400

    domain = urlparse(url).netloc.lower().replace('www.', '')

    # --- LAYER 1: REPUTATION (WHITELIST) ---
    if any(white in domain for white in WHITELIST):
        return jsonify({"url": url, "status": "Safe", "method": "Reputation Check"})

    # --- LAYER 2: AI BRAIN (URL SEQUENCE ANALYSIS) ---
    seq = tokenizer.texts_to_sequences([url.lower()])
    # This is where the error was happening!
    padded = pad_sequences(seq, maxlen=150)
    ai_prediction = model.predict(padded, verbose=0)
    ai_idx = np.argmax(ai_prediction[0])
    ai_confidence = float(np.max(ai_prediction[0]))
    ai_status = CLASS_MAP.get(ai_idx, "Safe")

    # --- LAYER 3: MASTER HUNTER (BEHAVIORAL RISK) ---
    risk_score = 0
    
    # Hunter Trigger: Shadow Forms (Data Exfiltration)
    if dna.get('shadow_forms', 0) > 0: 
        risk_score += 60 
    
    # Hunter Trigger: Credential Harvesting detection
    if dna.get('has_password') and ai_status != "Safe":
        risk_score += 30
        
    # Hunter Trigger: Obfuscation detection
    if dna.get('hidden_iframes', 0) > 0:
        risk_score += 20

    # --- FINAL HYBRID VERDICT ---
    final_status = ai_status
    
    # If the hunter finds major behavioral red flags, it overrides the AI
    if risk_score >= 70:
        final_status = "Malicious (Hunting Triggered)"
    elif risk_score < 20 and ai_confidence < 0.8:
        final_status = "Safe"

    print(f"🔬 Hunter Scan: {url[:40]}... | Result: {final_status} | Risk: {risk_score}")

    return jsonify({
        "url": url,
        "status": final_status,
        "ai_score": f"{ai_confidence*100:.1f}%",
        "hunter_risk": risk_score,
        "details": {
            "shadow_forms_detected": dna.get('shadow_forms', 0),
            "password_field_present": dna.get('has_password', False)
        }
    })

if __name__ == '__main__':
    app.run(port=5000, debug=False)