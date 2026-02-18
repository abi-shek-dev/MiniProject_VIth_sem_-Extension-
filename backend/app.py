from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
from classifier import URLFeatureExtractor

app = Flask(__name__)
CORS(app)  # Allows the extension to talk to this server

# Load the brain and the features list
model = joblib.load('models/model.pkl')
feature_cols = joblib.load('models/features.pkl')
extractor = URLFeatureExtractor()

# Map the numbers back to human-friendly names
CLASS_MAP = {0: "Safe", 1: "Defacement", 2: "Phishing", 3: "Malicious"}

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # 1. Extract features
    features = extractor.extract_all(url)
    
    # 2. Convert to format model expects (2D array)
    features_array = np.array([features])
    
    # 3. Get prediction and probability
    prediction_idx = model.predict(features_array)[0]
    probabilities = model.predict_proba(features_array)[0]
    confidence = float(np.max(probabilities))
    
    result = CLASS_MAP.get(prediction_idx, "Unknown")
    
    print(f"Checked: {url} | Result: {result} ({confidence*100:.1f}%)")
    
    return jsonify({
        "url": url,
        "status": result,
        "confidence": confidence,
        "risk_level": "High" if result != "Safe" else "Low"
    })

if __name__ == '__main__':
    # Start server on port 5000
    app.run(port=5000, debug=True)