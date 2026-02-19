from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
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

    # 1. Extract raw features as a list
    features_list = extractor.extract_all(url)
    
    # 2. Convert to a DataFrame with the EXACT column names used during training
    # This removes the UserWarning and ensures the model reads the data correctly
    features_df = pd.DataFrame([features_list], columns=feature_cols)
    
    # 3. Get prediction and probability
    prediction_idx = model.predict(features_df)[0]
    probabilities = model.predict_proba(features_df)[0]
    confidence = float(np.max(probabilities))
    
    result = CLASS_MAP.get(prediction_idx, "Unknown")
    
    print(f"Checked: {url} | Result: {result} ({confidence*100:.1f}%)")
    
    return jsonify({
        "url": url,
        "status": result,
        "confidence": confidence
    })

if __name__ == '__main__':
    # Start server on port 5000
    app.run(port=5000, debug=True)