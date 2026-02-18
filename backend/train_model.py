import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# 1. Load the massive dataset
print("Loading dataset... this may take a few seconds.")
df = pd.read_csv('data/malicious_urls.csv')

# 2. Select the numerical features we want to use
# We skip 'url', 'type', 'domain', and 'scan_date'
feature_cols = [
    'url_len', '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', 
    'digits', 'letters', 'abnormal_url', 'https', 'Shortining_Service', 
    'having_ip_address', 'web_is_live', 'web_security_score', 'web_has_login',
    'phish_urgency_words', 'phish_security_words', 'phish_brand_mentions'
]

X = df[feature_cols]
y = df['label'] # 0=benign, 1=defacement, 2=phishing, 3=malware

# 3. Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Initialize and train the Random Forest
print("Training the Random Forest model (this will take a minute)...")
model = RandomForestClassifier(
    n_estimators=100, 
    max_depth=20, 
    n_jobs=-1, 
    random_state=42,
    class_weight='balanced'  # <--- THIS IS THE MAGIC LINE
)
model.fit(X_train, y_train)

# 5. Evaluate the model
y_pred = model.predict(X_test)
print(f"✅ Training Complete! Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# 6. Save the model and the list of feature columns
joblib.dump(model, 'models/model.pkl')
joblib.dump(feature_cols, 'models/features.pkl') # Save column names for the API
print("🚀 Model and Features saved to /models/")