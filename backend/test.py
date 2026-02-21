import joblib

# Load the features list we saved during training
features = joblib.load('models/features.pkl')

print("--- MODEL EXPECTS THIS ORDER ---")
for i, name in enumerate(features):
    print(f"{i}: {name}")