import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
import joblib
import os

# Create models directory if it doesn't exist
if not os.path.exists('models'):
    os.makedirs('models')

# 1. Load and Clean Data
print("Loading and cleaning dataset...")
df = pd.read_csv('data/malicious_urls.csv') 
df = df.sample(frac=1, random_state=42).reset_index(drop=True) # SHUFFLE EVERYTHING

# Drop any rows where URL or Type is missing
df = df.dropna(subset=['url', 'type'])

# Explicitly map labels and remove rows that don't match our 4 categories
label_map = {'benign': 0, 'defacement': 1, 'phishing': 2, 'malicious': 3}
df['label'] = df['type'].map(label_map)

# Remove rows that couldn't be mapped (resulted in NaN)
df = df.dropna(subset=['label'])
df['label'] = df['label'].astype(int)

urls = df['url'].astype(str).values
labels = df['label'].values

print(f"Dataset ready: {len(urls)} clean samples found.")

# 2. Preprocessing
max_len = 150 
tokenizer = Tokenizer(char_level=True, lower=True)
tokenizer.fit_on_texts(urls)
X = tokenizer.texts_to_sequences(urls)
X = pad_sequences(X, maxlen=max_len)

# 3. Build Model (Note: Removed deprecated input_length as per your warning)
model = Sequential([
    Embedding(len(tokenizer.word_index) + 1, 64),
    Conv1D(128, 5, activation='relu'),
    GlobalMaxPooling1D(),
    Dense(64, activation='relu'),
    Dropout(0.2), 
    Dense(4, activation='softmax') 
])

model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

# 4. Train
print("🚀 Starting Deep Learning Training (This may take a few minutes)...")
model.fit(X, labels, epochs=5, batch_size=128, validation_split=0.2)

# 5. Save the Deep Brain
model.save('models/deep_shield_model.keras')
joblib.dump(tokenizer, 'models/tokenizer.pkl')
print("✅ Deep Learning Model and Tokenizer Saved to /models/")