import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.utils.class_weight import compute_class_weight
import joblib
import os
import copy

# ─────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────
DATA_PATH  = 'data/master_dataset.csv'
MODEL_DIR  = 'models'
MAX_LEN    = 150
EMBED_DIM  = 64
EPOCHS     = 15
BATCH_SIZE = 512

LABEL_MAP = {'benign': 0, 'defacement': 1, 'phishing': 2, 'malware': 3, 'scam': 4}
NUM_CLASSES = len(LABEL_MAP)

os.makedirs(MODEL_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────
# 1. CUSTOM CHAR TOKENIZER (No TensorFlow dependency needed)
# ─────────────────────────────────────────────────────────
class CharTokenizer:
    def __init__(self, max_len=150):
        self.char2idx = {'<PAD>': 0, '<UNK>': 1}
        self.max_len = max_len

    def fit(self, texts):
        idx = 2
        for text in texts:
            for char in str(text).lower():
                if char not in self.char2idx:
                    self.char2idx[char] = idx
                    idx += 1
                    
    def texts_to_sequences(self, texts):
        sequences = []
        for text in texts:
            seq = [self.char2idx.get(c, 1) for c in str(text).lower()]
            if len(seq) > self.max_len:
                seq = seq[:self.max_len]
            else:
                seq = seq + [0] * (self.max_len - len(seq))
            sequences.append(seq)
        return np.array(sequences)

# ─────────────────────────────────────────────────────────
# 2. LOAD DATA
# ─────────────────────────────────────────────────────────
print("📂 Loading data...")
df = pd.read_csv(DATA_PATH)
df = df.dropna(subset=['url', 'type'])
df['label'] = df['type'].str.lower().map(LABEL_MAP)
df = df.dropna(subset=['label'])
df['label'] = df['label'].astype(int)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

urls = df['url'].values
labels = df['label'].values

print("⚙️ Tokenizing...")
tokenizer = CharTokenizer(max_len=MAX_LEN)
tokenizer.fit(urls)
X = tokenizer.texts_to_sequences(urls)

# Class Weights to Handle Imbalance
classes = np.unique(labels)
weights = compute_class_weight('balanced', classes=classes, y=labels)
class_weights = torch.tensor(weights, dtype=torch.float32)

# Train/Val Split (85/15)
split_idx = int(len(X) * 0.85)
train_X, val_X = X[:split_idx], X[split_idx:]
train_y, val_y = labels[:split_idx], labels[split_idx:]

train_dataset = TensorDataset(torch.tensor(train_X, dtype=torch.long), torch.tensor(train_y, dtype=torch.long))
val_dataset = TensorDataset(torch.tensor(val_X, dtype=torch.long), torch.tensor(val_y, dtype=torch.long))

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE)

# ─────────────────────────────────────────────────────────
# 3. PYTORCH MODEL (CNN + BiLSTM Hybrid)
# ─────────────────────────────────────────────────────────
class URLShieldNet(nn.Module):
    def __init__(self, vocab_size, embed_dim, num_classes):
        super(URLShieldNet, self).__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv = nn.Conv1d(embed_dim, 128, kernel_size=5, padding=2)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)
        self.bilstm = nn.LSTM(128, 64, bidirectional=True, batch_first=True)
        self.fc1 = nn.Linear(128, 128)
        self.fc2 = nn.Linear(128, num_classes)

    def forward(self, x):
        x = self.embed(x)                  # [B, L, E]
        x = x.transpose(1, 2)              # [B, E, L]
        x = self.conv(x)                   # [B, 128, L]
        x = self.relu(x)
        x = self.dropout(x)
        x = x.transpose(1, 2)              # [B, L, 128]
        x, _ = self.bilstm(x)              # [B, L, 128]  (64 * 2)
        x = x.transpose(1, 2)              # [B, 128, L]
        x = torch.max(x, dim=2)[0]         # Global Max Pooling -> [B, 128]
        x = self.dropout(self.relu(self.fc1(x)))
        x = self.fc2(x)
        return x

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"🚀 Using Device: {device.type.upper()}")

vocab_size = len(tokenizer.char2idx)
model = URLShieldNet(vocab_size, EMBED_DIM, NUM_CLASSES).to(device)

criterion = nn.CrossEntropyLoss(weight=class_weights.to(device))
optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=2)

# ─────────────────────────────────────────────────────────
# 4. TRAINING LOOP
# ─────────────────────────────────────────────────────────
best_acc = 0.0
best_model_wts = copy.deepcopy(model.state_dict())
patience_counter = 0

print("🔥 Training Started...")
for epoch in range(EPOCHS):
    model.train()
    train_loss, train_correct, total = 0, 0, 0
    for inputs, targets in train_loader:
        inputs, targets = inputs.to(device), targets.to(device)
        
        optimizer.zero_grad()
        outputs = model(inputs)
        loss = criterion(outputs, targets)
        loss.backward()
        optimizer.step()
        
        train_loss += loss.item() * inputs.size(0)
        _, preds = torch.max(outputs, 1)
        train_correct += torch.sum(preds == targets).item()
        total += inputs.size(0)
        
    train_acc = train_correct / total
    
    # Validation
    model.eval()
    val_loss, val_correct, val_total = 0, 0, 0
    with torch.no_grad():
        for inputs, targets in val_loader:
            inputs, targets = inputs.to(device), targets.to(device)
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            
            val_loss += loss.item() * inputs.size(0)
            _, preds = torch.max(outputs, 1)
            val_correct += torch.sum(preds == targets).item()
            val_total += inputs.size(0)
            
    val_acc = val_correct / val_total
    scheduler.step(val_acc)
    
    print(f"Epoch {epoch+1}/{EPOCHS} | Train Acc: {train_acc:.4f} | Val Acc: {val_acc:.4f}")
    
    if val_acc > best_acc:
        best_acc = val_acc
        best_model_wts = copy.deepcopy(model.state_dict())
        patience_counter = 0
    else:
        patience_counter += 1
    
    if patience_counter >= 3:
        print("🛑 Early stopping triggered.")
        break

# ─────────────────────────────────────────────────────────
# 5. SAVE
# ─────────────────────────────────────────────────────────
print(f"🏆 Best Validation accuracy: {best_acc:.4f}")
model.load_state_dict(best_model_wts)
torch.save(model.state_dict(), f"{MODEL_DIR}/deep_shield_model.pth")

# Save model metadata (vocab size, embedding dim) so we can recreate the architecture in app.py
metadata = {
    'vocab_size': vocab_size,
    'embed_dim': EMBED_DIM,
    'num_classes': NUM_CLASSES,
    'max_len': MAX_LEN
}
joblib.dump(metadata, f"{MODEL_DIR}/model_meta.pkl")
joblib.dump(tokenizer, f"{MODEL_DIR}/tokenizer.pkl")

# Save Label map
import json
with open(f"{MODEL_DIR}/label_map.json", "w") as f:
    json.dump({str(v): k for k, v in LABEL_MAP.items()}, f, indent=2)

print("✅ PyTorch model and tokenizer saved! Ready for app.py!")