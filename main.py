import random
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input

# Lock randomness for reproducible results
random.seed(42)
np.random.seed(42)
tf.random.set_seed(42)

# --- STEP 1: LOAD THE DATA ---
print("Loading dataset... (This might take 1-2 minutes)")

# Use 'pyarrow' engine because it is faster for large files
try:
    df = pd.read_parquet('NF-UQ-NIDS-v2.parquet', engine='pyarrow')
except FileNotFoundError:
    print("ERROR: File not found! Please make sure 'NF-UQ-NIDS-v2.parquet' is in the same folder as this script.")
    exit()

print(f"SUCCESS: Dataset Loaded! Total connections: {len(df)}")

# --- STEP 2: FILTER FOR 'NORMAL' TRAFFIC ---
# We only want to train the Autoencoder on 'Benign' (Safe) traffic first.
# Label 0 = Safe, Label 1 = Attack
print("Filtering for normal traffic...")
benign_traffic = df[df['Label'] == 0]
print(f"Benign samples found: {len(benign_traffic)}")

# --- STEP 3: CLEANING ---
# We drop columns that would let the AI 'cheat' (like IP addresses).
# We want it to learn BEHAVIOR, not memorize specific computers.
cols_to_drop = [
    'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 
    'L4_SRC_PORT', 'L4_DST_PORT', 
    'Attack', 'Label', 'Dataset', 
    'DNS_QUERY_ID', 'ICMP_TYPE'
]

# We use errors='ignore' so the script doesn't crash if a column is missing
features = benign_traffic.drop(columns=cols_to_drop, errors='ignore')

# --- STEP 4: SCALING ---
# Shrink all numbers to be between 0 and 1 so the AI math works better.
print("Scaling data...")
scaler = MinMaxScaler()
scaled_data = scaler.fit_transform(features)

# Save the scaler so we can use it later for real traffic analysis
import joblib
joblib.dump(scaler, 'scaler.pkl')
print("✅ Scaler saved to scaler.pkl")

# --- STEP 5: SPLIT ---
# Keep 20% of the data hidden to test the AI later.
X_train, X_test = train_test_split(scaled_data, test_size=0.2, random_state=42)

print("\n------------------------------------------------")
print(f"Training Data Shape: {X_train.shape}")
print("SYSTEM STATUS: Ready for AI Model Building")
print("------------------------------------------------")

# --- STEP 6: BUILDING THE NEURAL NETWORK ---
print("\n------------------------------------------------")
print("Phase 2: Building the Neural Network (UPGRADED)")
print("------------------------------------------------")

# Define the architecture
input_dim = X_train.shape[1]  # 37 features

# Architecture: 37 -> 25 -> 15 -> 15 (Bottleneck) -> 15 -> 25 -> 37
# We added an extra layer (25 neurons) to help it understand complex patterns.
encoder = Sequential([
    Input(shape=(input_dim,)),
    Dense(25, activation='tanh'),  # Changed to 'tanh' for better range handling
    Dense(15, activation='tanh'),
    Dense(15, activation='relu')   # Bottleneck layer
])

decoder = Sequential([
    Dense(15, activation='tanh'),
    Dense(25, activation='tanh'),
    Dense(input_dim, activation='sigmoid')  # Output must be 0-1
])

autoencoder = Sequential([encoder, decoder])

# Compile with a lower learning rate
# We use a custom Adam optimizer to learn slower but more accurately.
optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
autoencoder.compile(optimizer=optimizer, loss='mse')

print("Model Architecture Upgraded!")
autoencoder.summary()

# --- STEP 7: TRAINING ---
print("Starting Training (25 Epochs)...")
history = autoencoder.fit(
    X_train[:1000000], X_train[:1000000],  # Train on 1M samples
    epochs=25,
    batch_size=128,                        # Larger batch size for stability
    validation_data=(X_test[:20000], X_test[:20000]),
    shuffle=True
)

print("\nSUCCESS: The AI is now an expert!")

# --- STEP 8: TESTING ON ATTACKS ---
print("\n------------------------------------------------")
print("Phase 3: The 'Hacker' Test (AGGRESSIVE)")
print("------------------------------------------------")

# Calculate a smart threshold using 83rd percentile
# We check the reconstruction error on the normal validation data.
print("Calculating smart threshold (83rd percentile)...")
val_predictions = autoencoder.predict(X_test[:20000])
mse_val = np.mean(np.power(X_test[:20000] - val_predictions, 2), axis=1)

# Set the threshold at the 83rd percentile of normal traffic.
# This means we accept a 17% False Positive rate to catch more hackers.
threshold = np.percentile(mse_val, 83)

print(f"Smart Threshold set to: {threshold:.6f}")

# Get random attack data
print("Loading random attack samples...")
# Use .sample() to get a random mix of attacks, not just the first ones.
attack_traffic = df[df['Label'] == 1].sample(n=10000, random_state=42) 
attack_features = attack_traffic.drop(columns=cols_to_drop, errors='ignore')
scaled_attacks = scaler.transform(attack_features)

# Predict reconstruction error on attacks
print("Scanning attacks...")
reconstructed_attacks = autoencoder.predict(scaled_attacks)
mse_attacks = np.mean(np.power(scaled_attacks - reconstructed_attacks, 2), axis=1)

# Display results
print("\n--- FINAL DIAGNOSTICS ---")
print(f"Avg Error (Normal): {np.mean(mse_val):.6f}")
print(f"Avg Error (Attack): {np.mean(mse_attacks):.6f}")

# Count how many attacks crossed the threshold
detections = sum(mse_attacks > threshold)

print(f"\n[+] Attacks Detected: {detections} / 10,000")
print(f"[+] Detection Rate: {(detections/10000)*100:.2f}%")

# --- STEP 9: SAVE THE MODEL ---
autoencoder.save('ids_autoencoder_85percent.h5')
print("\n✅ Model saved successfully!")

# FINAL PERFORMANCE (Reproducible with seed=42):
# Detection Rate: Will be consistent on every run
# Model saved: ids_autoencoder_85percent.h5