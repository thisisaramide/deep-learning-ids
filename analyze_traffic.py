import pandas as pd
import numpy as np
import joblib
from tensorflow.keras.models import load_model
from datetime import datetime
import glob
import os

print("=" * 60)
print("       🛡️  AI NETWORK INTRUSION DETECTION SYSTEM  🛡️")
print("=" * 60)
print()

# --- AUTO-DETECT TRAFFIC FILE ---
print("🔍 Searching for network traffic files...")

# Look for parquet or CSV files in current folder
traffic_files = glob.glob("*.parquet") + glob.glob("*.csv")

# Exclude the training dataset
traffic_files = [f for f in traffic_files if 'NF-UQ-NIDS' not in f]

if len(traffic_files) == 0:
    print("❌ No traffic files found!")
    print("   Please place a .parquet or .csv file in this folder")
    input("\nPress Enter to exit...")
    exit()
elif len(traffic_files) == 1:
    filename = traffic_files[0]
    print(f"✅ Found: {filename}")
else:
    print(f"📁 Found {len(traffic_files)} files:")
    for i, f in enumerate(traffic_files, 1):
        print(f"   {i}. {f}")
    choice = int(input("\nWhich file to analyze? Enter number: ")) - 1
    filename = traffic_files[choice]

print()

# --- LOAD AI MODEL AND SCALER ---
print("🤖 Loading AI model and scaler...")
try:
    model = load_model('ids_autoencoder_85percent.h5', compile=False)
    scaler = joblib.load('scaler.pkl')
    threshold = 0.000017
    print("✅ AI system ready!")
except Exception as e:
    print(f"❌ ERROR: Could not load model/scaler - {e}")
    print("   Make sure 'ids_autoencoder_88percent.h5' and 'scaler.pkl' are in this folder")
    input("\nPress Enter to exit...")
    exit()

print()

# --- LOAD TRAFFIC DATA ---
print(f"📊 Loading traffic data from {filename}...")
try:
    if filename.endswith('.parquet'):
        df = pd.read_parquet(filename)
    else:
        df = pd.read_csv(filename)
    print(f"✅ Loaded {len(df):,} network connections")
except Exception as e:
    print(f"❌ ERROR: Could not load file - {e}")
    input("\nPress Enter to exit...")
    exit()

print()

# --- PREPARE DATA ---
print("⚙️  Preparing data for analysis...")

cols_to_drop = [
    'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 
    'L4_SRC_PORT', 'L4_DST_PORT', 
    'Attack', 'Label', 'Dataset', 
    'DNS_QUERY_ID', 'ICMP_TYPE'
]

features = df.drop(columns=cols_to_drop, errors='ignore')
scaled_data = scaler.transform(features)

print("✅ Data prepared")
print()

# --- RUN AI ANALYSIS ---
print("🔬 AI analyzing traffic patterns...")
print("   (This may take a moment for large files)")
print()

# Show progress during prediction
predictions = model.predict(scaled_data, verbose=1)  # Changed verbose=0 to verbose=1
errors = np.mean(np.power(scaled_data - predictions, 2), axis=1)

attacks_detected = sum(errors > threshold)
total_connections = len(df)
detection_rate = (attacks_detected / total_connections) * 100

# --- GENERATE REPORT ---
report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

with open(report_filename, 'w', encoding='utf-8') as f:
    f.write("=" * 70 + "\n")
    f.write("           AI NETWORK SECURITY ANALYSIS REPORT\n")
    f.write("=" * 70 + "\n\n")
    f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"Traffic File: {filename}\n")
    f.write(f"AI Model: ids_autoencoder_85percent.h5\n")
    f.write("\n" + "-" * 70 + "\n")
    f.write("SUMMARY\n")
    f.write("-" * 70 + "\n\n")
    f.write(f"Total Connections Analyzed: {total_connections:,}\n")
    f.write(f"Suspicious Connections: {attacks_detected:,}\n")
    f.write(f"Detection Rate: {detection_rate:.2f}%\n\n")
    
    if attacks_detected > 0:
        f.write("⚠️  STATUS: POTENTIAL THREATS DETECTED\n\n")
        
        f.write("-" * 70 + "\n")
        f.write("TOP 10 MOST SUSPICIOUS CONNECTIONS\n")
        f.write("-" * 70 + "\n\n")
        
        suspicious_indices = np.argsort(errors)[-10:][::-1]
        
        for i, idx in enumerate(suspicious_indices, 1):
            f.write(f"#{i}\n")
            f.write(f"  Anomaly Score: {errors[idx]:.6f} (Threshold: {threshold:.6f})\n")
            
            if 'IPV4_SRC_ADDR' in df.columns:
                f.write(f"  Source IP: {df.iloc[idx]['IPV4_SRC_ADDR']}\n")
            if 'IPV4_DST_ADDR' in df.columns:
                f.write(f"  Destination IP: {df.iloc[idx]['IPV4_DST_ADDR']}\n")
            if 'L4_SRC_PORT' in df.columns:
                f.write(f"  Source Port: {df.iloc[idx]['L4_SRC_PORT']}\n")