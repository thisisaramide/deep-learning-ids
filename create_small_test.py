import pandas as pd

print("=" * 50)
print("Creating Small Test File")
print("=" * 50)
print()

# Load the full dataset
print("📂 Loading NF-UQ-NIDS-v2.parquet...")
df = pd.read_parquet('NF-UQ-NIDS-v2.parquet')

print(f"✅ Loaded {len(df):,} total connections")
print()

# Show breakdown
benign_count = len(df[df['Label'] == 0])
attack_count = len(df[df['Label'] == 1])

print(f"Dataset composition:")
print(f"  - Benign (safe): {benign_count:,}")
print(f"  - Attacks: {attack_count:,}")
print()

# Take 10,000 random samples
print("🎲 Selecting 10,000 random samples...")
small_sample = df.sample(n=10000, random_state=42)

# Save as new file
print("💾 Saving as 'small_test.parquet'...")
small_sample.to_parquet('small_test.parquet')

# Show what we created
small_benign = len(small_sample[small_sample['Label'] == 0])
small_attacks = len(small_sample[small_sample['Label'] == 1])

print()
print("=" * 50)
print("✅ SUCCESS!")
print("=" * 50)
print()
print(f"Created: small_test.parquet")
print(f"Size: 10,000 connections")
print(f"  - Benign: {small_benign:,}")
print(f"  - Attacks: {small_attacks:,}")
print()
print("You can now run: python analyze_traffic.py")
print("=" * 50)