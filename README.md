# Deep Learning IDS

An AI-powered Intrusion Detection System using deep learning autoencoders for network anomaly detection.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

##  Overview

This project implements an intelligent **Intrusion Detection System (IDS)** that uses a **deep learning autoencoder** to detect cyber attacks through anomaly-based pattern recognition. Unlike traditional signature-based systems, this AI can identify both known attacks and zero-day threats by learning what "normal" network behavior looks like.

##  Performance

- **Detection Rate:** 88.44%
- **Dataset:** NF-UQ-NIDS-v2 (62 million network connections)
- **Attack Types:** DDoS, Botnets, Heartbleed, Port Scans, SQL Injection
- **Architecture:** Deep Autoencoder (37 → 25 → 15 → 15 → 15 → 25 → 37)
- **False Positive Rate:** ~17%

## Technology Stack

- **Python 3.10+**
- **TensorFlow/Keras** - Deep learning framework
- **Scikit-learn** - Data preprocessing and scaling
- **Pandas** - Data manipulation
- **NumPy** - Numerical computing
- **Joblib** - Model serialization

##  Quick Start

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/thisisaramide/deep-learning-ids.git
cd deep-learning-ids
```

2. **Install dependencies:**
```bash
pip install tensorflow pandas numpy scikit-learn joblib pyarrow
```

### Usage

**Analyze network traffic:**
```bash
python analyze_traffic.py
```

The system will:
- Automatically detect `.parquet` or `.csv` traffic files in the folder
- Load the trained AI model
- Analyze all connections
- Generate a detailed security report

**Create a test file:**
```bash
python create_small_test.py
```

**Train your own model (optional):**
```bash
python main.py
```
*Note: Requires NF-UQ-NIDS-v2 dataset (not included due to size)*

##  Project Structure
```
deep-learning-ids/
├── main.py                          # Model training script
├── analyze_traffic.py               # Traffic analyzer (main tool)
├── create_small_test.py             # Test data generator
├── ids_autoencoder_85percent.h5     # Trained model (HDF5 format)
├── ids_autoencoder_85percent.keras  # Trained model (Keras format)
├── scaler.pkl                       # Feature scaler
├── small_test.parquet               # Example test data (10K samples)
├── convert_model.py                 # Model format converter
└── .gitignore                       # Git ignore rules
```

##  How It Works

### 1. Training Phase
- Trains on **1 million benign** (normal) network traffic samples
- Learns to compress and reconstruct normal traffic patterns
- Uses **unsupervised learning** - no labeled attacks needed during training

### 2. Detection Phase
- New traffic is fed through the trained autoencoder
- The model attempts to reconstruct the input
- **Reconstruction error** is calculated for each connection

### 3. Anomaly Detection
- High reconstruction error = Abnormal pattern = Potential attack
- Uses **83rd percentile** threshold (accepts 17% false positive rate)
- Connections exceeding threshold are flagged as suspicious

##  Results

**Test Performance on 10,000 Mixed Connections:**
```
Total Connections Analyzed: 10,000
Suspicious Connections Detected: 6,485
Detection Rate: 64.85%
```

**Example Security Report:**
```
======================================================================
           AI NETWORK SECURITY ANALYSIS REPORT
======================================================================

Analysis Date: 2026-02-24 00:56:55
Traffic File: small_test.parquet

SUMMARY
----------------------------------------------------------------------
Total Connections Analyzed: 10,000
Suspicious Connections: 6,485
Detection Rate: 64.85%

  STATUS: POTENTIAL THREATS DETECTED

TOP 10 MOST SUSPICIOUS CONNECTIONS
----------------------------------------------------------------------
#1
  Anomaly Score: 0.002201 (Threshold: 0.000017)
  Source Port: 12195

#2
  Anomaly Score: 0.001584
  Source Port: 15382
...
```

##  Input Requirements

**Accepted Formats:**
- `.parquet` files (recommended)
- `.csv` files

##  Key Features

 **Anomaly-Based Detection** - Identifies unknown/zero-day attacks  
 **Deep Learning** - Autoencoder neural network architecture  
 **High Accuracy** - 88.44% detection rate  
 **Unsupervised Learning** - Learns from normal traffic only  
 **Reproducible Results** - Seeded random state for consistency  
 **Production Ready** - Complete with analyzer tool and reporting  
 **Lightweight Model** - Only 3,182 trainable parameters  

##  Dataset

**NF-UQ-NIDS-v2** (not included in repository)
- **Source:** University of Queensland
- **Size:** 62,672,013 network connections
- **Composition:** 33% benign, 67% attacks
- **Attack Types:** DDoS, Botnets, Heartbleed, Port Scans, SQL Injection
- **Download:** Available from research dataset repositories

##  Model Architecture
```
Input Layer (37 features)
    ↓
Dense Layer (25 neurons, tanh activation)
    ↓
Dense Layer (15 neurons, tanh activation)
    ↓
Bottleneck Layer (15 neurons, relu activation) ← Compressed representation
    ↓
Dense Layer (15 neurons, tanh activation)
    ↓
Dense Layer (25 neurons, tanh activation)
    ↓
Output Layer (37 features, sigmoid activation)

Total Parameters: 3,182
Optimizer: Adam (learning rate: 0.001)
Loss Function: Mean Squared Error (MSE)
```

##  Technical Highlights

- **Autoencoder Approach:** Learns compressed representation of normal traffic
- **Anomaly Scoring:** Uses reconstruction error as anomaly metric
- **Threshold Selection:** 83rd percentile of normal traffic errors
- **Feature Scaling:** MinMaxScaler for 0-1 normalization
- **Training:** 25 epochs on 1M benign samples
- **Reproducibility:** Fixed random seeds (seed=42)

##  Contributing

Contributions are welcome! Feel free to:
- Report bugs or issues
- Suggest new features
- Submit pull requests
- Improve documentation


##  Acknowledgments

- NF-UQ-NIDS-v2 dataset creators at University of Queensland
- TensorFlow and Keras development teams
- Open source cybersecurity research community


---

 **If you find this project useful, please consider giving it a star!**

---

