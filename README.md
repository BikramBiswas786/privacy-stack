# Privacy Stack 🔐

**Ultimate Privacy Research Scraper** - Converts peer-reviewed privacy papers into reproducible, auditable research datasets.

text
# Privacy Stack 🛡️ 1500+ REAL arXiv Privacy Papers

[![Dataset Schema](https://img.shields.io/badge/Dataset-Schema%20✓-green.svg)](https://console.apify.com/view/runs)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://apify.com)
[![Runs](https://badgen.net/apify/actor-runs/oblate_wildcat/privacy-stack)](https://console.apify.com/oblate_wildcat/privacy-stack/runs)

**Scrapes 5000 UNIQUE real arXiv cs.CR papers** across **4 privacy categories** (1250 papers each).

## 📊 Categories
🌐 Internet Privacy: Tor, mixnets, I2P, anonymous routing
🔐 Crypto Privacy: ZK proofs, FHE, MPC, Bulletproofs
📊 Data Privacy: Differential Privacy, Federated Learning
⚛️ Post-Quantum: Kyber, Dilithium, SPHINCS+, Falcon

text

## 🚀 Features
- ✅ **100% REAL** arXiv papers (no fakes)
- ✅ **ZERO duplicates** (global + per-category deduplication)
- ✅ **Balanced categories** (1250 papers each)
- ✅ **Production dataset schema** (6 output tabs)
- ✅ **No requirements.txt** (Apify Python 3.11 environment)

## 🎯 Apify Console Output Tabs
📚 All Papers (5000 total)
🌐 Internet Privacy (1250)
🔐 Crypto Privacy (1250)
📊 Data Privacy (1250)
⚛️ Post-Quantum (1250)
📋 Live Logs

text

## 📥 Sample Output
{
"id": 1,
"title": "Device-Independent Anonymous Communication",
"arxiv_id": "2512.21047",
"full_category": "Internet Privacy",
"authors": ["John Doe", "Jane Smith"],
"url": "https://arxiv.org/abs/2512.21047",
"pdf_url": "https://arxiv.org/pdf/2512.21047.pdf",
"is_real_arxiv": true
}

text

## 🚀 Quick Start
Run in Apify Console: https://console.apify.com/oblate_wildcat/privacy-stack
Or CLI:
apify run privacy-stack-research-scraper

text

**Live Actor:** [Apify Console](https://console.apify.com/oblate_wildcat/privacy-stack)
