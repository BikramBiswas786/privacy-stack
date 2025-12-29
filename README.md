# Privacy Stack 🔐

**Ultimate Privacy Research Scraper** - Converts peer-reviewed privacy papers into reproducible, auditable research datasets.

## Features

✅ **GitHub Scraping** - 50+ privacy projects (Nym, Tor, Monero, ZK-proofs, etc.)
✅ **arXiv Mining** - Latest privacy research papers
✅ **Production-Ready** - Error handling, async processing, structured output
✅ **Apify Native** - Full Actor SDK integration for easy deployment

## Installation

### Prerequisites

- Python 3.11+
- Docker
- Git

### Steps

Clone repo
git clone https://github.com/BikramBiswas786/privacy-stack
cd privacy-stack

Install dependencies
pip install -r requirements.txt

Run locally
python src/main.py

## Usage

### On Apify Platform

1. **Go to:** https://apify.com/bikrambiswas/privacy-stack
2. **Configure inputs:**
   - Sources: `["github", "arxiv"]`
   - Keywords: `["mixnet", "zk-proof", "tor"]`
   - Max Results: `100`
3. **Click Run** → Download dataset

### Local Testing

Create input.json
cat > input.json << 'EOF'
{
"sources": ["github", "arxiv"],
"keywords": ["mixnet", "zk-proof"],
"maxResults": 50
}
EOF

Run actor
APIFY_INPUT=$(cat input.json) python src/main.py

## Output Format

{
"projects": [
{
"name": "nymtech/nym",
"stars": 1200,
"url": "https://github.com/nymtech/nym",
"description": "Nym provides strong network privacy",
"language": "Rust",
"source": "github",
"keyword": "mixnet"
},
{
"title": "Loopix: Scalable Mixnet",
"url": "https://arxiv.org/abs/...",
"published": "2024-01-15",
"summary": "Anonymous communication infrastructure...",
"source": "arxiv",
"keyword": "mixnet"
}
],
"total": 25,
"scrapedAt": "2025-12-29T17:53:08.123456"
}

## Technologies

- **Language:** Python 3.11
- **HTTP Client:** httpx (async)
- **RSS Parser:** feedparser
- **Platform:** Apify SDK
- **APIs:** GitHub REST, arXiv RSS

## Author

[Bikram Biswas](https://apify.com/bikrambiswas) - Privacy & Anonymity Research
Save to: README.md

🚀 DEPLOYMENT STEPS
Copy ALL 7 files to your GitHub repo

Commit: git commit -am "Fix: Complete working Privacy Stack"

Push: git push origin main

Wait 2 mins for Apify to rebuild

Apify Console → Click "Run" → SUCCESS! 🎉

✅ VERIFY YOU HAVE
privacy-stack/
├── requirements.txt           ✅ (apify==1.5.1)
├── src/
│   └── main.py               ✅ (from apify import Actor)
├── .actor/
│   ├── actor.json            ✅
│   ├── input_schema.json     ✅
│   ├── output_schema.json    ✅
│   └── Dockerfile            ✅
└── README.md                 ✅

