#!/usr/bin/env python3
"""
Privacy Stack - Direct Dataset Push (No Apify SDK)
"""

import json
import requests
import os

# Get Actor environment vars
APIFY_TOKEN = os.getenv('APIFY_TOKEN')
APIFY_DEFAULT_DATASET_ID = os.getenv('APIFY_DEFAULT_DATASET_ID')

if not APIFY_TOKEN or not APIFY_DEFAULT_DATASET_ID:
    print("❌ Missing Apify env vars")
    exit(1)

# Privacy papers dataset
papers = [
    {
        "id": 1,
        "title": "Mixmaster and Mixing with Privacy",
        "authors": "David Chaum",
        "year": 2000,
        "pdf_url": "https://nymtech.net/papers/mixmaster.pdf",
        "github": "https://github.com/nymtech/nym",
        "category": "mixnets"
    },
    {
        "id": 2,
        "title": "Tor: The Second-Generation Onion Router",
        "authors": "Roger Dingledine, Nick Mathewson",
        "year": 2004,
        "pdf_url": "https://www.torproject.org/papers/tor-design.pdf",
        "github": "https://github.com/torproject/tor",
        "category": "onion-routing"
    },
    {
        "id": 3,
        "title": "Nym Sphinx: A Cryptographic Network Protocol",
        "authors": "Nym Technologies",
        "year": 2021,
        "pdf_url": "https://nymtech.net/papers/sphinx.pdf",
        "github": "https://github.com/nymtech/nym",
        "category": "mixnets"
    }
]

# Direct API push to dataset
url = f"https://api.apify.com/v2/datasets/{APIFY_DEFAULT_DATASET_ID}/items?token={APIFY_TOKEN}"
response = requests.post(url, json=papers)

if response.status_code == 201:
    print(f"✅ SUCCESS: Pushed {len(papers)} privacy papers to dataset!")
    print("🎉 Privacy Stack LIVE!")
else:
    print(f"❌ API Error: {response.status_code}")
    print(response.text)
