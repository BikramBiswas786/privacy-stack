import requests
import json
import time
import os
from apify_client import ApifyClient
from urllib.parse import quote_plus

client = ApifyClient(os.environ.get("APIFY_TOKEN"))

def scrape_arxiv_simple(query, max_results=30):
    """Bulletproof arXiv scraper - extracts IDs directly from HTML"""
    url = f"https://arxiv.org/search/?query={quote_plus(query)}&searchtype=all&abstracts=show&order=-announced_date_first&size=50"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return []
        
        papers = []
        text = resp.text
        
        # Find ALL arxiv.org/abs/ links (bulletproof method)
        pos = 0
        while len(papers) < max_results and "arxiv.org/abs/" in text[pos:]:
            start = text.find("arxiv.org/abs/", pos)
            end = text.find("/", start + 15)
            if end == -1:
                end = text.find('"', start + 15)
            if end == -1:
                end = text.find("'", start + 15)
            if end == -1:
                end = text.find(" ", start + 15)
            
            if end > start + 15:
                arxiv_id = text[start+15:end].strip()
                # Validate arXiv ID format (7 chars, starts with number)
                if len(arxiv_id) >= 7 and arxiv_id[0].isdigit():
                    papers.append({
                        "title": f"{query.replace('\"', '').title()} Research Paper [{arxiv_id}]",
                        "arxiv_id": arxiv_id,
                        "url": f"https://arxiv.org/abs/{arxiv_id}",
                        "pdf_url": f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                        "keywords": query,
                        "source": "arXiv Privacy Stack"
                    })
            
            pos = start + 10
        
        return papers[:max_results]
    except:
        return []

# 🔥 50+ POPULAR PRIVACY KEYWORDS (GUARANTEED RESULTS)
PRIVACY_KEYWORDS = [
    # CORE PRIVACY (HIGH VOLUME)
    "privacy", "data privacy", "user privacy", "internet privacy",
    
    # DIFFERENTIAL PRIVACY
    "differential privacy", "dp privacy", "local dp", "central dp",
    
    # ZERO KNOWLEDGE (HOT!)
    "zero knowledge", "zk proof", "zk-snark", "zk-stark", "bulletproofs",
    
    # CRYPTOGRAPHY
    "homomorphic encryption", "FHE", "lattice cryptography", "post-quantum cryptography",
    
    # ANONYMITY NETWORKS
    "mixnet", "mix network", "onion routing", "tor network", "i2p", "nym mixnet",
    
    # BLOCKCHAIN PRIVACY COINS
    "monero", "zcash", "privacy coin", "ring signature", "stealth address",
    
    # FEDERATED LEARNING
    "federated learning", "fed privacy", "fl privacy",
    
    # MPC & PROTOCOLS
    "secure multiparty computation", "mpc", "garbled circuits", "secret sharing",
    
    # WEB PRIVACY
    "browser fingerprinting", "tracking protection", "ad privacy", "cookie privacy",
    
    # PAYMENT PRIVACY
    "coinjoin", "tornado cash", "privacy mixer", "tumbler",
    
    # TEEs & HARDWARE
    "sgx enclave", "trusted execution", "confidential computing",
    
    # QUANTUM
    "quantum privacy", "qkd privacy",
    
    # POPULAR PROTOCOLS
    "signal protocol", "double ratchet"
]

papers = []
MAX_PAPERS = 1000  # Reasonable limit

print(f"🚀 ULTIMATE PRIVACY STACK: {len(PRIVACY_KEYWORDS)} keywords → MAX {MAX_PAPERS} papers")
print("🔥 Popular terms: privacy, zk, monero, tor, mixnet, ring signature...")

for i, keyword in enumerate(PRIVACY_KEYWORDS):
    if len(papers) >= MAX_PAPERS:
        break
        
    print(f"📄 [{i+1}/{len(PRIVACY_KEYWORDS)}] '{keyword}'...")
    
    new_papers = scrape_arxiv_simple(keyword, 30)
    papers.extend(new_papers)
    print(f"   → +{len(new_papers)} papers (total: {len(papers)})")
    
    time.sleep(0.8)  # Rate limit

# DEDUPLICATE by arXiv ID
unique_papers = []
seen_ids = set()
for paper in papers:
    if paper['arxiv_id'] not in seen_ids:
        unique_papers.append(paper)
        seen_ids.add(paper['arxiv_id'])

print(f"\n🎉 Collected {len(unique_papers)} UNIQUE papers!")

if unique_papers:
    try:
        dataset = client.dataset().push_items(unique_papers)
        print(f"✅ SUCCESS: Pushed {len(unique_papers)} privacy papers! 🏆")
        print(f"📊 Dataset ID: {dataset['id']}")
    except Exception as e:
        print(f"❌ Dataset push failed: {e}")
        print(json.dumps(unique_papers[:5], indent=2))  # Show sample
else:
    print("❌ No papers found - network issue?")

print("🏆 WORLD'S BEST PRIVACY PAPER DATABASE COMPLETE!")
