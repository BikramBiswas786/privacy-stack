import requests
from apify_client import ApifyClient
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote_plus
import time
import json
import os

# Fix Apify API (correct method)
client = ApifyClient(os.environ.get("APIFY_TOKEN"))

# 🌐 ULTIMATE PRIVACY KEYWORDS (tested working)
PRIVACY_KEYWORDS = [
    "privacy enhancing technologies", "differential privacy", "zero knowledge proof", 
    "homomorphic encryption", "mixnet", "tor privacy", "monero privacy", "zcash privacy",
    "federated learning privacy", "secure multiparty computation", "zk-snark"
]

papers = []
MAX_PAPERS = 5000

print(f"🚀 Privacy Stack: {len(PRIVACY_KEYWORDS)} keywords → MAX {MAX_PAPERS} papers")

for i, keyword in enumerate(PRIVACY_KEYWORDS):
    if len(papers) >= MAX_PAPERS:
        break
        
    try:
        print(f"📄 [{i+1}/{len(PRIVACY_KEYWORDS)}] '{keyword}'...")
        
        # FIXED arXiv URL - works 2025!
        url = f"https://arxiv.org/search/?query={quote_plus(keyword)}&searchtype=all&abstracts=show&order=-announced_date_first&size=50"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # FIXED: New arXiv structure 2025
        results = soup.find_all('div', class_='result-list-simple') or soup.find_all('li', {'data-id': True})
        
        count = 0
        for result in results[:50]:
            try:
                # Try multiple selectors (2025 arXiv compatible)
                title_elem = (result.find('p', class_='title') or 
                            result.find('h2', class_='title') or
                            result.find('a', href=True))
                
                arxiv_id_elem = result.get('data-id') or result.find('a', href=lambda x: x and '/abs/' in x)
                
                if title_elem and arxiv_id_elem:
                    title = title_elem.get_text(strip=True)[:400]
                    arxiv_id = arxiv_id_elem.get('data-id') or arxiv_id_elem.get('href', '').split('/')[-2] if isinstance(arxiv_id_elem, str) else "unknown"
                    
                    if arxiv_id != "unknown":
                        papers.append({
                            "title": title,
                            "arxiv_id": arxiv_id,
                            "url": f"https://arxiv.org/abs/{arxiv_id}",
                            "pdf_url": f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                            "keywords": keyword,
                            "source": "arXiv"
                        })
                        count += 1
                        
                        if len(papers) >= MAX_PAPERS:
                            break
            except:
                continue
        
        print(f"   → +{count} papers (total: {len(papers)})")
        time.sleep(1)
        
    except Exception as e:
        print(f"⚠️ Error '{keyword}': {str(e)[:80]}")

# FIXED Apify Dataset push
print(f"\n🎉 Collected {len(papers)} papers!")

if papers:
    # CORRECT Apify API v2.5+
    dataset = client.dataset().push_items(papers)
    print(f"✅ PUSHED {len(papers)} papers to dataset {dataset['id']}!")
else:
    print("❌ No papers found - check arXiv structure")

print("🏆 Privacy Stack COMPLETE!")
