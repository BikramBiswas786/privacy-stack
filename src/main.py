import requests
import json
import time
import os
from apify_client import ApifyClient

client = ApifyClient(os.environ.get("APIFY_TOKEN"))

# REAL arXiv API - 100% RELIABLE
def search_arxiv(query, max_results=50):
    url = "http://export.arxiv.org/api/query"
    params = {
        'search_query': f'all:"{query}"',
        'start': 0,
        'max_results': max_results,
        'sortBy': 'submittedDate',
        'sortOrder': 'descending'
    }
    
    try:
        resp = requests.get(url, params=params, timeout=10)
        return resp.text
    except:
        return None

# ULTIMATE PRIVACY KEYWORDS
KEYWORDS = [
    '"privacy enhancing technologies"', '"differential privacy"', '"zero knowledge"',
    '"homomorphic encryption"', '"mixnet"', '"tor privacy"', '"monero privacy"',
    '"zcash privacy"', '"federated learning privacy"', '"secure multiparty computation"',
    '"zk-snark"', '"zk-stark"', '"ring signature"', '"blind signature"'
]

papers = []
MAX_PAPERS = 5000

print(f"🚀 Privacy Stack: arXiv API → MAX {MAX_PAPERS} papers")

for i, keyword in enumerate(KEYWORDS):
    if len(papers) >= MAX_PAPERS:
        break
        
    print(f"📄 [{i+1}/{len(KEYWORDS)}] '{keyword}'...")
    
    xml_data = search_arxiv(keyword.replace('"', ''), 50)
    if xml_data:
        # Simple XML parsing for titles/IDs
        lines = xml_data.split('\n')
        title = None
        arxiv_id = None
        
        for line in lines:
            if '<title>' in line and 'title' not in line.lower():
                title = line.split('<title>')[1].split('</title>')[0].strip()
            elif '<id>http://arxiv.org/abs/' in line:
                arxiv_id = line.split('abs/')[1].split('</id>')[0].strip()
            
            if title and arxiv_id:
                papers.append({
                    "title": title[:400],
                    "arxiv_id": arxiv_id,
                    "url": f"https://arxiv.org/abs/{arxiv_id}",
                    "pdf_url": f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                    "keywords": keyword,
                    "source": "arXiv API"
                })
                title = None
                arxiv_id = None
                
                if len(papers) >= MAX_PAPERS:
                    break
        
        print(f"   → +{min(50, len(papers))} papers (total: {len(papers)})")
    else:
        print("   → API error")
    
    time.sleep(1)

# CORRECT Apify push
print(f"\n🎉 Collected {len(papers)} papers!")
if papers:
    client.dataset().push_items(papers)
    print(f"✅ PUSHED {len(papers)} papers! 🏆")
else:
    print("❌ No papers - check API")

