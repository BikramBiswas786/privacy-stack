import json
import os
import requests
from datetime import datetime, timedelta
from apify_client import ApifyClient

def main():
    print("🚀 Privacy Stack v12: Real arXiv Privacy Papers!")
    
    papers = []
    
    # Privacy keywords for arXiv search
    search_queries = [
        "privacy cryptography",
        "differential privacy",
        "zero knowledge proofs",
        "homomorphic encryption",
        "secure multiparty computation",
        "privacy preserving machine learning",
        "anonymous communication mixnet",
        "blockchain privacy cryptocurrency",
        "post quantum cryptography",
        "federated learning privacy"
    ]
    
    print("📡 Fetching latest papers from arXiv...")
    
    for query in search_queries:
        try:
            # arXiv API endpoint - get latest papers
            url = "http://export.arxiv.org/api/query"
            
            # Sort by submitted date (newest first)
            params = {
                "search_query": f'cat:cs.CR AND ("privacy" OR "cryptography") AND ({query})',
                "start": 0,
                "max_results": 50,  # 50 papers per query
                "sortBy": "submittedDate",
                "sortOrder": "descending"
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            # Parse XML response
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.content)
            
            # Extract papers
            for entry in root.findall('{http://www.w3.org/2005/Atom}entry'):
                try:
                    arxiv_id = entry.find('{http://www.w3.org/2005/Atom}id').text.split('/abs/')[-1]
                    title = entry.find('{http://www.w3.org/2005/Atom}title').text.strip()
                    summary = entry.find('{http://www.w3.org/2005/Atom}summary').text.strip()
                    published = entry.find('{http://www.w3.org/2005/Atom}published').text
                    
                    # Extract year from published date
                    year = int(published.split('-')[0])
                    
                    # Get authors
                    authors = []
                    for author in entry.findall('{http://www.w3.org/2005/Atom}author'):
                        author_name = author.find('{http://www.w3.org/2005/Atom}name').text
                        authors.append(author_name)
                    
                    papers.append({
                        "arxiv_id": arxiv_id,
                        "title": title,
                        "summary": summary[:500],  # First 500 chars
                        "url": f"https://arxiv.org/abs/{arxiv_id}",
                        "pdf_url": f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                        "published": published,
                        "year": year,
                        "authors": authors[:5],  # First 5 authors
                        "query": query,
                        "categories": ["Privacy", "Cryptography", "Security"]
                    })
                except Exception as e:
                    print(f"  ⚠️ Skip paper: {e}")
                    continue
        
        except Exception as e:
            print(f"  ❌ Query '{query}' failed: {e}")
            continue
    
    # Remove duplicates (by arxiv_id)
    seen = set()
    unique_papers = []
    for paper in papers:
        if paper['arxiv_id'] not in seen:
            seen.add(paper['arxiv_id'])
            unique_papers.append(paper)
    
    papers = unique_papers
    
    # Sort by date (newest first)
    papers.sort(key=lambda x: x['published'], reverse=True)
    
    print(f"📚 Found {len(papers)} REAL privacy papers from arXiv!")
    print(f"   Latest: {papers[0]['title'][:60]}...")
    print(f"   Year range: {papers[-1]['year']} → {papers[0]['year']}")
    
    if len(papers) == 0:
        print("❌ No papers found!")
        return
    
    # Push to Apify dataset
    try:
        client = ApifyClient(os.environ.get("APIFY_TOKEN"))
        
        # Get default dataset ID from Apify environment
        dataset_id = os.environ.get("APIFY_DEFAULT_DATASET_ID")
        if dataset_id:
            dataset = client.dataset(dataset_id)
        else:
            # Fallback: Write to file
            output_file = "/tmp/papers.json"
            with open(output_file, 'w') as f:
                json.dump(papers, f, indent=2)
            print(f"✅ Saved {len(papers)} papers to dataset!")
            print("🏆 Privacy Stack COMPLETE!")
            return
        
        dataset.push_items(papers)
        print(f"✅ Pushed {len(papers)} REAL papers to dataset!")
        
    except Exception as e:
        print(f"❌ Push failed: {e}")
        # Fallback
        output_file = "/tmp/papers.json"
        with open(output_file, 'w') as f:
            json.dump(papers, f, indent=2)
        print(f"✅ Saved {len(papers)} papers to local storage!")
    
    print("🏆 Privacy Stack COMPLETE!")
    print(f"📊 Papers sorted: NEWEST {papers[0]['year']} → OLDEST {papers[-1]['year']}")

if __name__ == "__main__":
    main()
