import asyncio
from apify import Actor
import httpx
import time
import xml.etree.ElementTree as ET
from datetime import datetime

async def main():
    print("🚀 Privacy Stack v46: REAL arXiv Papers - 4 Categories (5000 Total)")
    
    # REAL arXiv API endpoint
    base_url = "http://export.arxiv.org/api/query?"
    
    # YOUR 4 EXACT CATEGORIES - REAL arXiv queries
    category_queries = {
        "Internet Privacy": [
            'cat:cs.CR AND (anonymity OR mixnet OR tor OR onion OR remailer)',
            'cat:cs.CR AND (anonymous communication OR anonymous routing)',
            'cat:cs.CR AND (traffic analysis OR flow analysis)',
        ],
        "Cryptographic Privacy": [
            'cat:cs.CR AND (zero-knowledge OR zk-snark OR zk-stark OR bulletproof)',
            'cat:cs.CR AND (homomorphic encryption OR FHE OR secure computation)',
            'cat:cs.CR AND (multi-party computation OR MPC OR secure MPC)',
        ],
        "Data Privacy": [
            'cat:cs.CR AND (differential privacy OR DP-SGD OR privacy-preserving)',
            'cat:cs.CR AND (federated learning AND privacy)',
            'cat:cs.CR AND (privacy-preserving machine learning)',
        ],
        "Post-Quantum Privacy": [
            'cat:cs.CR AND (post-quantum OR lattice-based OR quantum-safe)',
            'cat:cs.CR AND (Kyber OR Dilithium OR SPHINCS OR Falcon)',
            'cat:cs.CR AND (quantum cryptography OR quantum key)',
        ]
    }
    
    all_papers = []
    paper_id = 1
    seen_arxiv_ids = set()
    
    # TARGET: 1250 papers per category (4 × 1250 = 5000)
    papers_per_category = 1250
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for category, queries in category_queries.items():
            category_papers = []
            print(f"\n📚 Fetching {category}...")
            
            for query_idx, query in enumerate(queries):
                if len(category_papers) >= papers_per_category:
                    break
                
                remaining = papers_per_category - len(category_papers)
                max_results = min(remaining, 400)  # arXiv limits max 400 per request
                
                params = {
                    'search_query': query,
                    'start': 0,
                    'max_results': str(max_results),
                    'sortBy': 'submittedDate',
                    'sortOrder': 'descending'
                }
                
                try:
                    print(f"  🔍 Query {query_idx + 1}: {query[:50]}...")
                    response = await client.get(base_url, params=params)
                    response.raise_for_status()
                    
                    # Parse XML response
                    root = ET.fromstring(response.content)
                    
                    # Extract entries
                    entries_found = 0
                    for entry in root.findall('{http://www.w3.org/2005/Atom}entry'):
                        if len(category_papers) >= papers_per_category:
                            break
                        
                        try:
                            # Get arXiv ID (try multiple possible locations)
                            arxiv_id = None
                            arxiv_id_elem = entry.find('{http://arxiv.org/schemas/atom}arxiv_id')
                            if arxiv_id_elem is not None:
                                arxiv_id = arxiv_id_elem.text.strip()
                            else:
                                id_elem = entry.find('{http://www.w3.org/2005/Atom}id')
                                if id_elem is not None:
                                    arxiv_id = id_elem.text.split('/abs/')[-1].strip()
                            
                            if not arxiv_id or arxiv_id in seen_arxiv_ids:
                                continue
                            seen_arxiv_ids.add(arxiv_id)
                            
                            # Get title
                            title_elem = entry.find('{http://www.w3.org/2005/Atom}title')
                            title = title_elem.text.strip() if title_elem is not None else "Untitled"
                            
                            # Get published date
                            published_elem = entry.find('{http://www.w3.org/2005/Atom}published')
                            published = published_elem.text if published_elem is not None else "2025-01-01T00:00:00Z"
                            published_date = published[:10]
                            
                            # Get authors
                            authors = []
                            for author_elem in entry.findall('{http://www.w3.org/2005/Atom}author'):
                                name_elem = author_elem.find('{http://www.w3.org/2005/Atom}name')
                                if name_elem is not None:
                                    authors.append(name_elem.text.strip())
                            authors = authors[:3]  # First 3 authors
                            
                            # Get summary
                            summary_elem = entry.find('{http://www.w3.org/2005/Atom}summary')
                            summary = summary_elem.text.strip()[:200] if summary_elem is not None else ""
                            
                            # Parse year
                            publication_year = int(published[:4])
                            
                            paper = {
                                "id": paper_id,
                                "title": title,
                                "arxiv_id": arxiv_id,
                                "publication_year": publication_year,
                                "published": published_date,
                                "authors": authors,
                                "summary": summary,
                                "url": f"https://arxiv.org/abs/{arxiv_id}",
                                "pdf_url": f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                                "full_category": category,
                                "source": f"{category} arXiv [{arxiv_id}]",
                                "research_value": "Research Breakthrough",
                                "concept_short": summary[:100] + "..." if summary else "Privacy research paper",
                                "developer_suggestions": f"Implement {category.lower().replace(' ', '-')} using this research",
                                "implementation_areas": [f"{category.lower().replace(' ', '-')}-protocol"],
                                "use_cases": [f"{category.lower().replace(' ', '-')}-applications"],
                                "is_real_arxiv": True
                            }
                            
                            category_papers.append(paper)
                            all_papers.append(paper)
                            paper_id += 1
                            entries_found += 1
                            
                        except Exception as e:
                            print(f"    ⚠️  Parse error: {str(e)[:50]}")
                            continue
                    
                    print(f"  ✅ Got {entries_found} new papers from query {query_idx + 1}")
                    
                    # Rate limiting - arXiv API asks for 3 second delay
                    await asyncio.sleep(3)
                    
                except Exception as e:
                    print(f"  ❌ Error on query {query_idx + 1}: {str(e)}")
                    await asyncio.sleep(5)
                    continue
            
            print(f"📊 {category}: {len(category_papers)}/{papers_per_category} papers")
    
    # Final count & trim to 5000 max
    all_papers = all_papers[:5000]
    
    print(f"\n" + "="*60)
    print(f"✅ FETCHED {len(all_papers)} REAL arXiv papers!")
    print(f"✅ {len(seen_arxiv_ids)} UNIQUE arXiv IDs - ZERO DUPLICATES!")
    print(f"✅ Categories breakdown:")
    
    for category in category_queries.keys():
        count = len([p for p in all_papers if p['full_category'] == category])
        print(f"   • {category}: {count} papers")
    
    print("="*60)
    
    # Push REAL papers to Apify
    print(f"\n📤 Pushing {len(all_papers)} papers to Apify...\n")
    
    for i, paper in enumerate(all_papers):
        await Actor.push_data(paper)
        
        if (i + 1) % 500 == 0:
            print(f"✅ Pushed {i+1}/{len(all_papers)} REAL papers")
    
    print(f"\n🎉 MISSION COMPLETE!")
    print(f"🎉 {len(all_papers)} REAL arXiv Privacy Papers - 4 Categories - NO FAKES!")
    print(f"🎉 Each URL is 100% AUTHENTIC and UNIQUE!")

async def run():
    async with Actor:
        await main()

if __name__ == "__main__":
    asyncio.run(run())
