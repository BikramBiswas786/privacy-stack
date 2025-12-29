import asyncio
from apify import Actor
import httpx
import time
import xml.etree.ElementTree as ET
from datetime import datetime

async def main():
    print("🚀 Privacy Stack v48: NO REPEATS - TRUE 4-CATEGORY BALANCE!")
    
    base_url = "https://export.arxiv.org/api/query?"
    
    # 4 CATEGORIES - SPECIFIC KEYWORDS ONLY
    category_queries = {
        "Internet Privacy": [
            'cat:cs.CR AND (tor OR onion OR mixnet OR remailer OR "anonymous communication")',
            '"traffic analysis" AND anonymity',
            '"anonymous routing" OR i2p',
        ],
        "Cryptographic Privacy": [
            '"zero knowledge" OR zk-snark OR bulletproofs OR "zk-stark"',
            '"homomorphic encryption" OR FHE OR "secure multi-party"',
            '"multi-party computation" OR MPC',
        ],
        "Data Privacy": [
            '"differential privacy" OR DP-SGD',
            '"federated learning" AND privacy',
            '"privacy-preserving machine learning"',
        ],
        "Post-Quantum Privacy": [
            '"post-quantum" OR kyber OR dilithium OR sphincs OR falcon',
            '"lattice-based" OR "quantum-safe" OR "quantum-resistant"',
            '"quantum cryptography" AND privacy',
        ]
    }
    
    all_papers = []
    paper_id = 1
    
    # PER-CATEGORY duplicate tracking
    category_papers = {cat: [] for cat in category_queries.keys()}
    all_seen_ids = set()
    
    # TARGET: 1250 UNIQUE per category
    target_per_category = 1250
    
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        for category, queries in category_queries.items():
            print(f"\n📚 [{len(category_papers[category])}/{target_per_category}] {category}")
            
            while len(category_papers[category]) < target_per_category:
                # Try all queries for this category
                query_found = False
                for query_idx, query in enumerate(queries):
                    if len(category_papers[category]) >= target_per_category:
                        break
                    
                    # Skip if already got enough from this query
                    start_pos = len(category_papers[category]) * 2  # Stagger results
                    max_results = min(100, target_per_category - len(category_papers[category]))
                    
                    params = {
                        'search_query': query,
                        'start': str(start_pos),
                        'max_results': str(max_results),
                        'sortBy': 'submittedDate',
                        'sortOrder': 'descending'
                    }
                    
                    try:
                        print(f"  🔍 Q{query_idx+1}: {query[:40]}... (start={start_pos})")
                        response = await client.get(base_url, params=params)
                        response.raise_for_status()
                        
                        root = ET.fromstring(response.content)
                        entries = root.findall('{http://www.w3.org/2005/Atom}entry')
                        
                        new_count = 0
                        for entry in entries:
                            arxiv_id = None
                            
                            # Extract arXiv ID
                            arxiv_id_elem = entry.find('{http://arxiv.org/schemas/atom}arxiv_id')
                            if arxiv_id_elem is not None and arxiv_id_elem.text:
                                arxiv_id = arxiv_id_elem.text.strip()
                            else:
                                id_elem = entry.find('{http://www.w3.org/2005/Atom}id')
                                if id_elem is not None:
                                    arxiv_id = id_elem.text.split('/')[-1].strip()
                            
                            # GLOBAL + CATEGORY duplicate check
                            if not arxiv_id or arxiv_id in all_seen_ids:
                                continue
                            
                            all_seen_ids.add(arxiv_id)
                            
                            # Extract metadata
                            title_elem = entry.find('{http://www.w3.org/2005/Atom}title')
                            title = title_elem.text.strip()[:200] if title_elem is not None else "Privacy Research"
                            
                            published_elem = entry.find('{http://www.w3.org/2005/Atom}published')
                            published = published_elem.text[:10] if published_elem is not None else "2025-01-01"
                            
                            authors = []
                            for author_elem in entry.findall('{http://www.w3.org/2005/Atom}author'):
                                name_elem = author_elem.find('{http://www.w3.org/2005/Atom}name')
                                if name_elem is not None:
                                    authors.append(name_elem.text.strip())
                            authors = authors[:3]
                            
                            summary_elem = entry.find('{http://www.w3.org/2005/Atom}summary')
                            summary = summary_elem.text.strip()[:150] if summary_elem is not None else ""
                            
                            paper = {
                                "id": paper_id,
                                "title": title,
                                "arxiv_id": arxiv_id,
                                "publication_year": int(published[:4]),
                                "published": published,
                                "authors": authors,
                                "summary": summary,
                                "url": f"https://arxiv.org/abs/{arxiv_id}",
                                "pdf_url": f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                                "full_category": category,
                                "source": f"{category} [{arxiv_id}]",
                                "research_value": "Research Breakthrough",
                                "concept_short": summary[:100] + "..." if summary else f"{category} research",
                                "developer_suggestions": f"Build {category.lower().replace(' ', '-')} from {arxiv_id}",
                                "implementation_areas": [f"{category.split()[0].lower()}-protocol"],
                                "use_cases": [f"{category.lower().replace(' ', '-')}"],
                                "is_real_arxiv": True
                            }
                            
                            category_papers[category].append(paper)
                            all_papers.append(paper)
                            paper_id += 1
                            new_count += 1
                            
                            if len(category_papers[category]) >= target_per_category:
                                break
                        
                        print(f"  ✅ +{new_count} papers (now {len(category_papers[category])})")
                        query_found = new_count > 0
                        
                        await asyncio.sleep(3)
                        
                    except Exception as e:
                        print(f"  ❌ {str(e)[:50]}")
                        await asyncio.sleep(5)
                        continue
                
                if not query_found:
                    print(f"  ⚠️ No more papers found for {category}")
                    break
            
            print(f"📊 {category}: {len(category_papers[category])} papers ✓")
    
    # Final trim
    all_papers = all_papers[:5000]
    
    print(f"\n{'='*80}")
    print(f"🎉 {len(all_papers)} TOTAL REAL PAPERS - NO DUPLICATES!")
    
    for category in category_queries.keys():
        count = len([p for p in all_papers if p['full_category'] == category])
        print(f"📈 {category}: {count} papers")
    
    print(f"{'='*80}")
    
    # Push results
    for i, paper in enumerate(all_papers):
        await Actor.push_data(paper)
        if (i + 1) % 100 == 0:
            print(f"📤 Pushed {i+1}/{len(all_papers)}")

async def run():
    async with Actor:
        await main()

if __name__ == "__main__":
    asyncio.run(run())
