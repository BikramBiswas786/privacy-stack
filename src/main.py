#!/usr/bin/env python3
"""Privacy Stack - Ultimate Privacy Research Scraper"""
from apify import Actor
import json
import httpx
import feedparser
from datetime import datetime

async def main():
    """Apify Actor entrypoint"""
    async with Actor:
        # Get input
        input_data = await Actor.get_input() or {}
        Actor.log.info(f"Input: {json.dumps(input_data, indent=2)}")
        
        # Defaults
        sources = input_data.get('sources', ['github', 'arxiv'])
        keywords = input_data.get('keywords', ['mixnet', 'zk-proof'])
        max_results = input_data.get('maxResults', 100)
        
        # Scrape
        results = []
        
        if 'github' in sources:
            github_results = await scrape_github(keywords)
            results.extend(github_results)
            Actor.log.info(f"GitHub: {len(github_results)} repos")
        
        if 'arxiv' in sources:
            arxiv_results = await scrape_arxiv(keywords)
            results.extend(arxiv_results)
            Actor.log.info(f"arXiv: {len(arxiv_results)} papers")
        
        # Limit results
        results = results[:max_results]
        
        # Push to dataset
        await Actor.push_data({
            'projects': results,
            'scrapedAt': datetime.utcnow().isoformat(),
            'total': len(results),
            'sources': sources,
            'keywords': keywords
        })
        
        Actor.log.info(f"✅ Privacy Stack complete! Found {len(results)} items")

async def scrape_github(keywords: list) -> list:
    """Scrape GitHub for privacy repos"""
    results = []
    headers = {'User-Agent': 'PrivacyStack/1.0'}
    
    for keyword in keywords:
        url = f"https://api.github.com/search/repositories?q={keyword}+privacy+stars:>50&sort=stars&order=desc&per_page=5"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=10.0)
                data = resp.json()
                
                for repo in data.get('items', []):
                    results.append({
                        'name': repo['full_name'],
                        'stars': repo['stargazers_count'],
                        'url': repo['html_url'],
                        'description': repo.get('description') or '',
                        'language': repo.get('language') or '',
                        'updated': repo.get('updated_at'),
                        'source': 'github',
                        'keyword': keyword
                    })
        except Exception as e:
            Actor.log.error(f"GitHub {keyword}: {str(e)}")
    
    return results

async def scrape_arxiv(keywords: list) -> list:
    """Scrape arXiv for privacy papers"""
    results = []
    
    for keyword in keywords:
        url = f"http://export.arxiv.org/api/query?search_query=all:{keyword}+AND+privacy&start=0&max_results=5&sortBy=submittedDate&sortOrder=descending"
        try:
            feed = feedparser.parse(url)
            
            for entry in feed.entries:
                results.append({
                    'title': entry.get('title', ''),
                    'url': entry.get('link', ''),
                    'published': entry.get('published', ''),
                    'authors': ', '.join([a.get('name', '') for a in entry.get('authors', [])]),
                    'summary': (entry.get('summary', '') or '')[:300],
                    'source': 'arxiv',
                    'keyword': keyword
                })
        except Exception as e:
            Actor.log.error(f"arXiv {keyword}: {str(e)}")
    
    return results

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
