#!/usr/bin/env python3
"""Privacy Stack - Ultimate Privacy Research Scraper"""
from apify import Actor
import json
from typing import Dict, Any
import httpx
import feedparser
from datetime import datetime

async def main():
    """Apify Actor entrypoint"""
    async with Actor:
        # Parse input
        input_data = await Actor.get_input() or {}
        Actor.log.info(f"Input: {json.dumps(input_data, indent=2)}")
        
        # Defaults
        sources = input_data.get('sources', ['github', 'arxiv'])
        keywords = input_data.get('keywords', ['mixnet', 'zk-proof'])
        
        # Scrape
        results = []
        if 'github' in sources:
            results.extend(await scrape_github(keywords))
        if 'arxiv' in sources:
            results.extend(await scrape_arxiv(keywords))
        
        # Push to dataset
        await Actor.push_data({
            'projects': results, 
            'scrapedAt': datetime.utcnow().isoformat(),
            'total': len(results)
        })
        
        Actor.log.info(f"✅ Found {len(results)} privacy projects!")

async def scrape_github(keywords: list) -> list:
    """Scrape GitHub privacy repos"""
    results = []
    headers = {'User-Agent': 'PrivacyStack/1.0'}
    
    for keyword in keywords:
        url = f"https://api.github.com/search/repositories?q={keyword}+privacy+stars:>50"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=10.0)
                data = resp.json()
                
                for repo in data.get('items', [])[:5]:
                    results.append({
                        'name': repo['full_name'],
                        'stars': repo['stargazers_count'],
                        'url': repo['html_url'],
                        'description': repo['description'] or '',
                        'language': repo['language'],
                        'source': 'github',
                        'keyword': keyword
                    })
        except Exception as e:
            Actor.log.error(f"GitHub {keyword} error: {e}")
    
    return results

async def scrape_arxiv(keywords: list) -> list:
    """Scrape arXiv privacy papers"""
    results = []
    for keyword in keywords:
        url = f"http://export.arxiv.org/api/query?search_query=all:{keyword}+AND+privacy&start=0&max_results=5"
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                results.append({
                    'title': entry.title,
                    'url': entry.link,
                    'published': getattr(entry, 'published', ''),
                    'summary': (entry.summary or '')[:200] + '...',
                    'source': 'arxiv',
                    'keyword': keyword
                })
        except Exception as e:
            Actor.log.error(f"arXiv {keyword} error: {e}")
    
    return results

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
