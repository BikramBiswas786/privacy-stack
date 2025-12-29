#!/usr/bin/env python3
"""Privacy Stack - Ultimate Privacy Research Scraper"""
import os
from apify_client import ApifyClient  # Apify SDK
import json
from typing import Dict, Any
import httpx
import feedparser
from datetime import datetime

def main():
    """Main Apify Actor entrypoint"""
    # Parse input
    input_data = json.loads(os.environ.get('APIFY_INPUT', '{}'))
    print(f"Input: {json.dumps(input_data, indent=2)}")
    
    # Default input
    sources = input_data.get('sources', ['github', 'arxiv'])
    keywords = input_data.get('keywords', ['mixnet', 'zk-proof'])
    
    # Scrape privacy projects
    results = []
    
    if 'github' in sources:
        results.extend(scrape_github(keywords))
    
    if 'arxiv' in sources:
        results.extend(scrape_arxiv(keywords))
    
    # Output results
    dataset = {'projects': results, 'scrapedAt': datetime.utcnow().isoformat()}
    print(f"Found {len(results)} privacy projects")
    
    # Save to Apify dataset
    with open('/tmp/output.json', 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print("✅ Privacy Stack complete!")

def scrape_github(keywords: list) -> list:
    """Scrape GitHub for privacy repos"""
    results = []
    headers = {'User-Agent': 'PrivacyStack/1.0'}
    
    for keyword in keywords:
        url = f"https://api.github.com/search/repositories?q={keyword}+privacy+stars:>50"
        try:
            resp = httpx.get(url, headers=headers, timeout=10.0)
            data = resp.json()
            
            for repo in data.get('items', [])[:5]:
                results.append({
                    'name': repo['full_name'],
                    'stars': repo['stargazers_count'],
                    'url': repo['html_url'],
                    'description': repo['description'],
                    'language': repo['language'],
                    'source': 'github',
                    'keyword': keyword
                })
        except Exception as e:
            print(f"GitHub {keyword} error: {e}")
    
    return results

def scrape_arxiv(keywords: list) -> list:
    """Scrape arXiv for privacy papers"""
    results = []
    for keyword in keywords:
        url = f"http://export.arxiv.org/api/query?search_query=all:{keyword}+AND+privacy&start=0&max_results=5"
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                results.append({
                    'title': entry.title,
                    'url': entry.link,
                    'published': entry.published,
                    'summary': entry.summary[:200] + '...',
                    'source': 'arxiv',
                    'keyword': keyword
                })
        except Exception as e:
            print(f"arXiv {keyword} error: {e}")
    
    return results

if __name__ == '__main__':
    main()
