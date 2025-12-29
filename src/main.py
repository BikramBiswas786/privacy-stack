cat > src/main.py << 'EOF'
"""
Privacy Stack - Ultimate Privacy Project Scraper
Scrapes 50+ privacy papers, crypto projects, mixnets, ZK implementations
Built for privacy builders, developers, engineers
"""

from apify import Actor
import httpx
import json
from datetime import datetime, timedelta
from typing import List, Dict

async def main():
    """Main Actor function"""
    
    async with Actor:
        # Get input
        input_data = Actor.get_input() or {}
        
        Actor.log.info(f"Input data: {input_data}")
        
        sources = input_data.get("sources", ["github"])
        keywords = input_data.get("keywords", ["mixnet", "zk-proof", "tor"])
        stars_min = input_data.get("starsMin", 50)
        updated_days = input_data.get("updatedDays", 90)
        language = input_data.get("language", "All")
        max_results = input_data.get("maxResults", 100)
        include_metadata = input_data.get("includeMetadata", True)
        
        Actor.log.info(f"Scraping {sources} with keywords: {keywords}")
        
        all_projects = []
        
        # GitHub scraping
        if "github" in sources:
            Actor.log.info("Starting GitHub scrape...")
            github_projects = await scrape_github(keywords, stars_min, updated_days, language, max_results)
            all_projects.extend(github_projects)
            Actor.log.info(f"Found {len(github_projects)} GitHub projects")
        
        # arXiv scraping
        if "arxiv" in sources:
            Actor.log.info("Starting arXiv scrape...")
            arxiv_papers = await scrape_arxiv(keywords, max_results)
            all_projects.extend(arxiv_papers)
            Actor.log.info(f"Found {len(arxiv_papers)} arXiv papers")
        
        # Reddit scraping
        if "reddit" in sources:
            Actor.log.info("Starting Reddit scrape...")
            reddit_posts = await scrape_reddit(keywords, max_results)
            all_projects.extend(reddit_posts)
            Actor.log.info(f"Found {len(reddit_posts)} Reddit posts")
        
        # Push results to dataset
        Actor.log.info(f"Pushing {len(all_projects)} results to dataset...")
        for project in all_projects[:max_results]:
            await Actor.push_data(project)
        
        Actor.log.info(f"Done! Scraped {len(all_projects)} privacy projects/papers")


async def scrape_github(keywords: List[str], stars_min: int, updated_days: int, language: str, max_results: int) -> List[Dict]:
    """Scrape GitHub for privacy projects"""
    projects = []
    
    try:
        async with httpx.AsyncClient() as client:
            for keyword in keywords[:10]:  # Limit to 10 keywords per run
                # Calculate date filter
                if updated_days > 0:
                    since_date = (datetime.now() - timedelta(days=updated_days)).strftime("%Y-%m-%d")
                    date_filter = f"pushed:>{since_date}"
                else:
                    date_filter = ""
                
                # Build search query
                lang_filter = f"language:{language}" if language != "All" else ""
                query = f"{keyword} {lang_filter} stars:>{stars_min} {date_filter}".strip()
                
                url = "https://api.github.com/search/repositories"
                params = {
                    "q": query,
                    "sort": "stars",
                    "order": "desc",
                    "per_page": 30
                }
                
                try:
                    response = await client.get(url, params=params, timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    
                    for repo in data.get("items", [])[:max_results - len(projects)]:
                        projects.append({
                            "source": "github",
                            "type": "repository",
                            "name": repo["name"],
                            "url": repo["html_url"],
                            "owner": repo["owner"]["login"],
                            "description": repo["description"],
                            "stars": repo["stargazers_count"],
                            "forks": repo["forks_count"],
                            "watchers": repo["watchers_count"],
                            "language": repo["language"],
                            "topics": repo.get("topics", []),
                            "updated": repo["updated_at"],
                            "created": repo["created_at"],
                            "keyword": keyword,
                            "scraped_at": datetime.now().isoformat()
                        })
                except Exception as e:
                    print(f"Error scraping GitHub keyword '{keyword}': {e}")
    
    except Exception as e:
        print(f"GitHub scraping error: {e}")
    
    return projects


async def scrape_arxiv(keywords: List[str], max_results: int) -> List[Dict]:
    """Scrape arXiv for privacy papers"""
    papers = []
    
    try:
        import feedparser
        
        for keyword in keywords[:5]:  # Limit to 5 keywords
            url = f"http://export.arxiv.org/api/query?search_query=cat:cs.CR%20AND%20{keyword}&start=0&max_results=20&sortBy=submittedDate&sortOrder=descending"
            
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:max_results - len(papers)]:
                    papers.append({
                        "source": "arxiv",
                        "type": "paper",
                        "title": entry.title,
                        "url": entry.id,
                        "authors": [author.name for author in entry.authors],
                        "summary": entry.summary,
                        "published": entry.published,
                        "keyword": keyword,
                        "scraped_at": datetime.now().isoformat()
                    })
            except Exception as e:
                print(f"Error scraping arXiv keyword '{keyword}': {e}")
    
    except Exception as e:
        print(f"arXiv scraping error: {e}")
    
    return papers


async def scrape_reddit(keywords: List[str], max_results: int) -> List[Dict]:
    """Scrape Reddit for privacy discussions"""
    posts = []
    
    # Placeholder - requires Reddit API credentials
    # Implementation would use PRAW library
    
    return posts


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
EOF
cat src/main.py


