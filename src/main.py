import asyncio
from apify import Actor

async def main():
    async with Actor:
        dataset = await Actor.open_dataset()
        
        # Test privacy papers
        privacy_papers = [
            {
                "title": "Mixmaster and Mixing with Privacy",
                "authors": "David Chaum",
                "year": 2000,
                "pdf": "https://nymtech.net/papers/mixmaster.pdf",
                "github": "https://github.com/nymtech/nym"
            },
            {
                "title": "Tor: The Second-Generation Onion Router", 
                "authors": "Roger Dingledine et al.",
                "year": 2004,
                "pdf": "https://www.torproject.org/papers/tor-design.pdf",
                "github": "https://github.com/torproject/tor"
            }
        ]
        
        await dataset.push_items(privacy_papers)
        print(f"✅ Pushed {len(privacy_papers)} privacy papers!")

asyncio.run(main())
