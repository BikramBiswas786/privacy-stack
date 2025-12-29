#!/usr/bin/env python3
"""
Privacy Stack - Test Actor
Scrapes privacy research papers
"""

import asyncio
from apify import Actor

async def main():
    async with Actor:
        dataset = await Actor.open_dataset()
        
        # Privacy papers dataset
        papers = [
            {
                "id": 1,
                "title": "Mixmaster and Mixing with Privacy",
                "authors": "David Chaum",
                "year": 2000,
                "pdf_url": "https://nymtech.net/papers/mixmaster.pdf",
                "github": "https://github.com/nymtech/nym",
                "category": "mixnets"
            },
            {
                "id": 2,
                "title": "Tor: The Second-Generation Onion Router",
                "authors": "Roger Dingledine, Nick Mathewson",
                "year": 2004,
                "pdf_url": "https://www.torproject.org/papers/tor-design.pdf",
                "github": "https://github.com/torproject/tor",
                "category": "onion-routing"
            },
            {
                "id": 3,
                "title": "Nym Sphinx: A Cryptographic Network Protocol",
                "authors": "Nym Technologies",
                "year": 2021,
                "pdf_url": "https://nymtech.net/papers/sphinx.pdf",
                "github": "https://github.com/nymtech/nym",
                "category": "mixnets"
            }
        ]
        
        # Push to dataset
        await dataset.push_items(papers)
        
        print(f"✅ SUCCESS: Pushed {len(papers)} privacy papers to dataset!")
        print("🎉 Privacy Stack test COMPLETE!")

if __name__ == "__main__":
    asyncio.run(main())
