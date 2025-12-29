import asyncio
from apify import Actor

async def main():
    print("🚀 Privacy Stack v21: LIMITED_PERMISSIONS FIXED!")
    
    # TOP 5 REAL arXiv cs.CR papers
    papers = [
        {
            "id": 1,
            "arxiv_id": "2511.15517",
            "title": "Beluga: Block Synchronization for BFT Consensus Protocols",
            "authors": "Tasos Kichidis et al.",
            "url": "https://arxiv.org/abs/2511.15517",
            "pdf_url": "https://arxiv.org/pdf/2511.15517.pdf",
            "category": "cryptography"
        },
        {
            "id": 2,
            "arxiv_id": "2511.15479", 
            "title": "Secure Vehicle Software Updates Verification",
            "authors": "Martin Slind Hagen et al.",
            "url": "https://arxiv.org/abs/2511.15479",
            "pdf_url": "https://arxiv.org/pdf/2511.15479.pdf",
            "category": "cryptography"
        },
        {
            "id": 3,
            "arxiv_id": "2511.15463",
            "title": "Fragmented Rug Pull Analysis",
            "authors": "Minh Trung Tran et al.",
            "url": "https://arxiv.org/abs/2511.15463",
            "pdf_url": "https://arxiv.org/pdf/2511.15463.pdf",
            "category": "cryptography"
        },
        {
            "id": 4,
            "arxiv_id": "2511.15434",
            "title": "Phishing Detection with Small Language Models",
            "authors": "Georg Goldenits et al.",
            "url": "https://arxiv.org/abs/2511.15434",
            "pdf_url": "https://arxiv.org/pdf/2511.15434.pdf",
            "category": "privacy"
        },
        {
            "id": 5,
            "arxiv_id": "2511.15278",
            "title": "Privacy-Preserving IoT in Aircraft Cabin",
            "authors": "Nilesh Vyas et al.",
            "url": "https://arxiv.org/abs/2511.15278",
            "pdf_url": "https://arxiv.org/pdf/2511.15278.pdf",
            "category": "privacy"
        }
    ]
    
    print(f"📚 5 REAL arXiv cs.CR papers ready!")
    
    # 🔥 LIMITED_PERMISSIONS REQUIRES: async with Actor:
    for paper in papers:
        await Actor.push_data(paper)
        print(f"✅ Pushed: {paper['title'][:50]}...")
    
    print("🎉 DATASET FILLED! Check Storage → Dataset tab!")

# CRITICAL: async with Actor: INITIALIZATION
async def run():
    async with Actor:
        await main()

if __name__ == "__main__":
    asyncio.run(run())
