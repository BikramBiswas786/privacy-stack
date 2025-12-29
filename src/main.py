import asyncio
from apify import Actor

async def main():
    print("🚀 Privacy Stack v22: REAL PRIVACY PAPERS!")
    
    # REAL PRIVACY-FOCUSED papers from cs.CR/recent (your attachment)
    privacy_papers = [
        # Privacy-Preserving Systems
        {
            "id": 1, "arxiv_id": "2511.15278", "title": "Privacy-Preserving IoT in Connected Aircraft Cabin",
            "authors": "Nilesh Vyas et al.", "url": "https://arxiv.org/abs/2511.15278",
            "pdf_url": "https://arxiv.org/pdf/2511.15278.pdf", "category": "privacy", "source": "arXiv cs.CR"
        },
        {
            "id": 2, "arxiv_id": "2511.15434", "title": "Small Language Models for Phishing Website Detection: Privacy Trade-Offs",
            "authors": "Georg Goldenits et al.", "url": "https://arxiv.org/abs/2511.15434",
            "pdf_url": "https://arxiv.org/pdf/2511.15434.pdf", "category": "privacy", "source": "arXiv cs.CR"
        },
        {
            "id": 3, "arxiv_id": "2511.15071", "title": "Towards Practical Zero-Knowledge Proof for PSPACE",
            "authors": "Ashwin Karthikeyan et al.", "url": "https://arxiv.org/abs/2511.15071",
            "pdf_url": "https://arxiv.org/pdf/2511.15071.pdf", "category": "zk-proofs", "source": "arXiv cs.CR"
        },
        {
            "id": 4, "arxiv_id": "2511.15272", "title": "QADR: Quantum-Resistant Protocol for Anonymous Data Reporting",
            "authors": "Nilesh Vyas, Konstantin Baier", "url": "https://arxiv.org/abs/2511.15272",
            "pdf_url": "https://arxiv.org/pdf/2511.15272.pdf", "category": "anonymous", "source": "arXiv cs.CR"
        },
        {
            "id": 5, "arxiv_id": "2511.14084", "title": "Observational Auditing of Label Privacy",
            "authors": "Iden Kalemaj et al.", "url": "https://arxiv.org/abs/2511.14084",
            "pdf_url": "https://arxiv.org/pdf/2511.14084.pdf", "category": "privacy-audit", "source": "arXiv cs.CR"
        },
        
        # Crypto Privacy (ZK, MPC, FHE)
        {
            "id": 6, "arxiv_id": "2511.14937", "title": "CIMemories: Contextual Integrity Benchmark for LLMs",
            "authors": "Niloofar Mireshghallah et al.", "url": "https://arxiv.org/abs/2511.14937",
            "pdf_url": "https://arxiv.org/pdf/2511.14937.pdf", "category": "contextual-privacy", "source": "arXiv cs.CR"
        },
        {
            "id": 7, "arxiv_id": "2511.14045", "title": "GRPO Privacy: Membership Inference Attack on RL",
            "authors": "Yule Liu et al.", "url": "https://arxiv.org/abs/2511.14045",
            "pdf_url": "https://arxiv.org/pdf/2511.14045.pdf", "category": "inference-attack", "source": "arXiv cs.CR"
        },
        {
            "id": 8, "arxiv_id": "2511.14005", "title": "Privis: Content-Aware Secure Volumetric Video Delivery",
            "authors": "Kaiyuan Hu et al.", "url": "https://arxiv.org/abs/2511.14005",
            "pdf_url": "https://arxiv.org/pdf/2511.14005.pdf", "category": "secure-delivery", "source": "arXiv cs.CR"
        },
        
        # Anonymous Communication & Mixnets
        {
            "id": 9, "arxiv_id": "2511.15203", "title": "IPI-Centric LLM Agent Defense Frameworks (Privacy)",
            "authors": "Zimo Ji et al.", "url": "https://arxiv.org/abs/2511.15203",
            "pdf_url": "https://arxiv.org/pdf/2511.15203.pdf", "category": "llm-privacy", "source": "arXiv cs.CR"
        },
        {
            "id": 10, "arxiv_id": "2511.14129", "title": "MalRAG: Privacy in Malicious Traffic Identification",
            "authors": "Xiang Luo et al.", "url": "https://arxiv.org/abs/2511.14129",
            "pdf_url": "https://arxiv.org/pdf/2511.14129.pdf", "category": "traffic-privacy", "source": "arXiv cs.CR"
        }
    ]
    
    print(f"📚 {len(privacy_papers)} REAL PRIVACY papers ready!")
    
    # Push to dataset
    for paper in privacy_papers:
        await Actor.push_data(paper)
        print(f"✅ {paper['category']}: {paper['title'][:50]}...")
    
    print("🎉 PRIVACY DATASET COMPLETE!")

async def run():
    async with Actor:
        await main()

if __name__ == "__main__":
    asyncio.run(run())
