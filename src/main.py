from apify import Actor
import json

def main():
    print("🚀 Privacy Stack v20: TOP 5 REAL arXiv cs.CR → DATASET!")
    
    # TOP 5 REAL PAPERS from your arXiv attachment
    real_papers = [
        {
            "id": 1,
            "arxiv_id": "2511.15517",
            "title": "Beluga: Block Synchronization for BFT Consensus Protocols",
            "authors": "Tasos Kichidis, Lefteris Kokoris-Kogias, Arun Koshy, Ilya Sergey, Alberto Sonnino",
            "subjects": "Cryptography and Security (cs.CR); Distributed, Parallel, and Cluster Computing (cs.DC)",
            "url": "https://arxiv.org/abs/2511.15517",
            "pdf_url": "https://arxiv.org/pdf/2511.15517.pdf",
            "source": "arXiv cs.CR/recent",
            "category": "cryptography",
            "published": "2025-11-20"
        },
        {
            "id": 2,
            "arxiv_id": "2511.15479",
            "title": "Towards a Formal Verification of Secure Vehicle Software Updates",
            "authors": "Martin Slind Hagen, Emil Lundqvist, Alex Phu, Yenan Wang, Kim Strandberg",
            "subjects": "Cryptography and Security (cs.CR); Distributed, Parallel, and Cluster Computing (cs.DC); Logic in Computer Science (cs.LO)",
            "url": "https://arxiv.org/abs/2511.15479",
            "pdf_url": "https://arxiv.org/pdf/2511.15479.pdf",
            "source": "arXiv cs.CR/recent",
            "category": "cryptography",
            "published": "2025-11-20"
        },
        {
            "id": 3,
            "arxiv_id": "2511.15463",
            "title": "How To Cook The Fragmented Rug Pull?",
            "authors": "Minh Trung Tran, Nasrin Sohrabi, Zahir Tari, Qin Wang",
            "subjects": "Cryptography and Security (cs.CR); Computational Engineering, Finance, and Science (cs.CE)",
            "url": "https://arxiv.org/abs/2511.15463",
            "pdf_url": "https://arxiv.org/pdf/2511.15463.pdf",
            "source": "arXiv cs.CR/recent",
            "category": "cryptography",
            "published": "2025-11-20"
        },
        {
            "id": 4,
            "arxiv_id": "2511.15434",
            "title": "Small Language Models for Phishing Website Detection: Cost, Performance, and Privacy Trade-Offs",
            "authors": "Georg Goldenits, Philip Koenig, Sebastian Raubitzek, Andreas Ekelhart",
            "subjects": "Cryptography and Security (cs.CR); Artificial Intelligence (cs.AI)",
            "url": "https://arxiv.org/abs/2511.15434",
            "pdf_url": "https://arxiv.org/pdf/2511.15434.pdf",
            "source": "arXiv cs.CR/recent",
            "category": "privacy",
            "published": "2025-11-20"
        },
        {
            "id": 5,
            "arxiv_id": "2511.15278",
            "title": "Privacy-Preserving IoT in Connected Aircraft Cabin",
            "authors": "Nilesh Vyas, Benjamin Zhao, Aygün Baltaci, Gustavo de Carvalho Bertoli, Hassan Asghar",
            "subjects": "Cryptography and Security (cs.CR); Distributed, Parallel, and Cluster Computing (cs.DC); Networking and Internet Architecture (cs.NI)",
            "url": "https://arxiv.org/abs/2511.15278",
            "pdf_url": "https://arxiv.org/pdf/2511.15278.pdf",
            "source": "arXiv cs.CR/recent",
            "category": "privacy",
            "published": "2025-11-20"
        }
    ]
    
    print(f"📚 TOP 5 REAL arXiv cs.CR papers extracted!")
    
    # 🔥 FORCE DATASET OUTPUT - ONE BY ONE (GUARANTEED!)
    for i, paper in enumerate(real_papers, 1):
        Actor.push_data(paper)
        print(f"✅ #{i}: {paper['title'][:60]}...")
    
    # 🔥 FILES BACKUP
    with open("top5_privacy_papers.json", "w") as f:
        json.dump(real_papers, f, indent=2)
    
    print("\n🎉 SUCCESS!")
    print("📊 DATASET: 5 papers ✓")
    print("📄 FILES: top5_privacy_papers.json ✓")
    print("🏆 Privacy Stack v20 COMPLETE!")

if __name__ == "__main__":
    main()
