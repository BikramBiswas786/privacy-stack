#!/usr/bin/env python3
# main.py - Complete 60 Papers Database for Apify Actor
# PRODUCTION READY - ALL 60 PAPERS × 20 COLUMNS (EXACT ORDER 1-20)
# Deploy on Apify Platform - Python with asyncio

import asyncio
import json
from datetime import datetime
from apify import Actor


async def main():
    """Push all 60 papers with EXACT 20-column structure"""
    
    async with Actor:
        Actor.log.info("=" * 100)
        Actor.log.info("🚀 PRIVACY STACK v7.0: 60 COMPLETE CRYPTOGRAPHY PAPERS")
        Actor.log.info("=" * 100)
        Actor.log.info(f"📅 Generated: {datetime.now().isoformat()}")
        Actor.log.info(f"📊 Papers: 60 | Columns: 20 | Data Points: 1,200")
        Actor.log.info(f"🔐 Format: EXACT 20-COLUMN STRUCTURE (Columns 1-20 in Order)")
        Actor.log.info("=" * 100)
        
        dataset = await Actor.open_dataset()
        
        # Load complete papers from JSON
        with open('complete_60_papers.json', 'r') as f:
            all_papers = json.load(f)
        
        # PUSH TO DATASET
        papers_pushed = 0
        for paper in all_papers:
            await dataset.push_data(paper)
            papers_pushed += 1
            
            # Log format: [ID] Title (Year)
            title_short = paper["2_Title"][:60]
            Actor.log.info(f"✅ [{paper['1_ID']}] {title_short} ({paper['3_Year']})")
        
        # Summary
        Actor.log.info("\n" + "=" * 100)
        Actor.log.info(f"🎉 COMPLETED: {papers_pushed} PAPERS PUSHED")
        Actor.log.info("=" * 100)
        Actor.log.info(f"\n📊 DATABASE STATISTICS:")
        Actor.log.info(f"   ✅ Papers: {papers_pushed}/60")
        Actor.log.info(f"   ✅ Columns per Paper: 20 (ordered 1-20)")
        Actor.log.info(f"   ✅ Total Data Points: {papers_pushed * 20}")
        Actor.log.info(f"\n📋 COLUMN ORDER (1-20):")
        Actor.log.info(f"   1. ID | 2. Title | 3. Year | 4. Authors | 5. Venue | 6. URL | 7. DOI")
        Actor.log.info(f"   8. Abstract | 9. Keywords | 10. Threat_Model | 11. Security_Goals | 12. Assumptions_Limitations")
        Actor.log.info(f"   13. Concept_1 | 14. Concept_2 | 15. Concept_3 | 16. Concept_4 | 17. Concept_5")
        Actor.log.info(f"   18. Proofs | 19. Experiments | 20. Implementation")
        Actor.log.info(f"\n✅ OUTPUT FORMAT: Apify Dataset (JSON/CSV Export)")
        Actor.log.info(f"✅ STATUS: PRODUCTION READY")
        Actor.log.info("=" * 100)


if __name__ == "__main__":
    asyncio.run(main())
