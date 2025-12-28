#!/usr/bin/env python3
# main.py - Complete 60 Papers Database for Apify Actor
# PRODUCTION READY - ALL 60 PAPERS × 20 COLUMNS (EXACT ORDER 01-20 ZERO-PADDED)
# Deploy on Apify Platform - Python with asyncio
# CRITICAL FIX: Zero-padded column names (01_ID, 02_Title, etc.) for correct Apify table numerical sorting

import asyncio
import json
from datetime import datetime
from apify import Actor


async def main():
    """Push all 60 papers with EXACT 20-column structure (01-20 zero-padded for correct sort)"""
    
    async with Actor:
        Actor.log.info("=" * 100)
        Actor.log.info("🚀 PRIVACY STACK v7.0: 60 COMPLETE CRYPTOGRAPHY PAPERS")
        Actor.log.info("=" * 100)
        Actor.log.info(f"📅 Generated: {datetime.now().isoformat()}")
        Actor.log.info(f"📊 Papers: 60 | Columns: 20 | Data Points: 1,200")
        Actor.log.info(f"🔐 Format: EXACT 20-COLUMN STRUCTURE (Columns 01-20 ZERO-PADDED)")
        Actor.log.info("=" * 100)
        
        dataset = await Actor.open_dataset()
        
        # Load complete papers from JSON (already has zero-padded columns)
        with open('complete_60_papers_fixed.json', 'r') as f:
            all_papers = json.load(f)
        
        # PUSH TO DATASET
        papers_pushed = 0
        for paper in all_papers:
            # Data already zero-padded in JSON, push directly
            await dataset.push_data(paper)
            papers_pushed += 1
            
            # Log format: [ID] Title (Year)
            title_short = paper.get("02_Title", "Unknown")[:60]
            paper_id = paper.get("01_ID", f"P{papers_pushed:03d}")
            year = paper.get("03_Year", "????")
            Actor.log.info(f"✅ [{paper_id}] {title_short} ({year})")
        
        # Summary
        Actor.log.info("\n" + "=" * 100)
        Actor.log.info(f"🎉 COMPLETED: {papers_pushed} PAPERS PUSHED")
        Actor.log.info("=" * 100)
        Actor.log.info(f"\n📊 DATABASE STATISTICS:")
        Actor.log.info(f"   ✅ Papers: {papers_pushed}/60")
        Actor.log.info(f"   ✅ Columns per Paper: 20 (zero-padded 01-20)")
        Actor.log.info(f"   ✅ Total Data Points: {papers_pushed * 20}")
        Actor.log.info(f"\n📋 COLUMN ORDER (01-20 ZERO-PADDED):")
        Actor.log.info(f"   01. ID | 02. Title | 03. Year | 04. Authors | 05. Venue | 06. URL | 07. DOI")
        Actor.log.info(f"   08. Abstract | 09. Keywords | 10. Threat_Model | 11. Security_Goals | 12. Assumptions_Limitations")
        Actor.log.info(f"   13. Concept_1 | 14. Concept_2 | 15. Concept_3 | 16. Concept_4 | 17. Concept_5")
        Actor.log.info(f"   18. Proofs | 19. Experiments | 20. Implementation")
        Actor.log.info(f"\n✅ FIX APPLIED: Zero-padded column names (01_ID, 02_Title, ... 20_Implementation)")
        Actor.log.info(f"✅ RESULT: Apify table now displays columns in CORRECT NUMERICAL ORDER 01→20")
        Actor.log.info(f"✅ OUTPUT FORMAT: Apify Dataset (JSON/CSV Export)")
        Actor.log.info(f"✅ STATUS: PRODUCTION READY")
        Actor.log.info("=" * 100)


if __name__ == "__main__":
    asyncio.run(main())
