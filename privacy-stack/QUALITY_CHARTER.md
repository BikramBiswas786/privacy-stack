# Anon Lab Quality Charter
*Published: 2025-12-26 | Last updated: [TODAY]*

## What This Document Is

This charter defines the trust levels for every paper published on Anon Lab. 
It tells you exactly what verification each paper has undergone and what it does 
and does not guarantee.

---

## Four Trust Levels

### Level 1: Prototype
**Definition:** Minimal, educational, unverified.

**What it includes:**
- Original paper title, author, year
- Basic summary (1–2 paragraphs)
- Code snippet (illustrative only)

**What it does NOT guarantee:**
- Metadata is verified
- Code runs without error
- Crypto is correct
- It is safe for production use

**When to use:** Learning the concept; exploring ideas; teaching a class.

**Reviewer signoff:** None required.

**Example:** "Understanding Signal Protocol: a walkthrough" (no DOI link, no threat model yet)

---

### Level 2: Reviewed
**Definition:** Human-verified metadata + reviewer signoff on pedagogy.

**What it includes:**
- All Level 1 items, PLUS:
- Canonical metadata (DOI, arXiv, authors, year, venue verified via official source)
- One-sentence TL;DR
- Three learning objectives
- Threat model (text + diagram)
- Verification log with reviewer name, role, date

**What it does NOT guarantee:**
- Cryptographic correctness (see Level 3 for that)
- Code is production-ready
- Independent security audit

**When to use:** Using in a classroom; reading for understanding; citing in papers.

**Reviewer signoff:** Required from metadata verifier + pedagogy reviewer.

**Example:** "Signal Protocol: End-to-End Encryption Explained" (DOI verified, threat model present, reviewed by Dr. X)

---

### Level 3: Audited
**Definition:** Cryptographic review by an expert + reproducibility tests pass.

**What it includes:**
- All Level 2 items, PLUS:
- Security commentary (crypto correctness, plain English)
- Implementation notes (what's simplified, what's full)
- All limitations listed
- All known attacks documented
- Code passes reproducibility tests
- Crypto reviewer signoff

**What it does NOT guarantee:**
- Independent third-party security audit
- It is safe for production use without additional hardening
- No new attacks will be discovered

**When to use:** Building on this research; teaching advanced courses; engineering reference.

**Reviewer signoff:** Required from metadata + pedagogy + crypto reviewer.

**Example:** "Signal Protocol: Reference Implementation & Security Analysis" (tested, crypto reviewed by Dr. Y, no new exploits found)

---

### Level 4: Production
**Definition:** Independent security audit + legal review + CI passing.

**What it includes:**
- All Level 3 items, PLUS:
- Independent third-party security audit (name of auditor, date, link to report)
- Legal review (license, liability, ethical use)
- Automated test suite (CI/CD passing)
- Performance benchmarks
- Deployment guide

**What it DOES guarantee:**
- Third-party auditor found no exploitable flaws in the code
- Legal review completed
- Tests are automated and passing
- Safe for production use under stated assumptions

**What it does NOT guarantee:**
- Future-proof against new cryptanalytic attacks
- No possible misuse by end users

**When to use:** Production systems; high-stakes applications; regulatory compliance.

**Reviewer signoff:** Required from all roles + independent auditor signoff.

**Example:** "Signal Protocol: Audited Production Implementation" (audited by Cure53 on 2025-12, legal OK, CI green)

---

## How Levels Appear on Anon Lab

Every paper shows a badge:

