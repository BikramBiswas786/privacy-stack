text
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

🟢 Level 2: Reviewed
Metadata verified by Jane Smith (Metadata Verifier) on 2025-12-26
Pedagogy verified by Prof. Bob Chen on 2025-12-26
Last updated: 2025-12-26
[View verification log]

text

---

## Reviewer Roles & Expectations

### Role 1: Metadata Verifier
**Responsibility:** Confirm that paper metadata is accurate and provenance is traceable.

**What they check:**
- Title, authors, year match the official source
- DOI or arXiv link resolves correctly
- Author affiliation is current
- Bibtex is formatted correctly
- No metadata is fabricated

**Time required:** 20–30 minutes per paper

**Signoff format:** "Verified 2025-12-26 by Jane Smith (Metadata Verifier) | Evidence: [link to official source]"

---

### Role 2: Crypto Reviewer
**Responsibility:** Validate that security commentary is accurate and limitations are honestly documented.

**What they check:**
- Security claims are traceable to the paper or clearly explained
- Crypto primitives are used correctly in the explanation
- Limitations section is complete
- Known attacks are documented
- No misleading safety claims

**Time required:** 1–2 hours per paper

**Signoff format:** "Crypto review completed 2025-12-26 by Dr. Alex cryptographer (Crypto Reviewer) | No exploitable flaws found in analysis; assumptions stated."

---

### Role 3: Pedagogy Reviewer
**Responsibility:** Ensure the paper's learning materials are clear, correct, and useful.

**What they check:**
- TL;DR is crisp and neutral
- Learning objectives are clear and measurable
- Threat model is explained in plain language
- Exercises have answers
- Use cases are realistic
- Reading difficulty matches target audience

**Time required:** 1–1.5 hours per paper

**Signoff format:** "Pedagogy review completed 2025-12-26 by Prof. Bob Chen (Pedagogy Reviewer) | Suitable for advanced undergraduate + graduate students; exercises tested with class."

---

## Verification Log Format

Every paper includes this section:

Verification Log
Date	Reviewer	Role	Status	Evidence
2025-12-26	Jane Smith	Metadata Verifier	✅ Verified	[Crosscheck with arXiv page]
2025-12-26	Dr. Alex	Crypto Reviewer	✅ Verified	[Security analysis complete]
2025-12-26	Prof. Bob Chen	Pedagogy Reviewer	✅ Verified	[Tested with 2 students]
text

---

## How to Transition Existing Papers

**For papers currently on Anon Lab:**

1. Start all papers at Level 1: Prototype
2. Assign a metadata verifier; they move the paper to Level 2
3. Assign a crypto reviewer; they move it to Level 3
4. For papers destined for production, hire independent auditor; move to Level 4

**Timeline:**
- Week 1–2: All papers at Level 1 or 2
- Week 3–4: 50% reach Level 3
- Month 2: 100% reach Level 2; 50% reach Level 3
- Month 3: Production-ready papers begin Level 4 audits

---

## Disputes & Updates

**If a reader challenges the verification:**
1. Post the challenge in the paper's "Discussions" section
2. Route to the relevant reviewer for re-verification
3. If reviewer agrees, update the verification log with a new entry
4. If reviewer disagrees, post both perspectives in the log

**If an author requests changes:**
1. Accept the request if it's a factual correction
2. Update metadata + add new entry to verification log
3. Notify the original reviewers for re-verification
4. Update the "Last modified" date

---

## Public Commitment

Anon Lab commits to:
- Publishing this charter publicly
- Never hiding verification logs
- Never claiming a paper is "production-ready" without independent audit evidence
- Transparently crediting all reviewers
- Updating this charter as the platform evolves

---

*This charter is version 1.0. Feedback welcomed. Contact: [your email]*
