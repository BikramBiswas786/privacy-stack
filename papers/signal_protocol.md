# Signal Protocol: End-to-End Encryption for the Modern Web

## Canonical Metadata

**Title:** Signal Protocol

**Authors:**
- Moxie Marlinspike, Open Whisper Systems
- Trevor Perrin, Open Whisper Systems

**Year:** 2016

**Venue:** https://signal.org/docs/specifications/doubleratchet/

**Official PDF:** https://signal.org/docs/specifications/doubleratchet/

**DOI:** Not available (specification, not peer-reviewed paper)

**arXiv:** Not available

**Bibtex:**
```bibtex
@techreport{signal2016,
  author = {Marlinspike, Moxie and Perrin, Trevor},
  title = {The Signal Protocol},
  institution = {Open Whisper Systems},
  year = {2016},
  url = {https://signal.org/docs/specifications/doubleratchet/}
}
Citation (short form):

Marlinspike & Perrin (2016). Signal Protocol. Open Whisper Systems.

Metadata Status: ✅ Verified

Metadata Verifier: [Your name], Metadata Verifier | Date: 2025-12-26

Evidence:

Authors confirmed on official Signal website

Specification document published and maintained by Open Whisper Systems

Bibtex matches official citation format

text

**Completion checklist:**
- [ ] All metadata fields filled
- [ ] Bibtex tested (paste into BibTeX validator)
- [ ] Official source links verified

---

### Step 3.3: Write the TL;DR & Learning Objectives

**What to do:**
Add this section to your Signal Protocol paper:

```markdown
## TL;DR (One-Sentence Summary)

Signal Protocol is a cryptographic framework for secure asynchronous messaging 
that provides confidentiality, authenticity, forward secrecy, and break-in recovery 
using the Double Ratchet algorithm and elliptic-curve Diffie-Hellman key exchange.

---

## Learning Objectives

After reading this entry and working through the exercises, you will be able to:

1. **Explain the Double Ratchet algorithm** — describe how Signal uses ratcheting to achieve forward secrecy and break-in recovery, and explain why each ratchet step is necessary.

2. **Analyze the threat model** — identify which adversaries Signal protects against (and which it does not), and explain the assumptions required for each security guarantee.

3. **Implement a minimal Double Ratchet cipher** — write code that performs one encryption/decryption cycle of the Double Ratchet, correctly handling state, nonces, and key derivation.
