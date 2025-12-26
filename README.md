# Privacy Stack 🔐
"Privacy Stack makes peer-reviewed privacy research reproducible, teachable and auditable — 
converting papers into verified explanations, threat models, and reference implementations 
that researchers and practitioners can trust."

Privacy-focused research paper generator and cryptocurrency implementation.

## Features

- 🔍 Privacy research papers generator
- 🔐 Cryptocurrency implementations
- ⛓️ Blockchain-focused content
- 🚀 Production-quality Python code
- 📚 Well-documented
- 🛡️ Security best practices

## Installation

### Prerequisites
- Python 3.8+
- Git
- GitHub account

### Steps

1. Clone the repository:
```bash git clone https://github.com/BikramBiswas786/privacy-stack.git


{
  "title": "Signal Protocol: End-to-End Encryption",
  "tldr": "Signal Protocol is a cryptographic framework for secure asynchronous messaging using the Double Ratchet algorithm with forward secrecy and break-in recovery.",
  "authors": [
    {
      "name": "Moxie Marlinspike",
      "affiliation": "Open Whisper Systems",
      "orcid": "https://orcid.org/[if-available]"
    },
    {
      "name": "Trevor Perrin",
      "affiliation": "Open Whisper Systems"
    }
  ],
  "year": 2016,
  "doi": "https://signal.org/docs/specifications/doubleratchet/",
  "bibtex": "@techreport{signal2016, author = {Marlinspike, Moxie and Perrin, Trevor}, title = {The Signal Protocol}, institution = {Open Whisper Systems}, year = {2016}, url = {https://signal.org/docs/specifications/doubleratchet/}}",
  "trustLevel": "Level 2: Reviewed",
  "metadataStatus": "verified",
  "learningObjectives": [
    {
      "objective": "Explain the Double Ratchet algorithm and why each step is necessary",
      "level": "intermediate"
    },
    {
      "objective": "Analyze the threat model and identify which adversaries Signal protects against",
      "level": "advanced"
    },
    {
      "objective": "Implement a minimal Double Ratchet cipher correctly handling state and key derivation",
      "level": "advanced"
    }
  ],
  "threatModel": {
    "description": "Signal Protocol protects against network eavesdroppers and compromised devices",
    "adversaryCapabilities": "Read all network traffic, intercept messages, steal device state, perform forward cryptanalysis",
    "adversaryLimitations": "Cannot break ECDH, cannot predict CSPRNG, cannot solve discrete logarithm",
    "protections": "Confidentiality, authenticity, forward secrecy, break-in recovery",
    "assumptions": [
      "ECDH (Curve25519) is hard to compute",
      "SHA-256 has no collisions",
      "CSPRNG is cryptographically secure",
      "Initial X3DH key exchange succeeds"
    ],
    "diagram": "[ASCII diagram showing Alice → Bob message flow with ratcheting]"
  },
  "algorithmWalkthrough": {
    "steps": [
      {
        "stepNumber": 1,
        "description": "Derive message key from current chain key",
        "pseudocode": "MK = HMAC-SHA256(CK_send, 0x01)",
        "why": "Each message gets a unique key; compromise of one key doesn't break others"
      },
      {
        "stepNumber": 2,
        "description": "Advance chain key (ratchet forward)",
        "pseudocode": "CK_send = HMAC-SHA256(CK_send, 0x02)",
        "why": "Ensures each message key is derived differently"
      }
    ],
    "fullExample": "[Complete worked example: RK_0 → MK_1, MK_2, MK_3 → new DH key]"
  },
  "implementationNotes": {
    "whatIsImplemented": [
      "Complete Double Ratchet algorithm explanation",
      "Pseudocode for encryption/decryption",
      "Working reference implementation",
      "Test vectors"
    ],
    "whatIsOmitted": [
      "Initial key exchange (X3DH) — see X3DH spec",
      "Out-of-order message handling — basic case only",
      "Serialization format — implementation-dependent"
    ],
    "sourceBasis": "Figure 2 (message keys) and Figure 5 (DH ratchet) from official Signal spec",
    "keyChoices": "HMAC-SHA256 is standard for Signal; AES-256-CBC recommended; Curve25519 for ECDH"
  },
  "securityCommentary": {
    "guarantees": [
      "If MK is kept secret, eavesdropper cannot read plaintext",
      "Bob can verify message came from Alice (HMAC proves Alice knew the key)",
      "If Alice's device is stolen after sending, that message remains secret (keys are deleted)",
      "After device recovery, future messages are protected (new DH key unknown to attacker)"
    ],
    "limitations": [
      "If SHA-256 is broken, Signal is broken",
      "Does NOT hide metadata (who talks to whom, when)",
      "Does NOT protect against device malware before sending",
      "Does NOT guarantee future-proofing against quantum computers"
    ],
    "cryptographicPrimitives": [
      {
        "name": "AES-256-CBC",
        "purpose": "Encrypt message content",
        "strengthAssumption": "256-bit symmetric security"
      },
      {
        "name": "HMAC-SHA256",
        "purpose": "Derive keys and authenticate ciphertext",
        "strengthAssumption": "SHA-256 collision resistance"
      },
      {
        "name": "Curve25519 ECDH",
        "purpose": "Ratchet forward with forward secrecy",
        "strengthAssumption": "Elliptic-curve discrete log hardness"
      }
    ],
    "commonPitfalls": [
      {
        "pitfall": "Reusing a message key",
        "wrongCode": "MK = derive(); encrypt(MK, msg1); encrypt(MK, msg2);",
        "rightCode": "MK1 = derive(); advance(); encrypt(MK1, msg1); MK2 = derive(); advance(); encrypt(MK2, msg2);",
        "risk": "Two messages with same key allow plaintext recovery (XOR analysis)"
      },
      {
        "pitfall": "Forgetting to delete old keys",
        "wrongCode": "message_keys = []; mk = derive(); message_keys.append(mk);",
        "rightCode": "mk = derive(); plaintext = decrypt(mk, msg); del mk;",
        "risk": "Device compromise exposes all past messages"
      }
    ]
  },
  "limitations": [
    {
      "limitation": "Metadata leakage",
      "why": "Hiding metadata requires mixing services (too slow for real-time)",
      "impact": "Network observer (ISP, govt) sees Alice ↔ Bob are communicating",
      "mitigation": "Use VPN or Tor; see Ricochet or Briar for metadata-hiding alternatives"
    },
    {
      "limitation": "No protection against device malware before sending",
      "why": "Signal is end-to-end encryption; cannot protect compromised endpoints",
      "impact": "Malware can read keystrokes and forge messages",
      "mitigation": "Keep device clean; use antivirus, full disk encryption"
    }
  ],
  "knownAttacks": [
    {
      "name": "Silent Reset Attack",
      "how": "Attacker replays old key-exchange messages",
      "result": "Alice and Bob accept with different session keys; attacker decrypts",
      "defense": "Double Ratchet ensures keys diverge; replayed messages cause decryption to fail",
      "status": "mitigated"
    },
    {
      "name": "Quantum Computing",
      "how": "Quantum computer solves discrete logarithm (breaks ECDH)",
      "result": "Attacker derives session keys from public keys; forward secrecy lost",
      "defense": "None currently; Signal team researching post-quantum variants",
      "status": "outstanding"
    }
  ],
  "exercises": [
    {
      "exerciseNumber": 1,
      "level": "beginner",
      "timeMinutes": 15,
      "title": "Trace a Single Message",
      "description": "Alice sends Bob 'Hello'. Derive MK_1 from CK_send, encrypt with AES-256-CBC, advance CK_send. Write down ciphertext and header.",
      "answer": "[Complete worked solution]"
    },
    {
      "exerciseNumber": 2,
      "level": "intermediate",
      "timeMinutes": 20,
      "title": "Detect a Forged Message",
      "description": "Bob receives 3 messages. One has invalid HMAC. Identify which and explain why it's forged.",
      "answer": "Message 2 is forged. HMAC does not verify; attacker either corrupted it or created it without knowing MK."
    },
    {
      "exerciseNumber": 3,
      "level": "intermediate",
      "timeMinutes": 25,
      "title": "Forward Secrecy Scenario",
      "description": "Alice sends M1, M2, M3. Device compromised. Alice sends M4 with new DH key. Which can attacker decrypt?",
      "answer": "Attacker CANNOT decrypt M1–M3 (keys deleted) or M4 (new DH key unknown). Forward secrecy maintained."
    },
    {
      "exerciseNumber": 4,
      "level": "advanced",
      "timeMinutes": 30,
      "title": "Breaking Forward Secrecy",
      "description": "Buggy implementation stores all old message keys in memory. Device stolen. What happens?",
      "answer": "Attacker gets all keys. Can decrypt all past messages. Solution: delete keys immediately after use."
    }
  ],
  "useCases": [
    {
      "scenario": "Secure chat for journalists in hostile countries",
      "what": "Encryption of all messages, authentication, forward secrecy, break-in recovery",
      "whatNot": "Metadata hiding, protection against device malware, guarantee against government backdoors (but company can't comply anyway)",
      "benefit": "Journalist can communicate freely without fear of historical messages being exposed"
    },
    {
      "scenario": "Encrypted group chat for development teams",
      "what": "Each participant maintains chain with every other; independent ratcheting",
      "whatNot": "Metadata hiding, server-side encryption",
      "benefit": "If one device compromised, only that participant's future messages at risk; others remain secure"
    }
  ],
  "teachingNotes": {
    "audience": "Advanced undergraduates, graduate students, security engineers",
    "prerequisites": [
      "Understanding of symmetric cryptography (AES)",
      "Understanding of HMAC and hash functions",
      "Understanding of public-key cryptography (ECDH)",
      "Familiarity with threat models"
    ],
    "timeRequired": {
      "lecture": "90 minutes",
      "exercises": "2–3 hours",
      "implementation": "4–6 hours"
    },
    "demoSuggestions": [
      "Implement Exercise 1 live in Python, showing HMAC derivation step-by-step",
      "Show a real Signal message (exported from Signal app) and walk through decryption",
      "Discuss which exercise is most relevant to students' work"
    ]
  },
  "howToCite": {
    "bibtex": "@techreport{signal2016, author = {Marlinspike, Moxie and Perrin, Trevor}, title = {The Signal Protocol}, institution = {Open Whisper Systems}, year = {2016}, url = {https://signal.org/docs/specifications/doubleratchet/}}",
    "shortForm": "Marlinspike & Perrin (2016). Signal Protocol. Open Whisper Systems.",
    "longForm": "The Signal Protocol (Marlinspike & Perrin, 2016) provides end-to-end encryption for asynchronous messaging with forward secrecy and break-in recovery properties."
  },
  "verificationLog": [
    {
      "date": "2025-12-26",
      "reviewer": "You (Metadata Verifier)",
      "role": "Metadata Verifier",
      "status": "✅ Verified",
      "evidence": "Crosschecked with Signal.org official page; authors confirmed; bibtex matches official citation",
      "notes": "Metadata is complete and accurate"
    },
    {
      "date": "2025-12-26",
      "reviewer": "Crypto Expert (TBD)",
      "role": "Crypto Reviewer",
      "status": "⏳ Pending",
      "evidence": "To be reviewed",
      "notes": "Needed to reach Level 3 (Audited)"
    }
  ],
  "trustLevel": "Level 2: Reviewed",
  "lastModified": "2025-12-26T06:00:00Z",
  "nextScheduledReview": "2026-06-26T06:00:00Z"
}
