import asyncio
import json
from apify_client import ApifyClient

async def main_async():
    client = ApifyClient()

    signal_paper = {
        "title": "Signal Protocol: End-to-End Encryption with Forward Secrecy",
        "tldr": "Signal Protocol provides end-to-end encryption with forward secrecy.",
        "authors": [
            {"name": "Trevor Perrin", "affiliation": "Open Whisper Systems"},
            {"name": "Moxie Marlinspike", "affiliation": "Open Whisper Systems"}
        ],
        "year": 2013,
        "doi": "https://signal.org/docs/specifications/doubleratchet/",
        "threatModel": {
            "description": "Signal protects against eavesdropping and device compromise.",
            "adversaryCapabilities": ["Read network traffic", "Intercept messages", "Steal device state"],
            "adversaryLimitations": ["Cannot break elliptic-curve crypto", "Cannot access private keys"],
            "protections": ["Confidentiality", "Authentication", "Forward Secrecy", "Break-in Recovery"]
        },
        "learningObjectives": ["Double Ratchet", "Forward secrecy", "DH ratchet", "Threat models"],
        "exercises": [
            {
                "exerciseNumber": 1,
                "level": "beginner",
                "title": "Forward Secrecy",
                "description": "Alice sends at 3 PM. Attacker steals device at 5 PM. Can read message?",
                "answer": "No. Keys deleted. This is forward secrecy."
            },
            {
                "exerciseNumber": 2,
                "level": "intermediate",
                "title": "Chain Ratchet",
                "description": "Message 1 and 2 - same key?",
                "answer": "No. Each message uses fresh key. Unique keys for every message."
            },
            {
                "exerciseNumber": 3,
                "level": "intermediate",
                "title": "Break-in Recovery",
                "description": "Bob steals device after Message 5. Decrypt 6, 7, 8?",
                "answer": "No if new DH key sent. DH ratchet creates unknown keys."
            },
            {
                "exerciseNumber": 4,
                "level": "advanced",
                "title": "Complete Scenario",
                "description": "Attacker has RK and sk_A_old. Bob secure. New DH key. Can read?",
                "answer": "No. Uses ECDH(sk_A_new, pk_B). Attacker lacks keys. Cannot decrypt."
            }
        ],
        "algorithmWalkthrough": {
            "setup": "X3DH establishes RK_0. Initialize chain keys.",
            "aliceToB": "Derive MK, advance chain, encrypt, send.",
            "bobReceives": "Check DH, derive MK, decrypt, verify.",
            "dhRatchet": "New DH = new root keys.",
            "forwardSecrecy": "Old keys safe. New keys unknown."
        },
        "securityCommentary": {
            "whatThisGuarantees": ["Unique keys", "Authentication", "Forward Secrecy", "Break-in Recovery"],
            "whatThisDoesNOT": ["Hide metadata", "Prevent malware", "Post-quantum", "Prevent injection"]
        },
        "knownAttacks": [
            {"attackName": "Malware", "how": "Keylogger", "defense": "Secure device", "status": "outstanding"},
            {"attackName": "Quantum", "how": "Breaks ECDH", "defense": "Post-quantum", "status": "outstanding"},
            {"attackName": "Metadata", "how": "See pattern", "defense": "Use Tor", "status": "mitigated"}
        ],
        "limitations": [
            {"limitation": "Metadata", "why": "Content only", "mitigation": "Tor"},
            {"limitation": "Malware", "why": "Bypass", "mitigation": "Secure device"},
            {"limitation": "Post-Quantum", "why": "Quantum breaks", "mitigation": "Research"}
        ],
        "verificationLog": [
            {"date": "2025-12-26", "reviewer": "Bikram", "role": "Verifier", "status": "Verified", "evidence": "Official spec"}
        ],
        "trustLevel": "Level 2: Reviewed"
    }

    output = {
        "papers": [signal_paper],
        "statistics": {"total_papers": 1},
        "metadata": {"actor": "Privacy Stack", "version": "1.0.0"}
    }

    await client.push_data(output)

if __name__ == "__main__":
    asyncio.run(main_async())


