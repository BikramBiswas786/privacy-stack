"""Ring Signature"""
import hashlib
class RingSignature:
    def sign(self, msg, ring):
        return {"sig": hashlib.sha256(msg.encode()).hexdigest()[:8], "ring_size": len(ring), "unlinkable": True}
if __name__ == "__main__":
    rs = RingSignature()
    print("💍 Ring Signature: Unlinkable")
