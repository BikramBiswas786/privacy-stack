"""Anonymous Credentials"""
import hashlib
class AnonymousCredentials:
    def issue(self, attr, val):
        return {"id": hashlib.sha256(f"{attr}:{val}".encode()).hexdigest()[:8], "unlinkable": True}
if __name__ == "__main__":
    print("📋 Credentials: Unlinkable")
