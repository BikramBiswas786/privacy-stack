"""Tor Circuit"""
class TorCircuit:
    def __init__(self, entry, middle, exit):
        self.entry = entry
        self.middle = middle
        self.exit = exit
    def encrypt(self, data):
        return f"[ENTRY:[MIDDLE:[EXIT:{data}]]]"
    def info(self):
        return {"hops": 3, "status": "ACTIVE"}
if __name__ == "__main__":
    c = TorCircuit("US", "EU", "ASIA")
    print("🧅 Tor: 3 hops")
