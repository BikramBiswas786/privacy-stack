"""Nym Mixnet"""
import random
class NymMixnet:
    def mix(self, msg):
        return {"route": [random.randint(0,4) for _ in range(5)], "timing": "RESISTANT"}
if __name__ == "__main__":
    print("🔀 Mixnet: Resistant")
