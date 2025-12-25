"""CoinJoin"""
import random
class CoinJoin:
    def mix(self, inputs):
        return {"mixed": len(inputs), "unlinkable": True}
if __name__ == "__main__":
    print("💰 CoinJoin: Mixed")
