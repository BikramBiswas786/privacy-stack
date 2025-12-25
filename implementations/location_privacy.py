"""Location Privacy"""
import random
class LocationPrivacy:
    def anonymize(self, lat, lon):
        return {"original": {"lat": lat, "lon": lon}, "anonymized": {"lat": lat + random.uniform(-0.01, 0.01), "lon": lon + random.uniform(-0.01, 0.01)}}
if __name__ == "__main__":
    print("📍 Location: Anonymized")
