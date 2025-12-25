"""
Tor Circuit Implementation
Simulates Tor onion routing circuits
"""

class TorCircuit:
    def __init__(self, entry_node, middle_node, exit_node):
        self.entry_node = entry_node
        self.middle_node = middle_node
        self.exit_node = exit_node
        self.circuit_id = self._generate_circuit_id()
    
    def _generate_circuit_id(self):
        import hashlib
        nodes = f"{self.entry_node}{self.middle_node}{self.exit_node}"
        return hashlib.sha256(nodes.encode()).hexdigest()[:16]
    
    def encrypt_data(self, data):
        """Encrypt data through Tor circuit"""
        encrypted = f"[EXIT:{data}]"
        encrypted = f"[MIDDLE:{encrypted}]"
        encrypted = f"[ENTRY:{encrypted}]"
        return encrypted
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data through circuit"""
        return encrypted_data.replace("[ENTRY:", "").replace("[MIDDLE:", "").replace("[EXIT:", "").replace("]", "")
    
    def get_circuit_info(self):
        return {
            "circuit_id": self.circuit_id,
            "entry_node": self.entry_node,
            "middle_node": self.middle_node,
            "exit_node": self.exit_node,
            "hops": 3,
            "status": "ACTIVE"
        }


if __name__ == "__main__":
    circuit = TorCircuit("US-East", "Europe-Central", "Asia-Pacific")
    print(f"🧅 Tor Circuit Created")
    print(f"Circuit ID: {circuit.circuit_id}")
    print(f"Hops: 3 (Entry → Middle → Exit)")

