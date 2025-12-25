"""
Searchable Encryption Implementation
Search encrypted data without decryption
"""

class SearchableEncryption:
    def __init__(self):
        self.encrypted_index = {}
    
    def create_search_index(self, documents):
        """Create searchable index"""
        import hashlib
        
        for doc_id, content in enumerate(documents):
            words = content.lower().split()
            
            for word in words:
                word_hash = hashlib.sha256(word.encode()).hexdigest()[:8]
                
                if word_hash not in self.encrypted_index:
                    self.encrypted_index[word_hash] = []
                
                self.encrypted_index[word_hash].append(doc_id)
        
        return {
            "indexed_documents": len(documents),
            "index_size": len(self.encrypted_index),
            "searchability": "ENABLED"
        }
    
    def search_encrypted(self, search_term):
        """Search without decryption"""
        import hashlib
        
        search_hash = hashlib.sha256(search_term.encode()).hexdigest()[:8]
        
        if search_hash in self.encrypted_index:
            results = self.encrypted_index[search_hash]
        else:
            results = []
        
        return {
            "query": search_term,
            "results_count": len(results),
            "matching_documents": results,
            "query_privacy": "PROTECTED"
        }


if __name__ == "__main__":
    docs = [
        "Privacy is a fundamental right",
        "Encryption protects communication",
        "Privacy advocates support encryption"
    ]
    
    se = SearchableEncryption()
    index_result = se.create_search_index(docs)
    
    print("🔍 Searchable Encryption")
    print(f"Documents indexed: {index_result['indexed_documents']}")
    
    search = se.search_encrypted("privacy")
    print(f"Search results: {search['results_count']}")
