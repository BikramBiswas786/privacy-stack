# Privacy Stack 🔐 – 5000 Real arXiv Privacy Papers for Researchers & Builders

**Ultimate Privacy Research Scraper – Converts peer‑reviewed privacy & anonymity papers into clean, reproducible, auditable datasets ready for analysis, dashboards, and code.**

Live Actor: https://console.apify.com/oblate_wildcat/privacy-stack  
GitHub: https://github.com/BikramBiswas786/privacy-stack

---

## 💡 What Is Privacy Stack?

Privacy Stack is an Apify Actor that builds a **large‑scale, high‑quality research corpus** of real arXiv papers in security & privacy.

It scrapes and normalizes **5000 unique arXiv cs.CR papers** across **4 critical categories**, making it easy to explore, filter, and build on top of the latest privacy research without touching the arXiv UI. [web:20][file:13]

You get:

- A **clean JSON/CSV dataset** you can drop into analysis pipelines
- Strong **deduplication guarantees**
- A **stable schema** designed for LLMs, dashboards, and downstream tools

---

## 📊 Categories (4 × 1250 Papers)

Each run targets exactly **1250 papers per category**, for a total of **5000 unique cs.CR papers**:

1. **🌐 Internet Privacy**
   - Tor, mix networks, I2P, VPNs, onion routing
   - Traffic analysis attacks & defenses
   - Website fingerprinting, metadata‑hiding systems

2. **🔐 Crypto Privacy**
   - Zero‑knowledge proofs (zk‑SNARKs, zk‑STARKs)
   - FHE, MPC, Bulletproofs, Pedersen commitments
   - Privacy coins (Zcash, Monero), mixer protocols, CoinJoin

3. **📊 Data Privacy**
   - Differential privacy (local & global)
   - Federated learning, secure aggregation
   - Synthetic data, re‑identification resistance, anonymization

4. **⚛️ Post‑Quantum / PQ Security**
   - Kyber, Dilithium, SPHINCS+, Falcon
   - Lattice‑based crypto, hash‑based signatures
   - PQ‑safe anonymous communication & key exchange

Each paper is tagged with a **primary category** plus the **full arXiv category string**, so you can slice the dataset however you want. [file:13]

---

## 🚀 Key Features

- ✅ **100% real arXiv papers**  
  Directly scraped from arxiv.org `cs.CR` – no synthetic titles, no hallucinations, no fake IDs.

- ✅ **5000 UNIQUE papers**  
  Global deduplication by arXiv ID, plus **per‑category deduplication** so the same paper is never counted twice within a category.

- ✅ **Balanced categories**  
  1250 papers for each of the 4 categories → balanced training/test sets for ML and fair comparisons between research areas.

- ✅ **Production‑grade dataset schema**  
  Designed for:
  - LLM context building
  - dashboards (Grafana/Metabase/Superset)
  - offline analytics (Python/pandas, DuckDB, BigQuery)

- ✅ **Zero manual setup on Apify**  
  No `requirements.txt` needed – runs on Apify’s managed Python runtime.

- ✅ **Repeatable & auditable**  
  Same input → same structure, easy to diff across runs as new papers appear on arXiv.

---

## 🧱 Dataset Schema

Each paper in the dataset has a consistent JSON structure:

```json
{
  "id": 1,
  "title": "Device-Independent Anonymous Communication",
  "arxiv_id": "2512.21047",
  "full_category": "cs.CR (Internet Privacy)",
  "short_category": "internet_privacy",
  "authors": ["John Doe", "Jane Smith"],
  "url": "https://arxiv.org/abs/2512.21047",
  "pdf_url": "https://arxiv.org/pdf/2512.21047.pdf",
  "is_real_arxiv": true,
  "published": "2025-12-21",
  "updated": "2025-12-23",
  "abstract": "We propose a device-independent protocol for anonymous communication...",
  "source_run_id": "RUN_ID_FOR_AUDIT"
}
```

---

## 📊 Apify Console Output Tabs

When you run Privacy Stack in Apify Console, the **Output** tab is split into multiple views (using dataset schema): [file:15]

- **📚 All Papers (5000)** – full corpus merged  
- **🌐 Internet Privacy (1250)** – Tor, mixnets, I2P, traffic analysis  
- **🔐 Crypto Privacy (1250)** – ZK, FHE, MPC, crypto protocols  
- **📊 Data Privacy (1250)** – DP, FL, anonymization, re‑identification  
- **⚛️ Post‑Quantum (1250)** – Kyber, Dilithium, PQ anonymous systems  
- **📋 Live Logs** – scrape progress, dedup stats, category counts

Each view is sortable & filterable directly in the Apify Console, and also accessible as CSV/JSON via API.

---

## 📥 Sample Output Snippet

```json
{
  "id": 42,
  "title": "Traffic Analysis Resistant Mix Networks for the Modern Internet",
  "arxiv_id": "2507.12345",
  "full_category": "cs.CR (Cryptography and Security)",
  "short_category": "internet_privacy",
  "authors": ["Alice Anon", "Bob Mixnet"],
  "url": "https://arxiv.org/abs/2507.12345",
  "pdf_url": "https://arxiv.org/pdf/2507.12345.pdf",
  "is_real_arxiv": true
}
```

---

## ⚙️ How It Works (High‑Level)

1. **Input**: categories + maximum papers per category (defaults to 1250 × 4).  
2. **Fetch arXiv feeds / search results** for each category (`cs.CR` + keywords / sub-tags).  
3. **Normalize results** into the unified schema:
   - parse title, authors, IDs, URLs, dates, category strings  
4. **Deduplicate**:
   - global deduplication by `arxiv_id`
   - ensure each category’s slice has only unique entries
5. **Store** into Apify Dataset with **multiple views** (all + per‑category).

The Actor is designed to be **idempotent** in terms of structure, but you will naturally see **newer papers** when you re‑run it over time.

---

## 🚀 Quick Start

### 1. Run from Apify Console

1. Open: **Privacy Stack Actor**  
   `https://console.apify.com/oblate_wildcat/privacy-stack`  
2. Set input (optional):
   - `maxPapersPerCategory`: default 1250  
   - category toggles (if you want only 1–2 categories)  
3. Click **Run**  
4. When it finishes, open the **Output** tab:
   - Browse `All Papers`  
   - Or switch to specific category views  
5. Export as:
   - **JSON** (`items?clean=true`)  
   - **CSV** (`items?format=csv`)  
   - **HTML table** (for quick browsing)

### 2. Run via Apify CLI

```bash
apify run privacy-stack-research-scraper
```

This will:

- run the Actor locally
- store dataset in `./storage/datasets/default/`
- you can then inspect `OUTPUT.json` or CSV in that folder.

---

## 🧪 Example: Using the Dataset in Python

```python
import requests
import pandas as pd

DATASET_URL = "https://api.apify.com/v2/datasets/<DATASET_ID>/items?clean=true"

res = requests.get(DATASET_URL)
res.raise_for_status()
items = res.json()

df = pd.DataFrame(items)

# Example: show recent ZK papers
zk_df = df[df['title'].str.contains("zero-knowledge", case=False, na=False)]
print(zk_df[['title', 'arxiv_id', 'url']].head())

# Example: count papers per short_category
print(df['short_category'].value_counts())
```

---

## 🧠 Typical Use Cases

- **Literature review** for PhD / MSc / paper writing  
  Quickly get 5000+ relevant cs.CR papers organized by topical area.

- **Benchmark building**  
  Curate evaluation sets for LLMs, anonymization tools, or privacy frameworks.

- **Trend analysis**  
  See how research volume changes over time in areas like ZK proofs or post‑quantum crypto.

- **Dataset for downstream models**  
  Use `title + abstract` as input for topic modeling, embeddings, or semantic search.

- **Meta‑research**  
  Study the evolution of anonymity, privacy‑preserving ML, and PQ crypto.

---

## 🔐 Design Principles

- **Real papers only** – every record must correspond to a real arXiv entry.  
- **Transparent scraping** – URLs always point back to arxiv.org.  
- **No guessing / hallucinating metadata** – if arXiv does not provide it, it is not faked.  
- **Reproducibility** – input + time window → deterministically shaped dataset schema.

---

## 📦 Actor Input (Suggested Schema)

Typical input fields (simplified):

```json
{
  "maxPapersPerCategory": 1250,
  "includeInternetPrivacy": true,
  "includeCryptoPrivacy": true,
  "includeDataPrivacy": true,
  "includePostQuantum": true
}
```

You can extend this in future (e.g., year range, specific arXiv query strings, exclusion filters).

---

## 🧑‍💻 About the Author

**Bikram Biswas** (`@BikramBiswas786`)  
- Quantum & privacy tooling developer  
- Creator of **Anon Lab** (interactive privacy paper explorer)  
- Active on Apify building research‑grade Actors for security, privacy, and data aggregation.

Apify profile: https://apify.com/bikrambiswas

---

## 📄 Citation

If Privacy Stack helps in your work, you can cite it as:

```bibtex
@software{biswas2025privacystack,
  author = {Biswas, Bikram},
  title = {Privacy Stack: 5000 Real arXiv Privacy Papers for Researchers},
  year = {2025},
  url = {https://apify.com/oblate_wildcat/privacy-stack}
}
```

---

## 📝 License & Ethics

- Use this dataset **responsibly**.  
- All papers belong to their respective authors and arXiv.  
- This Actor only organizes metadata and links; it does not strip or redistribute paywalled content.

---

**Privacy Stack turns scattered security & privacy literature into a single, structured research surface you can actually build on.**  
Run it, export it, and plug it straight into your research pipeline.
