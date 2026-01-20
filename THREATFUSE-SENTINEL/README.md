# THREATFUSE SENTINEL 🛡️  
**Threat Intelligence Aggregation & Normalization Framework**

THREATFUSE SENTINEL is a Python-based threat intelligence aggregation engine designed to collect, normalize, enrich, and correlate Indicators of Compromise (IOCs) from multiple sources.  
It simulates a real-world SOC threat intel pipeline used for proactive defense, detection engineering, and security analytics.

This project focuses on **blue-team operations**, emphasizing structured intelligence handling, data integrity, and SOC-ready outputs.

---

## 📌 Key Features

- Multi-source threat feed ingestion (local datasets)
- Support for IP addresses, domains, URLs, and file hashes
- Indicator normalization into a unified schema
- Deduplication and integrity validation
- Threat severity tagging and confidence scoring
- Correlation-ready structured output
- Clean, SOC-friendly reporting

---

## 🏗️ Architecture Overview

The system is built as a modular pipeline, closely resembling real-world Threat Intelligence Platforms (TIPs):

1. **Threat Feed Collection**
   - Loads multiple structured datasets
   - Validates format and data integrity

2. **Indicator Normalization Engine**
   - Converts all IOCs into a standardized schema
   - Normalizes fields like type, value, source, and timestamp

3. **Deduplication & Validation Layer**
   - Removes duplicate indicators
   - Ensures clean, high-confidence intelligence

4. **Threat Enrichment & Classification**
   - Assigns severity levels
   - Adds contextual metadata for SOC analysis

5. **Output & Reporting Module**
   - Generates structured JSON output
   - Ready for SIEM ingestion or further automation

---

## ⚙️ Tech Stack

- **Language:** Python 3.12+
- **Core Libraries:**  
  - `json`  
  - `hashlib`  
  - `datetime`  
  - `pathlib`  
- **Platform:** Cross-platform (Windows / Linux)

---

## 🧠 Use Cases

  - SOC Threat Intelligence Processing
  - SIEM Feed Preparation
  - Blue Team Detection Engineering
  - Internship / Portfolio Demonstration
  - Threat Hunting Foundations
  
---

## 🔐 Security Focus

This project is built strictly for defensive security research and blue-team training.
No exploitation, scanning, or offensive payload execution is included.

---