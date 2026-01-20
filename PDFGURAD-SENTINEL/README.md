# PDFGUARD SENTINEL 🛡️  
**Static PDF Malware Analysis & Detection Framework**

PDFGUARD SENTINEL is a blue-team–oriented static analysis framework designed to inspect PDF files at a structural level, detect malicious or suspicious components, extract indicators of compromise (IOCs), and generate SOC-ready logs for investigation and monitoring.

Unlike traditional antivirus tools that rely on signatures or reputation, PDFGUARD SENTINEL focuses on **document behavior, structure, and forensic visibility** — mirroring how real-world SOCs and secure email gateways analyze document-based threats.

---

## 📌 Project Overview

- **Domain:** Cybersecurity / Blue Team  
- **Focus:** PDF Malware Analysis (Static)  
- **Type:** Practical Security Project  
- **Author:** Chirayu Paliwal  
- **Context:** Internship Practical Assignment  
- **Language:** Python  
- **Output:** Analyst-readable reports + structured JSON logs  

PDF files are widely trusted and frequently abused by attackers using embedded JavaScript, launch actions, encoded streams, and hidden objects. PDFGUARD SENTINEL was built to expose these threats **without executing the document**.

---

## 🎯 Objectives

- Analyze PDF files for malicious and suspicious structural elements
- Detect embedded JavaScript and risky PDF actions
- Extract indicators such as hashes, URLs, and suspicious strings
- Classify PDFs based on structural risk and behavior
- Generate structured logs suitable for SOC review or SIEM ingestion

---

## 🧠 Detection Philosophy

PDFGUARD SENTINEL operates on a simple but powerful idea:

> **A document is not safe because of its extension — it is safe only if its structure and behavior justify trust.**

Key principles:
- Structural behavior is prioritized over file appearance
- Active content increases risk scoring
- Explainability and forensic visibility are essential
- Detection focuses on *what the document can do*, not what it claims to be

This aligns closely with real-world document inspection engines used in enterprise SOC environments.

---

## 🏗️ Architecture Overview

PDFGUARD SENTINEL follows a modular static analysis pipeline:

1. **PDF Ingestion Module**  
   Safely loads and validates PDF files without executing embedded content.

2. **PDF Structure Parsing Engine**  
   Enumerates objects, streams, metadata, and internal references.

3. **Suspicious Element Detection Module**  
   Identifies embedded JavaScript, launch actions, embedded files, and encoded streams.

4. **Indicator Extraction Module**  
   Extracts hashes, URLs, suspicious keywords, and structural indicators.

5. **Risk Classification & Logging Module**  
   Assigns risk levels and generates structured, SOC-ready logs.

---

## 🔄 Analysis Workflow

1. PDF file ingestion from a controlled directory  
2. Structural parsing of objects and streams  
3. Detection of malicious indicators and risky actions  
4. Extraction of forensic indicators (hashes, URLs, strings)  
5. Risk classification (Benign / Suspicious / High Risk)  
6. Reporting via readable summaries and JSON logs  

---

## 🛠️ Tools & Technologies

- **Python 3** – Core logic and orchestration  
- **PDF Parsing Libraries** – Structural inspection  
- **JSON** – Structured logging and output  
- **Visual Studio Code / PowerShell** – Development & testing  

---

## 🔍 Threat Model & Assumptions

### Attacker Assumptions
- PDFs are used as initial access vectors
- Malicious logic is hidden inside document structure
- Obfuscation is used to evade basic scanning

### Defender Assumptions
- Static analysis only (no execution or sandboxing)
- Focus on detection, visibility, and investigation
- Output designed for SOC analysts and monitoring systems

---

## 📊 Results & Observations

During testing, PDFGUARD SENTINEL successfully demonstrated:

- Detection of embedded JavaScript inside PDFs
- Identification of suspicious actions and encoded streams
- Extraction of security-relevant indicators
- Clear differentiation between benign and suspicious documents
- Analyst-friendly output suitable for investigations

> Note: VirusTotal reputation queries may fail for novel or unseen PDFs — reinforcing the importance of structural analysis over reputation-based trust.

---

## 🚀 Use Cases

- SOC document triage
- Secure email attachment inspection
- Malware research and training
- Blue team skill development
- Pre-ingestion document analysis before sandboxing


---

## ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**.  
It performs **static analysis** and does not execute or detonate files.

---

## 🧾 License

This project is released under the **MIT License** — free to use, modify, and distribute with attribution.

---

## ✨ Final Note

PDFGUARD SENTINEL represents a realistic, SOC-aligned approach to document-based threat detection.  
It demonstrates how modern blue teams think: **structure first, behavior second, reputation last.**
