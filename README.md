# Sentinel Labs

Sentinel Labs is a collection of practical, blue-team–focused security detection projects designed to mirror real-world Security Operations Center (SOC) workflows.

This repository showcases how modern defenders detect, analyze, and contextualize threats across multiple layers of the attack surface — from document-based malware and endpoint persistence to web attacks and threat intelligence correlation.

The projects emphasize **explainable detections**, **risk-based decision making**, and **analyst-ready output**, rather than signature-only or black-box approaches.

---

## 🧭 Project Overview

### 🔐 PDFGuard Sentinel
**PDF Malware Analysis & Detection Framework**

Performs static, non-executing analysis of PDF files to identify malicious structural elements such as embedded JavaScript, risky actions, encoded streams, and suspicious metadata.  
Designed to simulate how secure email gateways and SOC analysts triage document-based threats.

**Threat Focus:** Phishing attachments, document-based malware  
**Core Skills:** Static malware analysis, IOC extraction, SOC logging

---

### 🖥️ ProcWatch Sentinel
**Windows Process, Service & Persistence Monitoring Agent**

Monitors running processes, parent–child execution chains, Windows services, and persistence mechanisms to detect abuse of legitimate system utilities (LOLBins).  
Maps detections to MITRE ATT&CK techniques with contextual risk scoring.

**Threat Focus:** Living-off-the-land attacks, post-compromise activity  
**Core Skills:** Process analysis, persistence detection, behavioral scoring

---

### 🗝️ RegWatch Sentinel
**Windows Registry Persistence Detection System**

Detects suspicious registry-based auto-start entries by analyzing executable context, file existence, masquerading behavior, and privilege scope.  
Generates explainable, analyst-readable detection reports.

**Threat Focus:** Registry-based persistence, stealthy footholds  
**Core Skills:** Windows internals, registry analysis, ATT&CK mapping

---

### 🌐 Sentinel Shield
**Web Intrusion Detection & Behavior Analysis System**

Analyzes HTTP requests to detect common web attacks such as SQL Injection, XSS, LFI, and Command Injection.  
Tracks attacker behavior over time and applies risk-based decisions (ALLOW / MONITOR / CHALLENGE / BLOCK).

**Threat Focus:** Web application attacks, automated scanners  
**Core Skills:** Request normalization, signature detection, behavior tracking

---

### 🧠 ThreatFuse Sentinel
**Threat Intelligence Aggregation & Correlation Engine**

Aggregates multiple OSINT threat feeds, normalizes indicators into a unified schema, deduplicates overlaps, and enriches context for SOC consumption.  
Designed to support alert enrichment and threat hunting rather than raw blocking.

**Threat Focus:** External threat intelligence, IOC correlation  
**Core Skills:** Threat intel processing, normalization, SOC enrichment

---

## 🧩 Design Philosophy

All projects in Sentinel Labs share the same core principles:

- Analyst-first, explainable detections  
- Contextual risk scoring over binary decisions  
- Structured, SOC-ready logging  
- Alignment with real-world defensive workflows  

These tools are intentionally built to resemble early-stage SOC, EDR, WAF, and Threat Intelligence Platform components rather than academic demonstrations.

---

## ⚠️ Disclaimer

These projects are for **educational and defensive research purposes only**.  
They are not intended for use in production environments without proper review, testing, and hardening.

---

## 👤 Author

**Chirayu Paliwal**  
Cybersecurity | Blue Team | SOC Analysis
