# 🛡️ Sentinel Shield  
### Log-Based Threat Detection & IP Reputation Analysis Framework

Sentinel Shield is a **blue team–focused security monitoring project** designed to simulate how a SOC detects suspicious and malicious activity using **log analysis, IP reputation checks, and automated alerting**.  

This project demonstrates real-world defensive security concepts such as **log ingestion, enrichment, correlation, and reporting**, making it suitable for SOC Analyst, Blue Team, and SIEM-oriented roles.

---

## 📌 Project Objectives

- Monitor web server activity through access logs  
- Identify suspicious and malicious IP addresses  
- Enrich logs using IP reputation intelligence  
- Classify events based on severity  
- Generate structured, human-readable security reports  

This project intentionally focuses on **detection and visibility**, not exploitation.

---

## 🧠 Key Concepts Demonstrated

- Log ingestion & parsing  
- Threat intelligence enrichment  
- IP reputation analysis  
- Event correlation  
- Severity classification  
- Blue team detection workflow  
- SOC-style reporting

---

## 🏗️ Architecture Overview

Web Application
│
▼
Apache Access Logs
│
▼
Log Ingestion Engine
│
▼
IP Reputation Module
│
▼
Threat Classification Engine
│
▼
Detection Report Generator

---

## 🛠️ Tools & Technologies Used

- **Python 3**
- **Apache Access Logs**
- **IP Reputation Databases / APIs**
- **JSON / Structured Logging**
- **Linux / Windows Environment**


---

## ⚙️ How It Works (Execution Flow)

1. Apache access logs are ingested in real time or batch mode  
2. Logs are parsed to extract IP addresses and request metadata  
3. Each IP is checked against reputation sources  
4. Events are categorized as **Benign, Suspicious, or Malicious**  
5. A structured detection report is generated  

---
