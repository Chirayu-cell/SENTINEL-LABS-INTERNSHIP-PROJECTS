# PROCWATCH SENTINEL 🛡️  
### Host-Based Watcher for Windows Process, Service, and Persistence Abuse

**Domain:** Cybersecurity · Blue Team · Endpoint Detection  
**Type:** Practical SOC / EDR-Style Project  
**Author:** Chirayu Paliwal  

---

## 📌 Project Overview

Modern cyberattacks rarely start with obvious malware. They begin quietly — abusing legitimate Windows utilities, spawning suspicious process chains, or establishing persistence through services and registry keys.

**PROCWATCH SENTINEL** is a lightweight, behavior-focused Windows monitoring tool designed to detect:

- Suspicious process execution  
- Abnormal parent–child process relationships  
- Windows service abuse  
- Persistence mechanisms (registry run keys, startup folders)

Instead of relying on signatures, the project focuses on **behavioral detection**, **context-aware analysis**, and **SOC-style reporting** — closely simulating how real-world endpoint detection and response (EDR) tools operate.

---

## 🎯 Project Objectives

- Monitor running Windows processes and services programmatically
- Analyze parent–child execution chains for anomalies
- Detect persistence mechanisms abused by attackers
- Apply rule-based detection with severity and risk scoring
- Map detections to the **MITRE ATT&CK** framework
- Generate structured, analyst-readable detection reports

---

## 🧠 Problem Statement

Windows includes many powerful built-in tools designed for administrators — PowerShell, services, startup tasks. Attackers exploit these same tools to:

- Execute malicious commands without dropping malware  
- Persist across reboots  
- Blend into normal system activity  

Traditional beginner tools either:
- Trigger excessive false positives, or  
- Flag behavior without explaining *why it matters*

**PROCWATCH SENTINEL bridges this gap** by focusing on *explainable detection logic*, helping analysts understand both **what happened** and **why it is risky**.

---

## 🏗️ Architecture Overview

The project follows a **modular SOC-style pipeline**, similar to enterprise EDR tools:

1. **Process Enumeration Module**  
   - Collects active processes, PIDs, parent PIDs, executable paths

2. **Relationship Analysis Module**  
   - Builds parent–child process trees  
   - Flags suspicious execution chains (e.g., Office → PowerShell)

3. **Service Audit Module**  
   - Enumerates Windows services  
   - Detects newly registered or suspicious services

4. **Persistence Monitoring Module**  
   - Scans registry Run keys  
   - Inspects startup folders

5. **Detection Rules Engine**  
   - Applies blacklist and heuristic rules  
   - Performs behavior-based risk scoring

6. **Telemetry & Reporting Module**  
   - Stores structured detection events  
   - Generates SOC-style final reports  
   - Maps activity to MITRE ATT&CK techniques

---

## 🔍 Detection Methodology

The detection pipeline follows these steps:

1. Enumerate active processes and metadata  
2. Build parent–child execution relationships  
3. Audit installed Windows services  
4. Detect persistence mechanisms  
5. Apply rule-based detection logic  
6. Assign severity levels and risk scores  
7. Map detections to MITRE ATT&CK  
8. Generate final analyst-ready report  

---

## ⚙️ Tools & Technologies

- **Programming Language:** Python 3  
- **Operating System:** Windows  
- **Concepts Used:**  
  - Process enumeration  
  - Windows service inspection  
  - Registry analysis  
  - JSON-based detection rules  
- **Framework:** MITRE ATT&CK  
- **Development Tools:**  
  - Visual Studio Code  
  - PowerShell (testing & validation)

---

## 🎯 Threat Model

**Attacker Assumptions**
- Local or limited administrative access
- Uses Living-Off-The-Land Binaries (LOLBins)
- Establishes persistence via services or startup mechanisms
- Avoids obvious malware deployment

**Defender Assumptions**
- User-space visibility only
- No kernel-level monitoring
- Focus on detection and analysis, not prevention

---

## 📊 Risk Scoring Philosophy

Risk scoring is **weighted**, not binary.  
Each detection considers:

- Executable type  
- Execution context  
- Presence of persistence mechanisms  
- Known malicious indicators  

This mirrors real SOC and EDR prioritization logic and helps analysts focus on **high-impact threats first**.

---

## 📄 Sample Output

The final report includes:

- Total events detected  
- Severity distribution (LOW / MEDIUM / HIGH)  
- Detailed explanations of high-risk events  
- MITRE ATT&CK technique mapping  
- Analyst-friendly summaries explaining:
  - What happened  
  - Why it matters  
  - How it aligns with attacker behavior  

---

## ⚠️ False Positives & Triage

Expected false positives include:
- Legitimate PowerShell usage by administrators  
- Security tools executing command-line utilities  
- Software updates registering services  

**How PROCWATCH SENTINEL Handles This**
- Context-aware detection
- Risk-based scoring instead of binary alerts
- Detailed explanations to support analyst judgment

---

## 🧪 How to Run

```bash
python main.py
