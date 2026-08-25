# 📡 NetSage AI: Automated Network Diagnostic Platform & HITL Verification Gate

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](http://127.0.0.1:8501)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Cisco Packet Tracer](https://img.shields.io/badge/Cisco-Packet%20Tracer-005073.svg)](https://www.netacad.com/courses/packet-tracer)
[![Track](https://img.shields.io/badge/Track-Networking-emerald.svg)](#-cisco-aicte-vip-program-2026)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

> **CISCO AICTE VIP PROGRAM 2026 — SUBMISSION PACKAGE**  
> **Track:** Networking Track  
> **Project Title:** NetSage AI: Automated Network Diagnostic Platform & Human-in-the-Loop (HITL) Verification Gate  
> **Technology Guides:** Dr. Praveen Sharma & Mr. Madhav Sahu  

---

## 🌐 Live Application Links

- ⚡ **Local Live App (Running):** [http://127.0.0.1:8501](http://127.0.0.1:8501) *(or [http://localhost:8501](http://localhost:8501))*
- 🚀 **Streamlit Cloud Deployment:** [Deploy on Streamlit Community Cloud](https://streamlit.io/cloud) *(Repository main file path: `04_NetSage_AI_Platform_Source_Code/src/app.py`)*
- 📝 **Official Submission Form:** [Google Form Link](https://forms.gle/J4FwzMmMR7pdyASY8)
- 🎥 **Guidance Video:** [YouTube Video Link](https://youtu.be/Bb7pM0xDu1g)

---

## 🌟 Executive Summary

**NetSage AI** is a novel, hybrid AI network diagnostic platform designed specifically for Cisco Packet Tracer and Cisco IOS environments. It combines **high-precision deterministic rules** (OSI Layers 1–4 regex verification) with **semantic prompt inference** (OSI Layers 5–7 root-cause reasoning) and enforces a **Human-in-the-Loop (HITL)** remediation gate before any CLI commands are deployed.

### Key Capabilities:
- 🚨 **Active Diagnostics:** Real-time multi-layer fault isolation across 30+ Packet Tracer failure scenarios.
- 🛡️ **HITL Remediation Gate:** One-click Approve, Edit CLI, or Reject (False Positive) actions.
- 🔬 **Custom Diagnostic Sandbox:** Paste raw Cisco `show` outputs for instant analysis.
- 📊 **Audit & Analytics:** Real-time tracking of operator decisions and agreement metrics vs benchmark (76.6%).
- 📚 **Scenario Catalog:** Interactive multi-layer network failure scenario repository.

---

## 📂 Project Repository Structure

```
CISCO_AICTE_VIP_2026_NETSAGE_AI/
│
├── 01_Project_Summary_Document/             # Formatted Project Summaries (PDF/Word/MD)
│   ├── Project_Summary_Document_NetSage_AI.md
│   ├── Amit_Kumar_Mishra-CollegeName-Networking_Track_Summary.md
│   └── Aditya_Tiwari-CollegeName-Networking_Track_Summary.md
│
├── 02_Packet_Tracer_Lab_Scenarios/          # Cisco Packet Tracer Topologies & Base Configs
│   ├── NetSage_AI_MultiTier_Enterprise_Topology.pkt
│   ├── Packet_Tracer_Topology_Guide.md
│   └── Cisco_Packet_Tracer_Base_Configs.ios
│
├── 03_Google_Sheet_Tracker_Checklist/       # Tracker Checklist & Review Verification
│   └── Submission_Tracker_Checklist.csv
│
├── 04_NetSage_AI_Platform_Source_Code/      # Full Core Application Source Code
│   ├── data/cases.csv                        # 30 Multi-Layer Diagnostic Scenarios
│   ├── src/app.py                            # Streamlit NOC Operations Dashboard
│   ├── src/checker.py                        # Deterministic Rule Engine (Regex & Logic)
│   ├── src/engine.py                         # Hybrid Diagnostic Engine & HITL Gate
│   └── docs/model_audit_log.md               # Model Audit & Agreement Benchmark Documentation
│
├── Run_NetSage_AI.bat                       # One-Click Windows Batch Launcher
├── Run_NetSage_AI.ps1                       # One-Click PowerShell Launcher
├── README.md                                 # Master Repository Readme (This File)
└── requirements.txt                          # Global Dependencies for Streamlit Cloud
```

---

## 🚀 Quick Start Guide

### Option 1: One-Click Windows Launcher
Simply double-click [`Run_NetSage_AI.bat`](file:///c:/Users/abhis/Downloads/CISCO_AICTE_VIP_2026_NETSAGE_AI/Run_NetSage_AI.bat) or run PowerShell script [`Run_NetSage_AI.ps1`](file:///c:/Users/abhis/Downloads/CISCO_AICTE_VIP_2026_NETSAGE_AI/Run_NetSage_AI.ps1).

### Option 2: Manual Terminal Execution
```bash
# 1. Navigate to the source code folder
cd 04_NetSage_AI_Platform_Source_Code

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch Streamlit Application
streamlit run src/app.py
```
Open **[http://127.0.0.1:8501](http://127.0.0.1:8501)** in your web browser.

---

## 👥 Student & Guide Information

- **Student Contributors:**
  - **Amit Kumar Mishra** (Lead Backend & Diagnostic Architect)
  - **Aditya Tiwari** (Systems & Operations Engineer)
- **Technology Guides:**
  - **Dr. Praveen Sharma**
  - **Mr. Madhav Sahu**
- **Program:** Cisco AICTE Virtual Internship Program (VIP) 2026

---

## 📜 License & Compliance
This repository is submitted in compliance with the **Cisco AICTE VIP Program 2026** guidelines. All code, topologies, and diagnostic models are 100% original and verified.
