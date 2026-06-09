# 🛡️ Malicious IP Intelligence System

### 🌐 Threat Intelligence & IP Reputation Analysis Platform

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Threat%20Intelligence-red)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 📖 Overview

The **Malicious IP Intelligence System** is a cybersecurity-focused web platform that enables analysts, researchers, and security teams to investigate **IPv4 addresses** using aggregated threat intelligence from multiple sources.

### ✨ Key Capabilities

🔍 **Single IP Investigation**

* Risk Score Analysis
* Threat Classification
* Analyst-Style Diagnosis
* Recommended Response Playbooks

📂 **Bulk IP Analysis**

* Upload `.csv`, `.txt`, and `.log` files
* Automatic IPv4 Extraction
* Deduplication Engine
* Batch Threat Intelligence Analysis

⚡ **Intelligence Caching**

* Cache-First Threat Intelligence Retrieval
* 24-Hour TTL
* Reduced Vendor API Calls
* Faster Investigations

📊 **Security Operations Features**

* Watchlist Management
* Investigation History
* Threat Analytics Dashboard
* Report Generation & Export

📄 **Reporting**

* TXT Reports
* CSV Exports
* Print-Optimized HTML/PDF Reports

> 🚀 Runs out-of-the-box in **Mock Mode** (No API Keys Required). Switch to **Live Mode** for real-time intelligence from VirusTotal and AbuseIPDB.

---

## 🖥️ Screens

* 🏠 Landing Page
* 🔐 Login & Registration
* 🔑 Google OAuth Authentication
* 📊 Dashboard
* 📈 Threat Analytics
* 🔍 IP Investigation Console
* 📂 File Upload & Bulk Analysis
* 📑 Results Console
* ⭐ Watchlist Management
* 🕒 Investigation History
* 📄 Reports & Exports
* 👤 Profile & Settings

---

## 🛠️ Tech Stack

### Backend

* 🐍 Python
* 🌶️ Flask

### Frontend

* 🎨 HTML5
* 🎨 CSS3
* ⚡ JavaScript
* 📊 Chart.js

### APIs & Intelligence Sources

* 🛡️ VirusTotal API
* 🚨 AbuseIPDB API
* 🌍 ip-api.com

### Configuration

* ⚙️ python-dotenv

### Storage

* 🗄️ CSV-Based Database

### Reporting

* 📄 Custom Report Generator

---

## ⚡ Quick Start

### 1️⃣ Create Virtual Environment

```bat
python -m venv .venv
.venv\Scripts\activate
```

### 2️⃣ Install Dependencies

```bat
pip install -r requirements.txt
```

### 3️⃣ Run Application

```bat
python app.py
```

🌐 Open:

```text
http://localhost:5000
```

---

## 🔐 Threat Intelligence Workflow

### 🗄️ Cache-First Retrieval

* Cache Location: `database/threat_intel_cache.csv`
* Cache TTL: **24 Hours**
* Automatic Refresh on Expiration
* Consistent Results for Repeated Investigations

### 🧪 Mock Mode

* No API Keys Required
* Deterministic Threat Intelligence
* Consistent Output for Testing

### 🌍 Live Mode

Real-Time Intelligence Sources:

* 🛡️ VirusTotal
* 🚨 AbuseIPDB
* 🌐 ip-api.com

---

## 🎯 Risk Scoring & Classification

### Risk Score (0–100)

| Source                   | Weight |
| ------------------------ | ------ |
| 🚨 AbuseIPDB             | 50%    |
| 🛡️ VirusTotal           | 35%    |
| 🌐 Hosting / VPN Profile | 15%    |

### Threat Classification

| Risk Score  | Classification |
| ----------- | -------------- |
| 🟢 0 – 20   | Safe           |
| 🟡 21 – 60  | Suspicious     |
| 🔴 61 – 100 | Malicious      |

---

## 📂 Bulk Analysis Pipeline

1️⃣ Upload `.csv`, `.txt`, or `.log`

2️⃣ Extract IPv4 Addresses

3️⃣ Remove Duplicates

4️⃣ Analyze Threat Intelligence

5️⃣ Aggregate Results

6️⃣ Generate Reports

---

## ⭐ Watchlist & History

### Watchlist

* ⭐ Manual Add/Remove
* 🚨 Auto-Watchlist for High-Risk IPs
* 💾 Persistent Storage

### Investigation History

* 🕒 Complete Audit Trail
* 📊 Risk Score Tracking
* 🔍 Investigation Metadata

---

## 📄 Reports & Exports

### Individual Reports

* 📄 TXT Security Reports
* 🖨️ PDF-Ready HTML Reports

### Bulk Reports

* 📊 CSV Exports
* 📑 TXT Summaries
* 📄 PDF Audit Reports

---

## 🧪 Testing

Run:

```bat
python test_pipeline.py
```

### Validates

✅ Authentication

✅ Threat Intelligence Pipeline

✅ Risk Scoring Engine

✅ Watchlist Operations

✅ Report Generation

---

## ⚠️ Known Limitations

* IPv4 Only
* CSV Storage Not Designed for High Concurrency
* External API Availability Affects Live Mode

---

## 🚀 Future Enhancements

* 🌐 IPv6 Support
* 🗄️ SQLite / PostgreSQL Migration
* 🔔 Automated Watchlist Re-Scanning
* 📧 Email Alerting
* 📡 SIEM Integration
* 👥 RBAC Support
* 🗺️ Geo-Location Mapping
* 🐳 Docker Deployment

---

## 👨‍💻 Developed By

### Koyyada Rohith

🔐 Cybersecurity Enthusiast

🎓 B.Tech Computer Science & Engineering

🚀 Building Innovative Solutions in Cybersecurity, Threat Intelligence, Collaboration, and Technology

---

## 📌 Version

**Version 1.0**

---

## 📜 License

© All Rights Reserved. This project is proprietary software and may not be copied, modified, or distributed without permission.
