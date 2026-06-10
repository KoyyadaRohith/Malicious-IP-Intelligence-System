# 🛡️ Malicious IP Intelligence System

### 🌐 AI-Powered Threat Intelligence & IP Reputation Analysis Platform




\

---

## 🚀 Live Demo

🌐 **Project Website**
https://malicious-ip-intelligence-system.onrender.com/

📂 **Source Code**
https://github.com/KoyyadaRohith/Malicious-IP-Intelligence-System

---

## 🏆 Why This Project?

✅ AI-Powered Threat Intelligence

✅ Real-Time IP Reputation Analysis

✅ VirusTotal Integration

✅ AbuseIPDB Integration

✅ Automated Risk Scoring

✅ Bulk IP Investigation

✅ Threat Analytics Dashboard

✅ Watchlist Management

✅ Security Reports & Exports

✅ SOC-Oriented Investigation Workflow

---

## 📖 Overview

The **Malicious IP Intelligence System** is a cybersecurity-focused web platform designed to help analysts, researchers, students, and security teams investigate suspicious IPv4 addresses using aggregated threat intelligence from multiple intelligence providers.

The platform combines threat intelligence, risk scoring, threat classification, reporting, and investigation workflows into a single interface, helping users identify potentially malicious infrastructure and make informed security decisions.

### ✨ Key Capabilities

### 🔍 Single IP Investigation

* Risk Score Analysis
* Threat Classification
* Analyst-Style Diagnosis
* Security Recommendations
* Investigation Playbooks

### 📂 Bulk IP Analysis

* Upload `.csv`, `.txt`, and `.log` files
* Automatic IPv4 Extraction
* Duplicate Removal
* Batch Threat Intelligence Processing
* Bulk Reporting

### ⚡ Intelligence Caching

* Cache-First Threat Intelligence Retrieval
* Automatic Cache Expiration (24 Hours)
* Reduced Vendor API Usage
* Consistent Investigation Results
* Faster Analysis Performance

### 📊 Security Operations Features

* Threat Analytics Dashboard
* Investigation History
* Watchlist Monitoring
* Threat Classification
* Security Reporting

### 📄 Reporting & Exports

* TXT Reports
* CSV Reports
* PDF-Friendly HTML Reports
* Investigation Summaries

> 🛡️ Runs out-of-the-box in Mock Mode (No API Keys Required). Enable Live Mode to retrieve real-time threat intelligence from VirusTotal and AbuseIPDB.

---

## 🏗️ Architecture

```text
User Investigation Request
            │
            ▼
 Threat Intelligence Cache
            │
   ┌────────┴────────┐
   ▼                 ▼
VirusTotal      AbuseIPDB
   │                 │
   └────────┬────────┘
            ▼
   Risk Scoring Engine
            ▼
 Threat Classification
            ▼
 Dashboard & Reports
```

---

## 🖥️ Application Modules

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
* 👤 User Profile & Settings

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

### APIs & Threat Intelligence Sources

* 🛡️ VirusTotal API
* 🚨 AbuseIPDB API
* 🌍 ip-api.com

### Configuration

* ⚙️ python-dotenv

### Storage

* 🗄️ CSV-Based Storage Engine

### Reporting

* 📄 Custom Report Generation System

### Development Tools

* 💻 VS Code
* 🔧 Git
* 📂 GitHub

---

## 🔐 Threat Intelligence Workflow

### 🗄️ Cache-First Retrieval

* Cache Location: `database/threat_intel_cache.csv`
* Cache Duration: **24 Hours**
* Automatic Refresh on Expiration
* Consistent Results Across Repeated Investigations

### 🧪 Mock Mode

* No API Keys Required
* Deterministic Threat Intelligence Data
* Ideal for Testing & Demonstrations

### 🌍 Live Mode

Real-Time Intelligence Sources:

* 🛡️ VirusTotal
* 🚨 AbuseIPDB
* 🌐 ip-api.com

If a provider becomes unavailable, the platform gracefully falls back to available intelligence sources.

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

3️⃣ Remove Duplicate IPs

4️⃣ Perform Threat Intelligence Analysis

5️⃣ Aggregate Investigation Results

6️⃣ Generate Reports

---

## ⭐ Watchlist & Investigation History

### Watchlist

* ⭐ Manual Add/Remove
* 🚨 Auto-Watchlist for High-Risk IPs
* 💾 Persistent Storage

### Investigation History

* 🕒 Investigation Audit Trail
* 📊 Risk Score Tracking
* 🔍 Threat Metadata Storage
* 📁 Historical Search Records

---

## 📄 Reports & Exports

### Individual Reports

* 📄 TXT Investigation Reports
* 🖨️ PDF-Friendly HTML Reports

### Bulk Reports

* 📊 CSV Exports
* 📑 TXT Summaries
* 📄 Bulk Audit Reports

---

## ⚡ Quick Start

### 1️⃣ Create a Virtual Environment

```bat
python -m venv .venv
.venv\Scripts\activate
```

### 2️⃣ Install Dependencies

```bat
pip install -r requirements.txt
```

### 3️⃣ Run the Application

```bat
python app.py
```

🌐 Open in your browser:

```text
http://localhost:5000
```

---

## 🧪 Run Tests

Validate the core functionality of the platform:

```bat
python test_pipeline.py
```

### Tests Covered

✅ User Authentication

✅ Threat Intelligence Pipeline

✅ Risk Scoring Engine

✅ Watchlist Operations

✅ Report Generation

✅ Investigation Workflow

---

## 📌 Available Modes

### 🧪 Mock Mode

* No API Keys Required
* Deterministic Threat Intelligence Data
* Ideal for Testing & Demonstrations

### 🌍 Live Mode

* VirusTotal Integration
* AbuseIPDB Integration
* Real-Time Threat Intelligence
* Automatic Cache Management

---

## ⚠️ Known Limitations

* IPv4 Support Only
* CSV Storage Is Intended for Demonstration Purposes
* Live Intelligence Depends on External API Availability
* Enterprise-Scale Storage Is Not Yet Implemented

---

## 🚀 Future Roadmap

* 🌐 IPv6 Support
* 🗄️ SQLite Integration
* 🐘 PostgreSQL Migration
* 🔔 Automated Threat Re-Scanning
* 📧 Email Notifications
* 📡 SIEM Integration
* 👥 Role-Based Access Control (RBAC)
* 🗺️ Threat Geolocation Mapping
* 🐳 Docker Deployment
* 🤖 Machine Learning-Based Threat Prediction

---

## 👨‍💻 Developed By

### Koyyada Rohith

🔐 Cybersecurity Enthusiast

🎓 B.Tech Computer Science & Engineering

🛡️ SOC & Threat Intelligence Learner

🤖 Generative AI & Cybersecurity Projects

🚀 Building Innovative Solutions in Cybersecurity, Collaboration, and Technology

---

## 📌 Version

**Version 1.0**

---

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.
