# DISTRIBUTED CYBERATTACK DETECTION AND ALERT SYSTEM (SENTINEL IDS)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.2%2B-black.svg)](https://palletsprojects.com/p/flask/)
[![MySQL](https://img.shields.io/badge/Database-MySQL%20%7C%20SQLite-orange.svg)](https://www.mysql.com/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple.svg)](https://getbootstrap.com/)
[![Chart.js](https://img.shields.io/badge/Charts-Chart.js%204.4-pink.svg)](https://www.chartjs.org/)
[![Status](https://img.shields.io/badge/Security-SOC%20Grade-success.svg)]()

> **Distributed Cybersecurity & Threat Alerting Platform**  
> A functional, enterprise-grade, distributed intrusion detection and threat alerting platform.

---

## 1. PROJECT ABSTRACT & OVERVIEW

Traditional perimeter firewalls and monolithic intrusion detection systems (IDS) struggle to detect lateral attack movements within enterprise subnets and coordinated multi-source attacks. 

The **Distributed Cyberattack Detection and Alert System (Sentinel IDS)** addresses these challenges by deploying autonomous, lightweight monitoring sensor agents across diverse network zones (Perimeter Gateways, DMZ Web Clusters, and Corporate Internal LANs). These sensors capture packet telemetry and securely stream telemetry to a centralized Flask Security Operations Center (SOC) engine via authenticated REST APIs.

The central engine applies **7 distinct detection algorithms** combining deterministic rule signatures and statistical anomaly models (Z-Score) to identify DoS floods, DDoS botnets, port scans, SSH brute-force attempts, blacklisted threat intelligence IPs, traffic spikes, and TCP SYN flood half-open attacks. Detected incidents are deduplicated, prioritized, and visualized through a cybersecurity SOC dashboard.

---

## 2. CORE SYSTEM CAPABILITIES

- **7 Active Attack Detection Algorithms**:
  1. **DoS Volumetric Flood Detector** (Single-source packet exhaustion)
  2. **DDoS Coordinated Botnet Detector** (Multi-source distributed assault)
  3. **Port Scanning Reconnaissance Detector** (Vertical & horizontal port sweeps)
  4. **Brute-Force Authentication Detector** (SSH/FTP/HTTP login bursts)
  5. **Suspicious IP & Threat Intel Matcher** (Known C2 beacons, Tor exit nodes, Mirai botnets)
  6. **Statistical Traffic Anomaly Detector** (Moving baseline Z-Score $\sigma$ deviation)
  7. **TCP SYN Flood Detector** (Half-open connection backlog exhaustion)
- **Distributed Agent Fleet Management**: Multi-sensor heartbeat monitoring, automatic offline status detection, and API-key authenticated telemetry.
- **Alert Triage & De-duplication**: Cooldown rate-limiting prevents alert fatigue; full incident state machine (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`).
- **Interactive SOC Dashboard**: Dark cybersecurity theme featuring Chart.js attack distribution doughnut, real-time traffic timeline, and threat intelligence scoring.
- **Forensic PCAP File Analysis**: Ingest and inspect `.pcap` / `.pcapng` packet captures using Scapy or pure-Python binary parser fallback.
- **Reporting & CSV Export**: Automated daily/monthly incident summaries and instant downloadable CSV compliance reports.
- **Dual-Engine Database Layer**: Full MySQL support (`cyberattack_detection`) with automatic SQLite fallback for offline viva demonstrations.

---

## 3. PROJECT DIRECTORY STRUCTURE

```
cyberattack-detection/
├── app.py                     # Flask application factory, routes, and error handlers
├── config.py                  # System configurations, thresholds, and secret keys
├── requirements.txt           # Python dependency specifications
├── run_server.py              # Server launcher with banner and configuration validation
├── database/
│   ├── __init__.py
│   ├── db.py                  # Dual-engine DatabaseManager (MySQL + SQLite fallback)
│   ├── schema.sql             # Complete MySQL DDL schema with keys, FKs, and indexes
│   └── sample_data.sql        # Realistic sample seeds for users, agents, attacks, and alerts
├── agents/
│   ├── __init__.py
│   ├── monitoring_agent.py    # Standalone distributed monitoring agent daemon
│   └── simulate_attacks.py    # Safe attack scenario generator (DoS, DDoS, PortScan, etc.)
├── detection/
│   ├── __init__.py
│   ├── engine.py              # Central Intrusion Detection Engine orchestrator
│   ├── dos_detection.py       # DoS volumetric rate-limit detector
│   ├── ddos_detection.py      # DDoS multi-source coordinated detector
│   ├── port_scan_detection.py # Port sweep reconnaissance detector
│   ├── brute_force_detection.py # Authentication failure detector
│   ├── suspicious_ip_detection.py # Threat intelligence blacklist matcher
│   ├── anomaly_detection.py   # Statistical baseline & Z-Score anomaly detector
│   └── syn_flood_detection.py # TCP half-open SYN connection detector
├── routes/
│   ├── __init__.py
│   ├── auth.py                # User login, session management, and logout
│   ├── dashboard.py           # Dashboard views & real-time telemetry stats API
│   ├── monitoring.py          # Live traffic inspection & PCAP upload handling
│   ├── alerts.py              # Incident triage, status transitions, and bulk actions
│   ├── agents.py              # Sensor agent registration & packet ingest REST API
│   ├── reports.py             # Security reports & CSV export
│   └── settings.py            # Detection threshold configuration & simulator trigger
├── templates/
│   ├── base.html              # Cyber SOC master layout (Bootstrap 5, Chart.js)
│   ├── login.html             # High-tech cybersecurity login terminal
│   ├── dashboard.html         # Executive SOC operations dashboard
│   ├── monitoring.html        # Live packet telemetry & PCAP inspection
│   ├── alerts.html            # Incident alert management roster & forensics modal
│   ├── agents.html            # Distributed agent fleet status & sensor registration
│   ├── reports.html           # Security reports & audit trail logs
│   └── settings.html          # Configurable thresholds & on-demand attack simulator
├── static/
│   ├── css/
│   │   └── style.css          # SOC cybersecurity dark theme styles & animations
│   └── js/
│       ├── dashboard.js       # Live charts, stat counters, and auto-polling
│       ├── monitoring.js      # Traffic stream filter & PCAP upload handler
│       └── alerts.js          # Alert triage, selection, and forensics modal
├── utils/
│   ├── __init__.py
│   ├── alert_manager.py       # Alert generator, de-duplication, and severity assignment
│   ├── logger.py              # System and security audit logger
│   └── pcap_parser.py         # Scapy PCAP reader + pure-Python binary PCAP fallback
├── tests/
│   ├── __init__.py
│   ├── test_detection.py      # Unit tests for all 7 detection algorithms
│   ├── test_db.py             # Database connectivity & table schema tests
│   └── test_api.py            # Flask endpoints & agent ingest API integration tests
├── sample_pcaps/
│   └── sample_traffic.json    # Sample packet trace for immediate evaluation
├── docs/
│   ├── ARCHITECTURE.md        # Architecture diagrams, DFD (0 & 1), Use Case, and ER diagrams
│   └── VIVA_QUESTIONS.md      # 25+ Comprehensive viva questions & answers for project defense
└── README.md                  # Project documentation & operational guide
```

---

## 4. DEFAULT EVALUATION CREDENTIALS

| Account Role | Username | Password | Access Privileges |
| :--- | :--- | :--- | :--- |
| **SOC Administrator** | `admin` | `Admin@123` | Full administrative control, threshold configuration, agent key generation, IP blocking |
| **Security Analyst** | `analyst` | `Analyst@123` | Incident triage, live traffic monitoring, PCAP inspection, alert acknowledgement/resolution |

---

## 5. INSTALLATION & SETUP INSTRUCTIONS (WINDOWS & VS CODE)

### Step 1: Open Terminal in Project Directory
Open **VS Code**, navigate to the project directory:
```powershell
cd c:\Users\GAURAV\OneDrive\Desktop\ds\cyberattack-detection
```

### Step 2: Install Python Dependencies
Install required packages using pip:
```powershell
pip install -r requirements.txt
```

---

## 6. DATABASE CONFIGURATION

### Option A: Using MySQL (Recommended for Production / Final Viva)
1. Ensure your MySQL server (or XAMPP / WampServer) is running on port `3306`.
2. Log into MySQL via command line or phpMyAdmin:
   ```sql
   mysql -u root -p
   ```
3. Execute the database schema and sample data:
   ```sql
   SOURCE database/schema.sql;
   SOURCE database/sample_data.sql;
   ```
4. Update MySQL credentials in `config.py` (or set environment variables):
   ```python
   DB_TYPE = 'mysql'
   MYSQL_HOST = 'localhost'
   MYSQL_USER = 'root'
   MYSQL_PASSWORD = 'your_mysql_password'
   MYSQL_DB = 'cyberattack_detection'
   ```

### Option B: Automatic SQLite Fallback (Zero Setup / Offline Evaluation)
- If MySQL is not running or unconfigured, the system **automatically falls back to an embedded SQLite database** (`database/cyberattack_detection.db`), automatically creates all 7 normalized tables, and seeds initial sample records. No configuration required!

---

## 7. RUNNING THE APPLICATION

### 1. Start the Central Flask SOC Server
```powershell
python run_server.py
```
- Open your browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**
---

## 8. RUNNING DISTRIBUTED MONITORING AGENTS

Open a new terminal window in VS Code to run sensor agents:

### Start Agent 1 (Perimeter Gateway Sensor):
```powershell
python agents/monitoring_agent.py --server http://127.0.0.1:5000 --agent-id AGENT-GW-01 --key APIKEY-GW-01-SECURE-9901 --name "Perimeter Gateway Sensor"
```

### Start Agent 2 (DMZ Web Server Sensor):
```powershell
python agents/monitoring_agent.py --server http://127.0.0.1:5000 --agent-id AGENT-DMZ-02 --key APIKEY-DMZ-02-SECURE-9902 --name "DMZ Web Server Sensor"
```

### Start Agent 3 (Internal Corporate LAN Sensor):
```powershell
python agents/monitoring_agent.py --server http://127.0.0.1:5000 --agent-id AGENT-INT-03 --key APIKEY-INT-03-SECURE-9903 --name "Internal Subnet Sensor"
```

*The sensors will immediately self-register, send 30-second heartbeats, and stream live packet telemetry to the SOC dashboard.*

---

## 9. DEMONSTRATING CYBERATTACK DETECTION (VIVA DEMO)

### Method 1: Using the Web Dashboard Simulator
1. Navigate to **Detection Thresholds** page (`/settings`).
2. Locate the **Interactive Attack Simulation Testing Console**.
3. Click any attack button (e.g., **Trigger DoS**, **Trigger DDoS**, **Trigger Port Scan**, or **Execute All Scenarios**).
4. Watch the alert banner update in real-time, then switch to the **SOC Dashboard** or **Security Alerts** page to inspect the new incidents!

### Method 2: Using the CLI Simulation Script
Open another terminal and trigger simulated attack scenarios:

```powershell
# Run all 7 attack simulation scenarios sequentially
python agents/simulate_attacks.py --scenario all

# Or run individual attack scenarios:
python agents/simulate_attacks.py --scenario dos
python agents/simulate_attacks.py --scenario ddos
python agents/simulate_attacks.py --scenario portscan
python agents/simulate_attacks.py --scenario bruteforce
python agents/simulate_attacks.py --scenario suspicious_ip
python agents/simulate_attacks.py --scenario synflood
python agents/simulate_attacks.py --scenario anomaly
```

---

## 10. RUNNING AUTOMATED UNIT & INTEGRATION TESTS

Run the comprehensive unit test suite:

```powershell
# 1. Run Detection Algorithm Tests
python -m unittest tests/test_detection.py

# 2. Run Database Schema & Query Tests
python -m unittest tests/test_db.py

# 3. Run Flask API & Ingestion Tests
python -m unittest tests/test_api.py

# 4. Run All Tests Together
python -m unittest discover tests
```

---


