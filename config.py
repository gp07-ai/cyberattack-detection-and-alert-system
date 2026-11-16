"""
Configuration module for Distributed Cyberattack Detection and Alert System.
Supports MySQL database with automatic SQLite fallback for offline demonstrations.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-sentinel-ultra-secure-key-2026')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 'yes')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max for PCAP uploads

    # Database Configuration (MySQL as primary, SQLite as fallback)
    DB_TYPE = os.environ.get('DB_TYPE', 'mysql').lower()  # 'mysql' or 'sqlite'
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'root')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'cyberattack_detection')
    
    # SQLite fallback database path
    SQLITE_PATH = os.path.join(BASE_DIR, 'database', 'cyberattack_detection.db')

    # Agent Authentication
    AGENT_SHARED_SECRET = os.environ.get('AGENT_SECRET', 'AGENT-SECRET-KEY-9941-XYZ')
    AGENT_HEARTBEAT_TIMEOUT = 120  # Seconds before marking agent as OFFLINE

    # Attack Detection Engine Configurable Thresholds
    # 1. DoS Detection: Packets from a single IP within detection window
    DOS_PACKET_THRESHOLD = int(os.environ.get('DOS_PACKET_THRESHOLD', 60))
    DOS_WINDOW_SECONDS = int(os.environ.get('DOS_WINDOW_SECONDS', 10))

    # 2. DDoS Detection: Distinct attacking IPs targeting same destination
    DDOS_MIN_ATTACKING_IPS = int(os.environ.get('DDOS_MIN_ATTACKING_IPS', 4))
    DDOS_PACKET_THRESHOLD = int(os.environ.get('DDOS_PACKET_THRESHOLD', 120))
    DDOS_WINDOW_SECONDS = int(os.environ.get('DDOS_WINDOW_SECONDS', 15))

    # 3. Port Scanning Detection: Distinct destination ports probed by single IP
    PORT_SCAN_PORT_THRESHOLD = int(os.environ.get('PORT_SCAN_PORT_THRESHOLD', 8))
    PORT_SCAN_WINDOW_SECONDS = int(os.environ.get('PORT_SCAN_WINDOW_SECONDS', 15))

    # 4. Brute Force Login Detection: Failed login attempts within window
    BRUTE_FORCE_ATTEMPT_THRESHOLD = int(os.environ.get('BRUTE_FORCE_ATTEMPT_THRESHOLD', 5))
    BRUTE_FORCE_WINDOW_SECONDS = int(os.environ.get('BRUTE_FORCE_WINDOW_SECONDS', 60))

    # 5. SYN Flood Detection: Half-open TCP SYN packets without ACK completion
    SYN_FLOOD_THRESHOLD = int(os.environ.get('SYN_FLOOD_THRESHOLD', 35))
    SYN_FLOOD_WINDOW_SECONDS = int(os.environ.get('SYN_FLOOD_WINDOW_SECONDS', 10))

    # 6. Anomaly / Traffic Spike Detection (Z-Score & Spike Factor)
    ANOMALY_ZSCORE_THRESHOLD = float(os.environ.get('ANOMALY_ZSCORE_THRESHOLD', 2.5))
    TRAFFIC_SPIKE_MULTIPLIER = float(os.environ.get('TRAFFIC_SPIKE_MULTIPLIER', 3.0))

    # 7. Alert Management & De-duplication
    ALERT_DEDUPLICATION_WINDOW_SECONDS = int(os.environ.get('ALERT_DEDUP_WINDOW', 30))

    # Threat Intelligence Feeds / Known Malicious IP blacklist (Sample set)
    KNOWN_SUSPICIOUS_IPS = {
        '198.51.100.14': 'Known Mirai Botnet C2 Node',
        '203.0.113.88': 'Reported Brute-Force Scanner',
        '185.220.101.5': 'Tor Exit Node / High Risk Anonymizer',
        '103.152.18.23': 'Identified Cobalt Strike Beacon',
        '45.146.164.110': 'Active Ransomware Scanner IP',
        '194.26.29.112': 'Malicious SSH Dictionary Attacker',
        '185.191.171.12': 'Cryptominer Delivery Source'
    }
