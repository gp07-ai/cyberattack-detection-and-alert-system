"""
Convenience Server Launcher for Distributed Cyberattack Detection and Alert System.
Run this script to initialize databases, verify sensors, and launch the SOC Web Portal.
"""
import os
import sys

# Ensure current directory is in Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import Config
from database.db import db
from app import create_app

def banner():
    print("=" * 72)
    print("   DISTRIBUTED CYBERATTACK DETECTION AND ALERT SYSTEM (SENTINEL IDS)")
    print("   SOC Cyber Defense Incident Operations Center")
    print("=" * 72)
    print(f"[*] Engine Mode        : Active (All 7 Attack Detectors Loaded)")
    print(f"[*] Database Engine    : {db.db_type.upper()}")
    if db.db_type == 'mysql':
        print(f"[*] MySQL Target       : {Config.MYSQL_HOST}:{Config.MYSQL_PORT}/{Config.MYSQL_DB}")
    else:
        print(f"[*] SQLite Database    : {Config.SQLITE_PATH}")
    print(f"[*] Default Admin User : admin / Admin@123")
    print(f"[*] Default Analyst    : analyst / Analyst@123")
    print(f"[*] Portal Web URL     : http://127.0.0.1:5000")
    print("=" * 72)

if __name__ == '__main__':
    banner()
    app = create_app()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=Config.DEBUG)
