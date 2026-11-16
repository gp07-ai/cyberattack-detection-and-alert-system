"""
System & Security Audit Logging Utility.
Records application events, operational logs, and security audits to console and database.
"""
import logging
import sys
from datetime import datetime

# Configure standard console logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('CyberSentinel')

def log_system_event(module, message, log_level='INFO', user_id=None, ip_address=None):
    """
    Logs an event to system logs in database and console.
    """
    logger.info(f"[{module}] ({log_level}) {message}")
    try:
        from database.db import db
        sql = """
        INSERT INTO system_logs (log_level, module, message, user_id, ip_address, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s);
        """
        db.execute_query(sql, (
            log_level.upper(),
            module,
            message,
            user_id,
            ip_address,
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))
    except Exception as e:
        logger.error(f"Failed to record system log into database: {e}")
