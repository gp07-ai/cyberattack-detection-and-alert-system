"""
Alert Management Engine.
Handles alert generation, de-duplication, severity assignment, status updates,
and integration with the attack logging and threat intelligence database.
"""
import uuid
import time
from datetime import datetime, timedelta
from config import Config
from database.db import db
from utils.logger import logger, log_system_event

class AlertManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AlertManager, cls).__new__(cls)
            cls._instance._recent_alerts = {}  # Cache: { (attack_type, src_ip, dest_ip): last_alert_time }
        return cls._instance

    def create_alert(self, attack_info, agent_id='AGENT-GW-01'):
        """
        Creates an attack log entry and security alert if not deduplicated.
        attack_info dict format:
        {
            'attack_type': str,
            'source_ip': str,
            'dest_ip': str,
            'target_port': int,
            'protocol': str,
            'packet_count': int,
            'signature_rule': str,
            'confidence': float,
            'severity': 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL',
            'details': str,
            'recommended_action': str
        }
        """
        attack_type = attack_info.get('attack_type', 'Suspicious Activity')
        src_ip = attack_info.get('source_ip', 'Unknown')
        dest_ip = attack_info.get('dest_ip', 'Unknown')
        severity = attack_info.get('severity', 'MEDIUM').upper()
        
        # De-duplication check: avoid storming identical alerts within cooldown window
        dedup_key = (attack_type, src_ip, dest_ip)
        now = time.time()
        last_time = self._recent_alerts.get(dedup_key, 0)
        cooldown = Config.ALERT_DEDUPLICATION_WINDOW_SECONDS

        if now - last_time < cooldown:
            logger.debug(f"Alert de-duplicated: {attack_type} from {src_ip} -> {dest_ip}")
            return None

        # Record cooldown timestamp
        self._recent_alerts[dedup_key] = now

        # Clean old cache entries
        self._recent_alerts = {k: v for k, v in self._recent_alerts.items() if now - v < 300}

        try:
            # 1. Insert into attack_logs
            attack_sql = """
            INSERT INTO attack_logs (
                agent_id, attack_type, source_ip, dest_ip, target_port,
                protocol, packet_count, signature_rule, detection_confidence,
                details, timestamp
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            attack_log_id = db.execute_query(attack_sql, (
                agent_id,
                attack_type,
                src_ip,
                dest_ip,
                attack_info.get('target_port'),
                attack_info.get('protocol', 'TCP'),
                attack_info.get('packet_count', 1),
                attack_info.get('signature_rule', 'GENERIC-RULE-01'),
                attack_info.get('confidence', 0.95),
                attack_info.get('details', ''),
                now_str
            ))

            # 2. Generate unique alert code (e.g. ALT-2026-A1B2)
            alert_code = f"ALT-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"

            # 3. Insert into security_alerts
            alert_sql = """
            INSERT INTO security_alerts (
                alert_code, attack_log_id, agent_id, attack_type, source_ip,
                dest_ip, severity, status, description, recommended_action, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'NEW', %s, %s, %s);
            """
            alert_id = db.execute_query(alert_sql, (
                alert_code,
                attack_log_id,
                agent_id,
                attack_type,
                src_ip,
                dest_ip,
                severity,
                attack_info.get('details', 'Security anomaly detected.'),
                attack_info.get('recommended_action', 'Investigate endpoint traffic and verify firewall rules.'),
                now_str
            ))

            # 4. If severity is HIGH or CRITICAL, update or insert into suspicious_ips table
            if severity in ('HIGH', 'CRITICAL') and not src_ip.startswith('DISTRIBUTED') and src_ip not in ('127.0.0.1', '0.0.0.0'):
                self._record_suspicious_ip(src_ip, attack_type, severity)

            log_system_event(
                module='ALERT_ENGINE',
                message=f"Generated {severity} alert {alert_code}: {attack_type} from {src_ip} targeting {dest_ip}",
                log_level='WARNING' if severity in ('LOW', 'MEDIUM') else 'ERROR',
                ip_address=src_ip
            )

            return {
                'id': alert_id,
                'alert_code': alert_code,
                'attack_type': attack_type,
                'source_ip': src_ip,
                'dest_ip': dest_ip,
                'severity': severity,
                'status': 'NEW',
                'created_at': now_str
            }

        except Exception as e:
            logger.error(f"Error persisting alert into database: {e}")
            return None

    def _record_suspicious_ip(self, ip_address, threat_type, severity):
        """Adds or updates suspicious IP reputation entry."""
        try:
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            existing = db.fetch_one("SELECT id, incident_count FROM suspicious_ips WHERE ip_address = %s;", (ip_address,))
            
            risk_score = 95 if severity == 'CRITICAL' else 80
            if existing:
                db.execute_query("""
                    UPDATE suspicious_ips 
                    SET incident_count = incident_count + 1,
                        last_seen = %s,
                        risk_score = CASE WHEN risk_score < 95 THEN risk_score + 5 ELSE 100 END
                    WHERE id = %s;
                """, (now_str, existing['id']))
            else:
                db.execute_query("""
                    INSERT INTO suspicious_ips (
                        ip_address, threat_type, risk_score, country_code,
                        asn_organization, incident_count, is_blocked, first_seen, last_seen
                    ) VALUES (%s, %s, %s, 'XX', 'External Threat Actor', 1, 0, %s, %s);
                """, (ip_address, threat_type, risk_score, now_str, now_str))
        except Exception as e:
            logger.warning(f"Could not record suspicious IP {ip_address}: {e}")

    def update_alert_status(self, alert_id, new_status, user_name='admin'):
        """
        Updates status of an alert: NEW, ACKNOWLEDGED, RESOLVED.
        """
        valid_statuses = ('NEW', 'ACKNOWLEDGED', 'RESOLVED')
        new_status = new_status.upper()
        if new_status not in valid_statuses:
            return False, f"Invalid status: {new_status}"

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if new_status == 'ACKNOWLEDGED':
            sql = """
            UPDATE security_alerts 
            SET status = %s, acknowledged_by = %s, acknowledged_at = %s 
            WHERE id = %s;
            """
            params = (new_status, user_name, now_str, alert_id)
        elif new_status == 'RESOLVED':
            sql = """
            UPDATE security_alerts 
            SET status = %s, resolved_by = %s, resolved_at = %s 
            WHERE id = %s;
            """
            params = (new_status, user_name, now_str, alert_id)
        else:
            sql = "UPDATE security_alerts SET status = %s WHERE id = %s;"
            params = (new_status, alert_id)

        db.execute_query(sql, params)
        log_system_event('ALERTS', f"Alert ID #{alert_id} status changed to {new_status} by {user_name}.", 'AUDIT')
        return True, "Alert status updated successfully."

alert_manager = AlertManager()
