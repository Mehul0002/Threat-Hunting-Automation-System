import sqlite3
from typing import List, Dict, Any
from utils import logger

class ThreatDatabase:
    def __init__(self, db_path: str = 'threat_hunter.db'):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize the database tables."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY,
                    os_type TEXT,
                    event_id TEXT,
                    source TEXT,
                    message TEXT,
                    timestamp TEXT,
                    raw_log TEXT
                )
            ''')
            # IOCs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY,
                    type TEXT,
                    value TEXT,
                    severity TEXT,
                    description TEXT
                )
            ''')
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    log_id INTEGER,
                    ioc_id INTEGER,
                    sigma_rule TEXT,
                    severity TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (log_id) REFERENCES logs (id),
                    FOREIGN KEY (ioc_id) REFERENCES iocs (id)
                )
            ''')
            conn.commit()

    def insert_log(self, log_data: Dict[str, Any]) -> int:
        """Insert a parsed log entry."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO logs (os_type, event_id, source, message, timestamp, raw_log)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                log_data.get('os_type'),
                log_data.get('event_id'),
                log_data.get('source'),
                log_data.get('message'),
                log_data.get('timestamp'),
                log_data.get('raw_log')
            ))
            return cursor.lastrowid

    def insert_ioc(self, ioc_data: Dict[str, Any]) -> int:
        """Insert an IOC."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO iocs (type, value, severity, description)
                VALUES (?, ?, ?, ?)
            ''', (
                ioc_data.get('type'),
                ioc_data.get('value'),
                ioc_data.get('severity'),
                ioc_data.get('description')
            ))
            return cursor.lastrowid

    def insert_alert(self, alert_data: Dict[str, Any]) -> int:
        """Insert an alert."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (log_id, ioc_id, sigma_rule, severity, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                alert_data.get('log_id'),
                alert_data.get('ioc_id'),
                alert_data.get('sigma_rule'),
                alert_data.get('severity'),
                alert_data.get('timestamp')
            ))
            return cursor.lastrowid

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve all alerts."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT a.id, l.os_type, l.event_id, l.message, i.type, i.value, a.sigma_rule, a.severity, a.timestamp
                FROM alerts a
                LEFT JOIN logs l ON a.log_id = l.id
                LEFT JOIN iocs i ON a.ioc_id = i.id
            ''')
            rows = cursor.fetchall()
            return [dict(zip([column[0] for column in cursor.description], row)) for row in rows]
