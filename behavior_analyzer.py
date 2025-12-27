import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any
from utils import logger

class BehaviorAnalyzer:
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.process_spawns = defaultdict(list)

    def analyze_failed_logins(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect multiple failed login attempts (brute force)."""
        alerts = []
        for log in logs:
            if log.get('event_id') == '4625':  # Windows failed login
                username = log.get('message', '').split('Account Name:')[1].split('\n')[0].strip() if 'Account Name:' in log.get('message', '') else 'unknown'
                timestamp = datetime.fromisoformat(log.get('timestamp', datetime.now().isoformat()))
                self.failed_logins[username].append(timestamp)

        # Check for brute force
        for user, times in self.failed_logins.items():
            times.sort()
            # Check for 5+ failed logins in 10 minutes
            for i in range(len(times) - 4):
                if times[i+4] - times[i] <= timedelta(minutes=10):
                    alerts.append({
                        'type': 'brute_force',
                        'user': user,
                        'severity': 'high',
                        'description': f'Brute force login attempt detected for user {user}',
                        'timestamps': [t.isoformat() for t in times[i:i+5]],
                        'count': 5
                    })
                    logger.warning(f"Brute force detected for user {user}")
                    break
        return alerts

    def analyze_privilege_escalation(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect privilege escalation attempts."""
        alerts = []
        for log in logs:
            message = log.get('message', '').lower()
            if 'privilege escalation' in message or 'elevated privileges' in message:
                alerts.append({
                    'type': 'privilege_escalation',
                    'severity': 'critical',
                    'description': 'Privilege escalation attempt detected',
                    'log_message': log.get('message'),
                    'timestamp': log.get('timestamp')
                })
                logger.warning("Privilege escalation attempt detected")
        return alerts

    def analyze_unusual_processes(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual process spawning."""
        alerts = []
        temp_dirs = [r'c:\temp', r'c:\windows\temp', '/tmp', '/var/tmp']
        
        for log in logs:
            if log.get('event_id') == '4688':  # Windows process creation
                process_name = log.get('message', '').split('New Process Name:')[1].split('\n')[0].strip() if 'New Process Name:' in log.get('message', '') else ''
                if any(temp_dir in process_name.lower() for temp_dir in temp_dirs):
                    alerts.append({
                        'type': 'unusual_process',
                        'severity': 'medium',
                        'description': f'Process executed from temp directory: {process_name}',
                        'process_name': process_name,
                        'timestamp': log.get('timestamp')
                    })
                    logger.info(f"Unusual process execution: {process_name}")

        # Linux process execution (simplified)
        for log in logs:
            if 'exec' in log.get('message', '').lower() and any(temp_dir in log.get('message', '').lower() for temp_dir in temp_dirs):
                alerts.append({
                    'type': 'unusual_process',
                    'severity': 'medium',
                    'description': 'Process executed from temp directory on Linux',
                    'log_message': log.get('message'),
                    'timestamp': log.get('timestamp')
                })
        return alerts

    def analyze_persistence_mechanisms(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect persistence techniques."""
        alerts = []
        persistence_indicators = [
            'scheduled task', 'registry run', 'startup folder', 'service creation',
            'cron job', 'systemd', 'init.d'
        ]
        
        for log in logs:
            message = log.get('message', '').lower()
            for indicator in persistence_indicators:
                if indicator in message:
                    alerts.append({
                        'type': 'persistence',
                        'severity': 'high',
                        'description': f'Persistence mechanism detected: {indicator}',
                        'indicator': indicator,
                        'log_message': log.get('message'),
                        'timestamp': log.get('timestamp')
                    })
                    logger.warning(f"Persistence mechanism detected: {indicator}")
                    break
        return alerts

    def analyze_all_behaviors(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all behavior analyses."""
        all_alerts = []
        all_alerts.extend(self.analyze_failed_logins(logs))
        all_alerts.extend(self.analyze_privilege_escalation(logs))
        all_alerts.extend(self.analyze_unusual_processes(logs))
        all_alerts.extend(self.analyze_persistence_mechanisms(logs))
        return all_alerts

    def get_behavior_summary(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of behavioral patterns."""
        summary = {
            'total_logs': len(logs),
            'event_types': Counter(log.get('event_id') for log in logs if log.get('event_id')),
            'sources': Counter(log.get('source') for log in logs if log.get('source')),
            'time_range': {
                'start': min(log.get('timestamp') for log in logs if log.get('timestamp')),
                'end': max(log.get('timestamp') for log in logs if log.get('timestamp'))
            } if logs else {}
        }
        return summary
