import json
import hashlib
from typing import List, Dict, Any, Set
from utils import logger

class IOCDetector:
    def __init__(self):
        self.iocs = self.load_sample_iocs()

    def load_sample_iocs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load hardcoded sample IOCs."""
        return {
            'ips': [
                {'value': '192.168.1.100', 'severity': 'high', 'description': 'Known malicious IP'},
                {'value': '10.0.0.1', 'severity': 'medium', 'description': 'Suspicious internal IP'}
            ],
            'domains': [
                {'value': 'malicious.com', 'severity': 'high', 'description': 'Malicious domain'},
                {'value': 'suspicious.net', 'severity': 'medium', 'description': 'Suspicious domain'}
            ],
            'hashes': [
                {'value': 'd41d8cd98f00b204e9800998ecf8427e', 'severity': 'critical', 'description': 'Known malware hash (MD5)'},
                {'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'severity': 'high', 'description': 'Known malware hash (SHA256)'}
            ],
            'processes': [
                {'value': 'malware.exe', 'severity': 'critical', 'description': 'Known malicious process'},
                {'value': 'suspicious_process', 'severity': 'medium', 'description': 'Suspicious process name'}
            ],
            'registry_keys': [
                {'value': 'HKLM\\SOFTWARE\\Malware', 'severity': 'high', 'description': 'Malware registry persistence'}
            ]
        }

    def load_iocs_from_json(self, json_path: str):
        """Load IOCs from JSON file for extensibility."""
        try:
            with open(json_path, 'r') as f:
                self.iocs = json.load(f)
            logger.info(f"Loaded IOCs from {json_path}")
        except Exception as e:
            logger.error(f"Error loading IOCs from {json_path}: {str(e)}")

    def detect_iocs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect IOCs in parsed logs."""
        matches = []
        for log in logs:
            message = log.get('message', '').lower()
            for ioc_type, ioc_list in self.iocs.items():
                for ioc in ioc_list:
                    value = ioc['value'].lower()
                    if value in message:
                        match = {
                            'log_id': log.get('id'),
                            'ioc_type': ioc_type,
                            'ioc_value': ioc['value'],
                            'severity': ioc['severity'],
                            'description': ioc['description'],
                            'log_message': log.get('message'),
                            'timestamp': log.get('timestamp')
                        }
                        matches.append(match)
                        logger.info(f"IOC match found: {ioc_type} - {ioc['value']}")
        return matches

    def calculate_hash(self, data: str) -> Dict[str, str]:
        """Calculate MD5 and SHA256 hashes."""
        md5 = hashlib.md5(data.encode()).hexdigest()
        sha256 = hashlib.sha256(data.encode()).hexdigest()
        return {'md5': md5, 'sha256': sha256}

    def check_file_hash(self, file_path: str) -> Dict[str, Any]:
        """Check if file hash matches known IOCs."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            hashes = self.calculate_hash(data.decode('utf-8', errors='ignore'))
            for hash_type, hash_value in hashes.items():
                for ioc in self.iocs.get('hashes', []):
                    if ioc['value'] == hash_value:
                        return {
                            'match': True,
                            'hash_type': hash_type,
                            'hash_value': hash_value,
                            'severity': ioc['severity'],
                            'description': ioc['description']
                        }
            return {'match': False}
        except Exception as e:
            logger.error(f"Error checking file hash: {str(e)}")
            return {'match': False}
