"""
MITRE ATT&CK framework mapping for threat attribution.
Maps detected behaviors to ATT&CK techniques and tactics.
"""

from typing import List, Dict, Any, Optional
from loguru import logger


class ATTACKTechnique:
    """Represents a MITRE ATT&CK technique."""

    def __init__(self, technique_id: str, name: str, tactic: str, description: str = ""):
        """Initialize ATT&CK technique."""
        self.technique_id = technique_id
        self.name = name
        self.tactic = tactic
        self.description = description

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary."""
        return {
            'id': self.technique_id,
            'name': self.name,
            'tactic': self.tactic,
            'description': self.description
        }


class ATTACKMapper:
    """
    Maps anomalies and behaviors to MITRE ATT&CK techniques.
    Provides threat intelligence context for hunting leads.
    """

    def __init__(self, framework_path: Optional[str] = None):
        """
        Initialize ATT&CK mapper.

        Args:
            framework_path: Path to ATT&CK framework JSON (optional)
        """
        self.framework_path = framework_path
        self.techniques_db = self._load_techniques()

        logger.info(f"ATT&CK mapper initialized with {len(self.techniques_db)} techniques")

    def _load_techniques(self) -> Dict[str, ATTACKTechnique]:
        """Load ATT&CK techniques database."""
        # In production, would load from enterprise-attack.json
        # For now, using a curated subset of common techniques

        techniques = {
            # Initial Access
            'T1078': ATTACKTechnique(
                'T1078',
                'Valid Accounts',
                'Initial Access',
                'Adversaries may obtain and abuse credentials of existing accounts'
            ),
            'T1190': ATTACKTechnique(
                'T1190',
                'Exploit Public-Facing Application',
                'Initial Access',
                'Adversaries may attempt to exploit vulnerabilities in public-facing applications'
            ),

            # Execution
            'T1059.001': ATTACKTechnique(
                'T1059.001',
                'Command and Scripting Interpreter: PowerShell',
                'Execution',
                'Adversaries may abuse PowerShell commands and scripts'
            ),
            'T1053': ATTACKTechnique(
                'T1053',
                'Scheduled Task/Job',
                'Execution',
                'Adversaries may abuse task scheduling functionality'
            ),

            # Persistence
            'T1136': ATTACKTechnique(
                'T1136',
                'Create Account',
                'Persistence',
                'Adversaries may create an account to maintain access'
            ),
            'T1547': ATTACKTechnique(
                'T1547',
                'Boot or Logon Autostart Execution',
                'Persistence',
                'Adversaries may configure system settings to automatically execute programs'
            ),

            # Privilege Escalation
            'T1068': ATTACKTechnique(
                'T1068',
                'Exploitation for Privilege Escalation',
                'Privilege Escalation',
                'Adversaries may exploit software vulnerabilities to elevate privileges'
            ),
            'T1134': ATTACKTechnique(
                'T1134',
                'Access Token Manipulation',
                'Privilege Escalation',
                'Adversaries may modify access tokens to operate under different users'
            ),

            # Defense Evasion
            'T1070': ATTACKTechnique(
                'T1070',
                'Indicator Removal on Host',
                'Defense Evasion',
                'Adversaries may delete or modify artifacts generated on host systems'
            ),
            'T1562': ATTACKTechnique(
                'T1562',
                'Impair Defenses',
                'Defense Evasion',
                'Adversaries may maliciously modify components to impair defenses'
            ),

            # Credential Access
            'T1110': ATTACKTechnique(
                'T1110',
                'Brute Force',
                'Credential Access',
                'Adversaries may use brute force techniques to gain access'
            ),
            'T1003': ATTACKTechnique(
                'T1003',
                'OS Credential Dumping',
                'Credential Access',
                'Adversaries may attempt to dump credentials'
            ),

            # Discovery
            'T1083': ATTACKTechnique(
                'T1083',
                'File and Directory Discovery',
                'Discovery',
                'Adversaries may enumerate files and directories'
            ),
            'T1046': ATTACKTechnique(
                'T1046',
                'Network Service Scanning',
                'Discovery',
                'Adversaries may attempt to get a listing of services running on remote hosts'
            ),

            # Lateral Movement
            'T1021.002': ATTACKTechnique(
                'T1021.002',
                'Remote Services: SMB/Windows Admin Shares',
                'Lateral Movement',
                'Adversaries may use SMB to interact with remote systems'
            ),
            'T1570': ATTACKTechnique(
                'T1570',
                'Lateral Tool Transfer',
                'Lateral Movement',
                'Adversaries may transfer tools between systems'
            ),

            # Collection
            'T1005': ATTACKTechnique(
                'T1005',
                'Data from Local System',
                'Collection',
                'Adversaries may search local system sources for sensitive data'
            ),
            'T1114': ATTACKTechnique(
                'T1114',
                'Email Collection',
                'Collection',
                'Adversaries may target user email to collect sensitive information'
            ),

            # Command and Control
            'T1071': ATTACKTechnique(
                'T1071',
                'Application Layer Protocol',
                'Command and Control',
                'Adversaries may communicate using application layer protocols'
            ),
            'T1095': ATTACKTechnique(
                'T1095',
                'Non-Application Layer Protocol',
                'Command and Control',
                'Adversaries may use non-application layer protocols for C2'
            ),

            # Exfiltration
            'T1041': ATTACKTechnique(
                'T1041',
                'Exfiltration Over C2 Channel',
                'Exfiltration',
                'Adversaries may steal data by exfiltrating over existing C2 channel'
            ),
            'T1048': ATTACKTechnique(
                'T1048',
                'Exfiltration Over Alternative Protocol',
                'Exfiltration',
                'Adversaries may steal data using alternative protocols'
            ),

            # Impact
            'T1486': ATTACKTechnique(
                'T1486',
                'Data Encrypted for Impact',
                'Impact',
                'Adversaries may encrypt data on target systems'
            ),
            'T1490': ATTACKTechnique(
                'T1490',
                'Inhibit System Recovery',
                'Impact',
                'Adversaries may delete or remove built-in data and disable services'
            ),
        }

        return techniques

    def map_anomaly_to_techniques(
        self,
        anomaly: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> List[ATTACKTechnique]:
        """
        Map an anomaly to potential ATT&CK techniques.

        Args:
            anomaly: Anomaly dictionary
            context: Additional context

        Returns:
            List of ATTACKTechnique objects
        """
        techniques = []
        context = context or {}

        # Determine anomaly characteristics
        anomaly_type = context.get('anomaly_type', '').lower()
        event_type = context.get('event_type', '').lower()

        # Authentication anomalies
        if 'auth' in anomaly_type or 'login' in anomaly_type:
            if 'failure' in anomaly_type or context.get('failed_attempts', 0) > 0:
                techniques.append(self.techniques_db['T1110'])  # Brute Force
            techniques.append(self.techniques_db['T1078'])  # Valid Accounts

        # File access anomalies
        if 'file' in anomaly_type or 'file' in event_type:
            techniques.append(self.techniques_db['T1083'])  # File Discovery
            if context.get('sensitive_data'):
                techniques.append(self.techniques_db['T1005'])  # Data from Local System

        # Network anomalies
        if 'network' in anomaly_type or 'connection' in anomaly_type:
            techniques.append(self.techniques_db['T1071'])  # Application Layer Protocol
            if context.get('unusual_port'):
                techniques.append(self.techniques_db['T1095'])  # Non-Application Layer Protocol
            if context.get('large_transfer'):
                techniques.append(self.techniques_db['T1041'])  # Exfiltration Over C2

        # Process anomalies
        if 'process' in anomaly_type:
            if 'powershell' in str(context.get('process_name', '')).lower():
                techniques.append(self.techniques_db['T1059.001'])  # PowerShell
            if context.get('privilege_escalation'):
                techniques.append(self.techniques_db['T1068'])  # Privilege Escalation

        # Lateral movement indicators
        if 'smb' in anomaly_type or 'share' in anomaly_type:
            techniques.append(self.techniques_db['T1021.002'])  # SMB/Admin Shares
            techniques.append(self.techniques_db['T1570'])  # Lateral Tool Transfer

        # Unusual time/location
        if context.get('unusual_time') or context.get('unusual_location'):
            techniques.append(self.techniques_db['T1078'])  # Valid Accounts (potentially compromised)

        return techniques

    def get_technique(self, technique_id: str) -> Optional[ATTACKTechnique]:
        """
        Get technique by ID.

        Args:
            technique_id: ATT&CK technique ID (e.g., 'T1078')

        Returns:
            ATTACKTechnique object or None
        """
        return self.techniques_db.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> List[ATTACKTechnique]:
        """
        Get all techniques for a tactic.

        Args:
            tactic: Tactic name (e.g., 'Lateral Movement')

        Returns:
            List of ATTACKTechnique objects
        """
        return [
            tech for tech in self.techniques_db.values()
            if tech.tactic.lower() == tactic.lower()
        ]

    def enrich_lead(self, lead: Dict[str, Any], anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Enrich threat hunting lead with ATT&CK mapping.

        Args:
            lead: Threat lead dictionary
            anomalies: Related anomalies

        Returns:
            Enriched lead with ATT&CK techniques
        """
        all_techniques = []

        for anomaly in anomalies:
            techniques = self.map_anomaly_to_techniques(anomaly, lead.get('context', {}))
            all_techniques.extend(techniques)

        # Remove duplicates
        unique_techniques = {tech.technique_id: tech for tech in all_techniques}

        lead['attack_techniques'] = [tech.to_dict() for tech in unique_techniques.values()]

        return lead
