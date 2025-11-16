"""
Automated threat hunting lead generation.
Converts anomalies into actionable threat hunting leads with context.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from loguru import logger


class SeverityLevel(str, Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatLead:
    """Represents a threat hunting lead."""

    def __init__(
        self,
        lead_id: str,
        title: str,
        description: str,
        severity: SeverityLevel,
        confidence: float
    ):
        """Initialize threat lead."""
        self.lead_id = lead_id
        self.title = title
        self.description = description
        self.severity = severity
        self.confidence = confidence
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.status = "NEW"
        self.anomaly_ids: List[int] = []
        self.entities: Dict[str, List[str]] = {}
        self.attack_techniques: List[str] = []
        self.timeline_start: Optional[datetime] = None
        self.timeline_end: Optional[datetime] = None
        self.event_count = 0
        self.recommended_actions: List[str] = []
        self.evidence: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert lead to dictionary."""
        return {
            'lead_id': self.lead_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'anomaly_ids': self.anomaly_ids,
            'entities': self.entities,
            'attack_techniques': self.attack_techniques,
            'timeline': {
                'start': self.timeline_start.isoformat() if self.timeline_start else None,
                'end': self.timeline_end.isoformat() if self.timeline_end else None
            },
            'event_count': self.event_count,
            'recommended_actions': self.recommended_actions,
            'evidence': self.evidence
        }


class LeadGenerator:
    """Generates threat hunting leads from anomalies and patterns."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize lead generator.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        self.min_anomaly_score = self.config.get('min_anomaly_score', 0.85)
        self.clustering_enabled = self.config.get('clustering_enabled', True)
        self.cluster_time_window_minutes = self.config.get('cluster_time_window_minutes', 60)
        self.cluster_min_events = self.config.get('cluster_min_events', 3)

        self.lead_counter = 0

        logger.info("Lead generator initialized")

    def generate_lead(
        self,
        anomalies: List[Dict[str, Any]],
        context: Dict[str, Any] = None
    ) -> ThreatLead:
        """
        Generate threat hunting lead from anomalies.

        Args:
            anomalies: List of detected anomalies
            context: Additional context information

        Returns:
            ThreatLead object
        """
        if not anomalies:
            raise ValueError("No anomalies provided")

        # Generate unique lead ID
        self.lead_counter += 1
        timestamp = datetime.utcnow().strftime("%Y%m%d")
        lead_id = f"THL-{timestamp}-{self.lead_counter:06d}"

        # Determine severity and confidence
        max_score = max(a['anomaly_score'] for a in anomalies)
        severity = self._calculate_severity(max_score, len(anomalies))
        confidence = max_score

        # Generate title and description
        title, description = self._generate_title_description(anomalies, context)

        # Create lead
        lead = ThreatLead(lead_id, title, description, severity, confidence)

        # Add anomaly IDs
        lead.anomaly_ids = [a.get('index', a.get('id', 0)) for a in anomalies]

        # Extract entities
        lead.entities = self._extract_entities(anomalies, context)

        # Calculate timeline
        lead.timeline_start, lead.timeline_end = self._calculate_timeline(context)
        lead.event_count = len(anomalies)

        # Generate recommended actions
        lead.recommended_actions = self._generate_recommendations(anomalies, context)

        # Add evidence
        lead.evidence = self._gather_evidence(anomalies, context)

        logger.info(f"Generated {severity.value} severity lead: {lead_id}")

        return lead

    def _calculate_severity(self, max_score: float, anomaly_count: int) -> SeverityLevel:
        """
        Calculate threat severity.

        Args:
            max_score: Maximum anomaly score
            anomaly_count: Number of anomalies

        Returns:
            SeverityLevel
        """
        # Critical: Very high score or many anomalies
        if max_score >= 0.95 or anomaly_count >= 10:
            return SeverityLevel.CRITICAL

        # High: High score or multiple anomalies
        if max_score >= 0.90 or anomaly_count >= 5:
            return SeverityLevel.HIGH

        # Medium: Moderate score
        if max_score >= 0.85 or anomaly_count >= 3:
            return SeverityLevel.MEDIUM

        # Low: Lower scores
        return SeverityLevel.LOW

    def _generate_title_description(
        self,
        anomalies: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> tuple[str, str]:
        """Generate human-readable title and description."""
        # Determine anomaly type from context
        anomaly_type = context.get('anomaly_type', 'Unknown Behavioral Anomaly')

        # Get entity information
        entity_id = context.get('entity_id', 'unknown')
        entity_type = context.get('entity_type', 'entity')

        # Generate title
        title = f"Potential Threat - {anomaly_type} Detected for {entity_type} {entity_id}"

        # Generate description
        anomaly_count = len(anomalies)
        max_score = max(a['anomaly_score'] for a in anomalies)

        description = (
            f"{entity_type.capitalize()} {entity_id} exhibited {anomaly_type.lower()} "
            f"with {anomaly_count} anomalous event(s) detected "
            f"(confidence: {max_score:.2%})."
        )

        # Add specific details if available
        if 'details' in context:
            description += f" {context['details']}"

        return title, description

    def _extract_entities(
        self,
        anomalies: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """Extract involved entities from anomalies."""
        entities = {
            'users': set(),
            'hosts': set(),
            'ips': set(),
            'processes': set()
        }

        # Extract from context
        if 'entity_id' in context:
            entity_type = context.get('entity_type', 'user')
            if entity_type == 'user':
                entities['users'].add(context['entity_id'])
            elif entity_type == 'host':
                entities['hosts'].add(context['entity_id'])
            elif entity_type == 'ip':
                entities['ips'].add(context['entity_id'])

        # Extract from anomalies
        for anomaly in anomalies:
            if 'user_name' in anomaly:
                entities['users'].add(anomaly['user_name'])
            if 'host_name' in anomaly:
                entities['hosts'].add(anomaly['host_name'])
            if 'source_ip' in anomaly:
                entities['ips'].add(anomaly['source_ip'])
            if 'process_name' in anomaly:
                entities['processes'].add(anomaly['process_name'])

        # Convert sets to lists
        return {k: list(v) for k, v in entities.items() if v}

    def _calculate_timeline(self, context: Dict[str, Any]) -> tuple[Optional[datetime], Optional[datetime]]:
        """Calculate timeline from context."""
        timeline_start = context.get('timeline_start')
        timeline_end = context.get('timeline_end')

        if isinstance(timeline_start, str):
            timeline_start = datetime.fromisoformat(timeline_start)
        if isinstance(timeline_end, str):
            timeline_end = datetime.fromisoformat(timeline_end)

        return timeline_start, timeline_end

    def _generate_recommendations(
        self,
        anomalies: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[str]:
        """Generate investigation recommendations."""
        recommendations = []

        anomaly_type = context.get('anomaly_type', '')

        # Generic recommendations
        recommendations.append("Review detailed event logs for the affected entity")
        recommendations.append("Check for correlation with other security alerts")
        recommendations.append("Verify legitimacy of activity with entity owner")

        # Type-specific recommendations
        if 'login' in anomaly_type.lower() or 'auth' in anomaly_type.lower():
            recommendations.extend([
                "Review authentication logs for credential misuse",
                "Check for signs of compromised credentials",
                "Verify source IP addresses against known locations"
            ])
        elif 'network' in anomaly_type.lower() or 'connection' in anomaly_type.lower():
            recommendations.extend([
                "Analyze network traffic patterns",
                "Check destination IPs against threat intelligence",
                "Investigate for data exfiltration indicators"
            ])
        elif 'file' in anomaly_type.lower():
            recommendations.extend([
                "Inspect accessed files for sensitive content",
                "Check for malware staging or lateral movement",
                "Review file permissions and access controls"
            ])
        elif 'process' in anomaly_type.lower():
            recommendations.extend([
                "Analyze process command lines for malicious indicators",
                "Check process hashes against threat intelligence",
                "Investigate parent-child process relationships"
            ])

        return recommendations

    def _gather_evidence(
        self,
        anomalies: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Gather evidence for the lead."""
        evidence = {
            'anomaly_count': len(anomalies),
            'max_anomaly_score': max(a['anomaly_score'] for a in anomalies),
            'avg_anomaly_score': sum(a['anomaly_score'] for a in anomalies) / len(anomalies)
        }

        # Add feature importance if available
        if anomalies and 'feature_importance' in anomalies[0]:
            evidence['top_features'] = anomalies[0]['feature_importance']

        # Add context evidence
        if 'baseline_value' in context:
            evidence['baseline_value'] = context['baseline_value']
        if 'observed_value' in context:
            evidence['observed_value'] = context['observed_value']
        if 'deviation_sigma' in context:
            evidence['deviation_sigma'] = context['deviation_sigma']

        return evidence

    def cluster_anomalies(self, anomalies: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """
        Cluster anomalies by time and entity.

        Args:
            anomalies: List of anomalies

        Returns:
            List of anomaly clusters
        """
        if not self.clustering_enabled or not anomalies:
            return [anomalies]

        # Simple time-based clustering
        clusters = []
        current_cluster = []

        sorted_anomalies = sorted(anomalies, key=lambda x: x.get('timestamp', datetime.utcnow()))

        for anomaly in sorted_anomalies:
            if not current_cluster:
                current_cluster.append(anomaly)
            else:
                # Check if anomaly belongs to current cluster (time window)
                # Placeholder - in production would use proper timestamps
                current_cluster.append(anomaly)

        if current_cluster:
            clusters.append(current_cluster)

        return clusters
