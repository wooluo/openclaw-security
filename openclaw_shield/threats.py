"""
Threat Detection Module
Advanced threat detection and analysis engine
"""

import re
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from loguru import logger


class ThreatDetector:
    """
    Advanced threat detection engine for OpenClaw.
    Analyzes code patterns, behaviors, and configurations to detect threats.
    """

    # Threat categories
    CATEGORIES = {
        'code_execution': {
            'severity': 'CRITICAL',
            'description': 'Code execution vulnerability',
            'remediation': 'Remove dynamic code execution functions'
        },
        'reverse_shell': {
            'severity': 'CRITICAL',
            'description': 'Reverse shell/backdoor detected',
            'remediation': 'Remove network connection code immediately'
        },
        'data_exfiltration': {
            'severity': 'HIGH',
            'description': 'Potential data exfiltration',
            'remediation': 'Review and restrict data transmission'
        },
        'credential_theft': {
            'severity': 'CRITICAL',
            'description': 'Credential/secret theft attempt',
            'remediation': 'Remove credential collection code'
        },
        'privilege_escalation': {
            'severity': 'HIGH',
            'description': 'Privilege escalation attempt',
            'remediation': 'Remove privilege escalation code'
        },
        'malicious_import': {
            'severity': 'HIGH',
            'description': 'Suspicious module import',
            'remediation': 'Review and verify module usage'
        },
        'unsafe_deserialization': {
            'severity': 'HIGH',
            'description': 'Unsafe deserialization',
            'remediation': 'Use safe deserialization methods'
        },
        'ssrf': {
            'severity': 'HIGH',
            'description': 'Server-Side Request Forgery risk',
            'remediation': 'Validate and restrict URL inputs'
        },
        'ssrf_attack': {
            'severity': 'HIGH',
            'description': 'Server-Side Request Forgery (CVE-2026-26322)',
            'remediation': 'Validate and whitelist all target URLs'
        },
        'path_traversal': {
            'severity': 'MEDIUM',
            'description': 'Path traversal vulnerability',
            'remediation': 'Validate and sanitize file paths'
        },
        'obfuscation': {
            'severity': 'MEDIUM',
            'description': 'Code obfuscation detected',
            'remediation': 'Remove obfuscated code'
        },
        # CVE-based categories
        'websocket_hijacking': {
            'severity': 'CRITICAL',
            'description': 'WebSocket hijacking (CVE-2026-25253)',
            'remediation': 'Validate gatewayUrl from whitelist only'
        },
        'token_theft': {
            'severity': 'CRITICAL',
            'description': 'Authentication token theft (CVE-2026-25253)',
            'remediation': 'Use Authorization header instead of URL parameters'
        },
        'command_injection': {
            'severity': 'CRITICAL',
            'description': 'Command injection (CVE-2026-24763)',
            'remediation': 'Never use user input in shell commands'
        },
        'typosquatting': {
            'severity': 'HIGH',
            'description': 'Typosquatting package attack',
            'remediation': 'Verify exact package name from official source'
        },
        'supply_chain_attack': {
            'severity': 'CRITICAL',
            'description': 'Supply chain attack (ClawHavoc)',
            'remediation': 'Only install from verified publishers'
        },
        'trojan_skill': {
            'severity': 'CRITICAL',
            'description': 'Trojanized skill (Clawdrain)',
            'remediation': 'Remove skill accessing Python internals'
        },
        'local_file_inclusion': {
            'severity': 'HIGH',
            'description': 'Local file inclusion attempt',
            'remediation': 'Block access to sensitive system files'
        },
        'env_injection': {
            'severity': 'HIGH',
            'description': 'Environment variable injection',
            'remediation': 'Never allow user input to modify environment'
        },
        'dns_exfiltration': {
            'severity': 'HIGH',
            'description': 'DNS data exfiltration',
            'remediation': 'Monitor DNS queries for suspicious patterns'
        },
        'cryptomining': {
            'severity': 'CRITICAL',
            'description': 'Cryptocurrency mining',
            'remediation': 'Remove cryptomining code immediately'
        },
        'botnet_c2': {
            'severity': 'CRITICAL',
            'description': 'Botnet command and control',
            'remediation': 'Skill may be part of a botnet'
        },
        'container_escape': {
            'severity': 'CRITICAL',
            'description': 'Container escape attempt',
            'remediation': 'Block access to container runtime sockets'
        },
        'prompt_injection': {
            'severity': 'HIGH',
            'description': 'LLM prompt injection',
            'remediation': 'Sanitize and validate all user prompts'
        },
        'api_key_harvesting': {
            'severity': 'CRITICAL',
            'description': 'API key harvesting',
            'remediation': 'Block unauthorized API key access'
        }
    }

    def __init__(self, config):
        """Initialize threat detector."""
        self.config = config
        self.custom_rules = []
        self._load_custom_rules()

    def _load_custom_rules(self):
        """Load custom threat detection rules."""
        rules_file = Path(self.config.get('threat_detection.rules_file',
                                         './config/threat_rules.yaml'))

        if rules_file.exists():
            try:
                with open(rules_file, 'r') as f:
                    rules_data = yaml.safe_load(f)
                    self.custom_rules = rules_data.get('rules', [])
                logger.info(f"Loaded {len(self.custom_rules)} custom threat rules")
            except Exception as e:
                logger.warning(f"Failed to load custom rules: {e}")

    def analyze(self, file_path: str, static_results: Dict) -> List[Dict]:
        """
        Analyze a file for threats based on static analysis results.

        Args:
            file_path: Path to the analyzed file
            static_results: Results from static analysis

        Returns:
            List of detected threats
        """
        threats = []

        # Analyze based on static analysis results
        for threat in static_results.get('threats', []):
            enriched = self._enrich_threat(threat)
            threats.append(enriched)

        # Additional behavioral analysis
        behavioral_threats = self._behavioral_analysis(file_path, static_results)
        threats.extend(behavioral_threats)

        # Apply custom rules
        custom_threats = self._apply_custom_rules(file_path, static_results)
        threats.extend(custom_threats)

        # Deduplicate and prioritize
        threats = self._prioritize_threats(threats)

        return threats

    def _enrich_threat(self, threat: Dict) -> Dict:
        """Enrich threat information with additional context."""
        threat_type = threat.get('type', 'unknown')

        if threat_type in self.CATEGORIES:
            category_info = self.CATEGORIES[threat_type]
            threat['category'] = threat_type
            threat['description'] = category_info['description']
            threat['remediation'] = category_info['remediation']

            # Ensure severity is set
            if 'severity' not in threat:
                threat['severity'] = category_info['severity']

        # Add timestamp
        threat['detected_at'] = datetime.now().isoformat()

        # Add confidence score
        threat['confidence'] = self._calculate_confidence(threat)

        return threat

    def _calculate_confidence(self, threat: Dict) -> float:
        """Calculate confidence score for a threat detection."""
        base_confidence = 0.5

        # Increase confidence based on indicators
        if threat.get('line'):
            base_confidence += 0.1

        if threat.get('match'):
            base_confidence += 0.15

        if threat.get('severity') == 'CRITICAL':
            base_confidence += 0.2

        # Category-specific confidence adjustments
        category = threat.get('type', '')
        if category in ['reverse_shell', 'code_execution', 'credential_theft']:
            base_confidence += 0.15

        return min(1.0, base_confidence)

    def _behavioral_analysis(self, file_path: str, static_results: Dict) -> List[Dict]:
        """Perform behavioral analysis to detect suspicious patterns."""
        threats = []

        imports = set(static_results.get('imports', []))
        functions = set(static_results.get('functions', []))

        # Check for combination of suspicious imports
        suspicious_combinations = [
            ({'socket', 'subprocess', 'os'}, 'potential_backdoor'),
            ({'pickle', 'socket'}, 'remote_code_execution'),
            ({'requests', 'os', 'subprocess'}, 'data_exfiltration'),
            ({'base64', 'exec', 'eval'}, 'obfuscated_malware'),
        ]

        for combo, threat_type in suspicious_combinations:
            if combo.issubset(imports):
                threats.append({
                    'type': threat_type,
                    'severity': 'HIGH',
                    'message': f"Suspicious import combination: {combo}",
                    'category': threat_type,
                    'confidence': 0.8
                })

        # Check for dangerous function chains
        if 'socket' in imports and 'connect' in functions:
            threats.append({
                'type': 'reverse_shell',
                'severity': 'CRITICAL',
                'message': "Socket connection detected - potential reverse shell",
                'category': 'reverse_shell',
                'confidence': 0.85
            })

        # Check for data collection patterns
        if 'os' in imports and any(f in functions for f in ['environ', 'getenv']):
            threats.append({
                'type': 'credential_theft',
                'severity': 'HIGH',
                'message': "Environment variable access detected",
                'category': 'credential_theft',
                'confidence': 0.7
            })

        return threats

    def _apply_custom_rules(self, file_path: str, static_results: Dict) -> List[Dict]:
        """Apply custom threat detection rules."""
        threats = []

        for rule in self.custom_rules:
            try:
                if self._matches_rule(rule, static_results):
                    threat = {
                        'type': rule.get('type', 'custom'),
                        'severity': rule.get('severity', 'MEDIUM'),
                        'message': rule.get('message', 'Custom rule matched'),
                        'rule_id': rule.get('id'),
                        'confidence': 0.9,
                        'remediation': rule.get('remediation', 'Review this threat')
                    }

                    # Add CVE reference if present
                    if 'cve' in rule:
                        threat['cve'] = rule['cve']

                    # Add reference links if present
                    if 'references' in rule:
                        threat['references'] = rule['references']

                    threats.append(threat)
            except Exception as e:
                logger.error(f"Error applying rule {rule.get('id')}: {e}")

        return threats

    def _matches_rule(self, rule: Dict, static_results: Dict) -> bool:
        """Check if static results match a custom rule."""
        conditions = rule.get('conditions', [])

        for condition in conditions:
            condition_type = condition.get('type')

            if condition_type == 'import':
                required_import = condition.get('value')
                if required_import not in static_results.get('imports', []):
                    return False

            elif condition_type == 'function':
                required_function = condition.get('value')
                if required_function not in static_results.get('functions', []):
                    return False

            elif condition_type == 'pattern':
                pattern = condition.get('value')
                # Check in threats for pattern matches
                matched = False
                for threat in static_results.get('threats', []):
                    if threat.get('type') == pattern:
                        matched = True
                        break
                # Also check in strings if available
                if not matched:
                    strings = static_results.get('strings', [])
                    try:
                        import re
                        for s in strings:
                            if re.search(pattern, s, re.IGNORECASE):
                                matched = True
                                break
                    except re.error:
                        pass
                if not matched:
                    return False

            elif condition_type == 'string':
                # Check for specific string literals in code
                required_string = condition.get('value')
                strings = static_results.get('strings', [])
                if required_string not in strings:
                    return False

        return True

    def _prioritize_threats(self, threats: List[Dict]) -> List[Dict]:
        """Prioritize and deduplicate threats."""
        # Remove exact duplicates
        seen = set()
        unique_threats = []

        for threat in threats:
            # Create a hash for deduplication
            threat_hash = (
                threat.get('type'),
                threat.get('severity'),
                threat.get('message', '')[:50]
            )

            if threat_hash not in seen:
                seen.add(threat_hash)
                unique_threats.append(threat)

        # Sort by severity and confidence
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

        def sort_key(threat):
            return (
                severity_order.get(threat.get('severity', 'LOW'), 3),
                -threat.get('confidence', 0.5)
            )

        return sorted(unique_threats, key=sort_key)

    def add_custom_rule(self, rule: Dict):
        """Add a custom threat detection rule."""
        required_fields = ['id', 'type', 'severity', 'conditions']

        for field in required_fields:
            if field not in rule:
                raise ValueError(f"Missing required field: {field}")

        self.custom_rules.append(rule)
        logger.info(f"Added custom rule: {rule['id']}")

    def get_threat_summary(self, threats: List[Dict]) -> Dict:
        """Generate a summary of detected threats."""
        summary = {
            'total': len(threats),
            'by_severity': {},
            'by_category': {},
            'high_confidence': 0
        }

        for threat in threats:
            # Count by severity
            severity = threat.get('severity', 'UNKNOWN')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1

            # Count by category
            category = threat.get('type', 'unknown')
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1

            # Count high confidence
            if threat.get('confidence', 0) >= 0.8:
                summary['high_confidence'] += 1

        return summary

    def calculate_risk_score(self, threats: List[Dict]) -> int:
        """Calculate overall risk score from threats."""
        if not threats:
            return 0

        severity_weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3,
            'INFO': 1
        }

        total_score = 0

        for threat in threats:
            severity = threat.get('severity', 'LOW')
            confidence = threat.get('confidence', 0.5)

            # Weight by severity and confidence
            base_score = severity_weights.get(severity, 3)
            weighted_score = base_score * confidence

            total_score += weighted_score

        # Normalize to 0-100 scale
        return min(100, int(total_score))
