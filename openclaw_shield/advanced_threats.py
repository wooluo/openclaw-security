"""
Advanced Threat Detection Module
Enhanced detection for sophisticated attack patterns
"""

import re
import ast
import hashlib
from typing import Dict, List, Any, Tuple
from datetime import datetime
from loguru import logger


class AdvancedThreatDetector:
    """
    Advanced threat detection for sophisticated attacks.
    Detects supply chain attacks, obfuscation, and modern attack patterns.
    """

    # Advanced attack patterns
    ADVANCED_PATTERNS = {
        # Supply chain attacks
        'dependency_confusion': {
            'patterns': [
                r'require\s*\(\s*[\'"]@[^\'"]+/[^\'"]+\s*[\'"]\s*\)',
                r'from\s+[\'"]@[^\'"]+/[^\'"]+\s+import',
                r'pip\s+install\s+@[^/\s]+',
                r'npm\s+install\s+@[^/\s]+',
            ],
            'severity': 'CRITICAL',
            'description': 'Dependency confusion attack - suspicious package source',
            'remediation': 'Verify package sources and only use official registries'
        },

        # Typosquatting
        'typosquatting': {
            'patterns': [
                r'require\s*\(\s*[\'"]react-nativ[e]\s*[\'"]\s*\)',  # react-native typo
                r'require\s*\(\s*[\'"]express[s]\s*[\'"]\s*\)',   # express typo
                r'require\s*\(\s*[\'"]lodas[h]\s*[\'"]\s*\)',    # lodash typo
                r'require\s*\(\s*[\'"]chakl[a]\s*[\'"]\s*\)',    # chalk typo
            ],
            'severity': 'HIGH',
            'description': 'Typosquatting detected - suspicious package name',
            'remediation': 'Check for typosquatting - verify package names carefully'
        },

        # Pre-install scripts
        'preinstall_script': {
            'patterns': [
                r'preinstall[s]?',
                r'postinstall[s]?',
                r'node-gyp\s+rebuild',
                r'\.gyp\s*$',
                r'binding\.gyp',
            ],
            'severity': 'HIGH',
            'description': 'Pre/post-install script - potential code execution',
            'remediation': 'Review install scripts for malicious code'
        },

        # Obfuscation techniques
        'obfuscation': {
            'patterns': [
                r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
                r'String\.fromCharCode',
                r'eval\s*\(\s*atob\s*\(',
                r'eval\s*\(\s*String\.fromCharCode',
                r'\\u[0-9a-fA-F]{4}',  # Unicode escapes
                r'atob\s*\([^)]*\+',
                r'parseInt\s*\([^)]*,\s*16\s*\)',
            ],
            'severity': 'HIGH',
            'description': 'Code obfuscation detected - potential hidden malicious code',
            'remediation': 'Review obfuscated code carefully - may hide malicious behavior'
        },

        # Cryptojacking
        'cryptojacking': {
            'patterns': [
                r'coinhive',
                r'crypto[-_]?miner',
                r'hashrate',
                r'monero',
                r'xmrig',
                r'stratum\s*\+tcp',
                r'pool\.[a-z]+',
            ],
            'severity': 'CRITICAL',
            'description': 'Cryptocurrency mining code detected',
            'remediation': 'Remove cryptocurrency mining code immediately'
        },

        # Botnet behavior
        'botnet': {
            'patterns': [
                r'command[_-]?and[_-]?control',
                r'c2[_-]?server',
                r'beacon',
                r'heartbeat',
                r'ddns[_-]?update',
                r'domain[_-]?generation',
                r'fast[_-]?flux',
            ],
            'severity': 'CRITICAL',
            'description': 'Botnet command and control behavior detected',
            'remediation': 'Remove C2 communication code immediately'
        },

        # DNS exfiltration
        'dns_exfiltration': {
            'patterns': [
                r'dns\s*\.\s*query',
                r'dns\s*\.\s*resolve',
                r'getaddrinfo',
                r'dig\s+\S+',
                r'nslookup',
                r'\.local\d',
            ],
            'severity': 'HIGH',
            'description': 'DNS-based data exfiltration detected',
            'remediation': 'Review DNS usage for potential data exfiltration'
        },

        # Steganography
        'steganography': {
            'patterns': [
                r'PIL\s*\.\s*Image',
                r'cv2\s*\.\s*imread',
                r'imread\s*\(',
                r'image\s*\.\s*load',
                r'stego',
                r'lsb\s*\(',
            ],
            'severity': 'MEDIUM',
            'description': 'Image processing code - potential steganography',
            'remediation': 'Review image processing for hidden data'
        },

        # Process injection
        'process_injection': {
            'patterns': [
                r'process\s*\.\s*spawn',
                r'subprocess\s*\.\s*Popen',
                r'child_process',
                r'exec[sS]?\s*\(',
                r'spawn[sS]?\s*\(',
                r'fork\s*\(',
            ],
            'severity': 'HIGH',
            'description': 'Process spawning/injection detected',
            'remediation': 'Review process creation for security'
        },

        # File system attacks
        'filesystem_attack': {
            'patterns': [
                r'\.\./',
                r'\.\.\\',
                r'/etc/passwd',
                r'/etc/shadow',
                r'\.ssh/',
                r'\.gnupg/',
                r'id_rsa',
                r'\.pem',
                r'\.key',
            ],
            'severity': 'HIGH',
            'description': 'File system attack pattern detected',
            'remediation': 'Review file access patterns for security'
        },

        # Memory dumping
        'memory_dump': {
            'patterns': [
                r'gcore\s*\(',
                r'proc\s*\/\s*self\s*\/\s*maps',
                r'/proc/self/mem',
                r'vmcore',
                r'memory\s*\.\s*dump',
                r'sysrq\s*-',
            ],
            'severity': 'HIGH',
            'description': 'Memory dumping detected - potential credential theft',
            'remediation': 'Review memory access for security'
        },

        # Container escape
        'container_escape': {
            'patterns': [
                r'/var/run/docker',
                r'docker\s*\.\s*sock',
                r'containerd',
                r'runc',
                r'cgroups',
                r'namespace',
                r'cap_sys_admin',
            ],
            'severity': 'CRITICAL',
            'description': 'Container escape attempt detected',
            'remediation': 'Review container-related code for security'
        },

        # Persistence mechanisms
        'persistence': {
            'patterns': [
                r'cron\s*\.\s*tab',
                r'systemctl\s+enable',
                r'launchctl\s+load',
                r'schtasks\s*/\s*create',
                r'init\.d\s*/',
                r'systemd',
                r'/etc/cron',
                r'~/\.local/share/systemd',
            ],
            'severity': 'HIGH',
            'description': 'Persistence mechanism detected - potential backdoor',
            'remediation': 'Review persistence mechanisms for legitimacy'
        },

        # Anti-analysis
        'anti_analysis': {
            'patterns': [
                r'IsDebuggerPresent',
                r'CheckRemoteDebuggerPresent',
                r'IsProcessFrozen',
                r'anti_debug',
                r'debugger',
                r'ptrace',
                r'process\s*\.\s*Tracer',
            ],
            'severity': 'MEDIUM',
            'description': 'Anti-debugging/anti-analysis code detected',
            'remediation': 'Review anti-analysis code - may hide malicious behavior'
        },

        # Privilege escalation
        'privilege_escalation': {
            'patterns': [
                r'setuid\s*\(',
                r'setgid\s*\(',
                r'seteuid\s*\(',
                r'setegid\s*\(',
                r'chmod\s+[ug]o]\s*\+',
                r'sudo\s+',
                r'doas\s*\(',
                r'cap_set',
            ],
            'severity': 'CRITICAL',
            'description': 'Privilege escalation attempt detected',
            'remediation': 'Review privilege escalation code immediately'
        },

        # Network reconnaissance
        'network_recon': {
            'patterns': [
                r'nmap\s+',
                r'masscan',
                r'netcat',
                r'nc\s+-',
                r'tcpdump',
                r'wireshark',
                r'tshark',
                r'arp\s+-a',
            ],
            'severity': 'MEDIUM',
            'description': 'Network reconnaissance tool detected',
            'remediation': 'Review network scanning code for legitimacy'
        },

        # Lateral movement
        'lateral_movement': {
            'patterns': [
                r'smbclient',
                r'winexe',
                r'psexec',
                r'wmi',
                r'rpc\s*\.\s*client',
                r'dcom',
                r'powershell',
                r'remote\s+exec',
            ],
            'severity': 'HIGH',
            'description': 'Lateral movement tool detected',
            'remediation': 'Review remote execution code for legitimacy'
        },

        # Data encoding
        'data_encoding': {
            'patterns': [
                r'base64\s*\.\s*b64encode',
                r'base64\s*\.\s*b64decode',
                r'binascii\s*\.\s*hexlify',
                r'binascii\s*\.\s*unhexlify',
                r'codecs\s*\.\s*encode',
                r'codecs\s*\.\s*decode',
                r'json\s*\.\s*dumps',
            ],
            'severity': 'LOW',
            'description': 'Data encoding detected - review for legitimate use',
            'remediation': 'Verify data encoding is used appropriately'
        },

        # Timing attacks
        'timing_attack': {
            'patterns': [
                r'time\s*\.\s*sleep',
                r'setTimeout',
                r'performance\s*\.\s*now',
                r'Date\s*\.\s*now',
                r'benchmark',
                r'timing\s*attack',
            ],
            'severity': 'MEDIUM',
            'description': 'Timing-related code detected - potential side-channel',
            'remediation': 'Review timing code for security implications'
        },
    }

    def __init__(self, config):
        """Initialize the advanced threat detector."""
        self.config = config
        self._threats = []
        self._compiled_patterns = self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance."""
        self._compiled = {}
        for category, data in self.ADVANCED_PATTERNS.items():
            patterns = []
            for pattern in data['patterns']:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    patterns.append((compiled, pattern))
                except re.error as e:
                    logger.warning(f"Failed to compile pattern: {pattern} - {e}")
            if patterns:
                self._compiled[category] = patterns

        logger.info(f"Compiled {len(self._compiled)} advanced threat patterns")

    def analyze(self, file_path: str, content: str, static_results: Dict) -> List[Dict]:
        """
        Analyze file for advanced threats.

        Args:
            file_path: Path to file
            content: File content
            static_results: Results from static analysis

        Returns:
            List of detected advanced threats
        """
        threats = []

        # Check all advanced patterns
        for category, patterns in self._compiled.items():
            category_info = self.ADVANCED_PATTERNS[category]
            for compiled_pattern, original_pattern in patterns:
                matches = compiled_pattern.finditer(content)
 if matches:
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        threat = {
                            'type': category,
                            'severity': category_info['severity'],
                            'description': category_info['description'],
                            'remediation': category_info['remediation'],
                            'line': line_num,
                            'match': match.group(0)[:100],
                            'confidence': self._calculate_confidence(category, match.group(0)),
                            'file': file_path,
                            'timestamp': datetime.now().isoformat()
                        }
                        threats.append(threat)
                        logger.debug(f"Detected {category} threat in {file_path}:{line_num}")

        # Additional behavioral analysis
        behavioral_threats = self._behavioral_analysis(file_path, content, static_results)
        threats.extend(behavioral_threats)

        return threats

    def _calculate_confidence(self, category: str, match: str) -> float:
        """Calculate confidence score for a threat."""
        base_confidence = 0.5

        # Higher confidence for critical patterns
        critical_categories = [
            'dependency_confusion', 'cryptojacking', 'botnet',
            'container_escape', 'privilege_escalation'
        ]
        if category in critical_categories:
            base_confidence += 0.3

        # Adjust based on match characteristics
        if len(match) > 50:
            base_confidence += 0.1
        if len(match) > 100:
            base_confidence += 0.15

        # Check for multiple matches (higher confidence)
        return min(1.0, base_confidence)

    def _behavioral_analysis(self, file_path: str, content: str, static_results: Dict) -> List[Dict]:
        """
        Perform behavioral analysis for sophisticated attacks.

        Args:
            file_path: Path to file
            content: File content
            static_results: Static analysis results
        Returns:
            List of detected threats
        """
        threats = []

        # Check for encoded strings that might indicate hidden payloads
        encoded_threats = self._detect_encoded_payloads(content)
        threats.extend(encoded_threats)

        # Check for suspicious string patterns
        string_threats = self._detect_suspicious_strings(content)
        threats.extend(string_threats)

        # Check for mathematical patterns (crypto operations)
        crypto_threats = self._detect_crypto_operations(content)
        threats.extend(crypto_threats)

        return threats

    def _detect_encoded_payloads(self, content: str) -> List[Dict]:
        """Detect potentially encoded/hidden payloads."""
        threats = []

        # Look for long base64 strings that might be payloads
        base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
        matches = re.finditer(base64_pattern, content)
        for match in matches:
            encoded_str = match.group(0)
            # Try to decode and check for suspicious patterns
            try:
                import base64
                # Remove padding
                clean_str = encoded_str.rstrip('=')
                # Add padding if needed
                padding = 4 - (len(clean_str) % 4)
                if padding:
                    clean_str += '=' * padding

                decoded = base64.b64decode(clean_str).decode('utf-8', errors='ignore')

                # Check decoded content for suspicious patterns
                suspicious_decoded = [
                    'eval', 'exec', 'import os', 'subprocess',
                    'socket', 'connect', 'http://', 'curl',
                    'wget', 'rm -rf', '/bin/sh'
                ]

                for pattern in suspicious_decoded:
                    if pattern in decoded.lower():
                        threats.append({
                            'type': 'hidden_payload',
                            'severity': 'CRITICAL',
                            'description': 'Hidden payload detected in base64 string',
                            'remediation': 'Remove hidden payload immediately',
                            'confidence': 0.95,
                            'match': encoded_str[:50] + '...'
                        })
                        break
            except Exception:
                pass

        return threats

    def _detect_suspicious_strings(self, content: str) -> List[Dict]:
        """Detect suspicious string patterns."""
        threats = []

        # Check for suspicious variable names
        suspicious_vars = [
            r'\b(password|passwd|pwd|secret|key|token|auth|cred)[wd]*)\b',
            r'\b(shell|backdoor|exploit|payload|malware|virus)\b',
            r'\b(admin|root|superuser|sudo)\b',
            r'\b(attack|hack|crack|pirate)\b',
        ]

        lines = content.split('\n')
        for i, range(len(lines)):
            line = lines[i]
            for pattern in suspicious_vars:
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract variable name
                    match = re.search(r'[a-zA-Z_][a-zA-Z0-9_]*', line)
                    if match:
                        var_name = match.group(0)
                        # Check if it's being assigned something suspicious
                        if '=' in line and not line.strip().startswith('#'):
                            threats.append({
                                'type': 'suspicious_variable',
                                'severity': 'MEDIUM',
                                'description': f'Suspicious variable name detected: {var_name}',
                                'remediation': 'Review variable usage for security',
                                'confidence': 0.6,
                                'line': i + 1,
                                'match': line.strip()[:100]
                            })
                            break

        return threats

    def _detect_crypto_operations(self, content: str) -> List[Dict]:
        """Detect cryptographic operations that might indicate malicious intent."""
        threats = []

        # Look for custom crypto implementations (potential backdoors)
        crypto_patterns = [
            (r'XOR\s*\(', 'XOR operation - potential obfuscation'),
            (r'rot\d+', 'ROT operation - potential obfuscation'),
            (r'from_bytes.*xor', 'XOR with bytes - potential encoding'),
            (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', 'Multiple hex values - potential shellcode'),
        ]

        for pattern, description in crypto_patterns:
            if re.search(pattern, content):
                threats.append({
                    'type': 'suspicious_crypto',
                    'severity': 'MEDIUM',
                    'description': description,
                    'remediation': 'Review cryptographic operations for security',
                    'confidence': 0.65,
                })

        return threats

    def scan_dependency_file(self, file_path: str, content: str) -> List[Dict]:
        """
        Scan package.json, requirements.txt or other dependency files.

        Args:
            file_path: Path to file
            content: File content
        Returns:
            List of detected threats
        """
        threats = []

        import json

        try:
            if 'package.json' in file_path:
                pkg = json.loads(content)

                # Check for suspicious dependencies
                suspicious_packages = [
                    'event-stream', 'node-serialize', 'serialize-to-cloudevents',
                    'electron-shell', 'chrome-remote-interface', 'puppeteer-core',
                ]

                for dep in pkg.get('dependencies', {}).keys():
                    if any(sus for dep.lower() for sus in suspicious_packages):
                        threats.append({
                            'type': 'suspicious_dependency',
                            'severity': 'HIGH',
                            'description': f'Suspicious package detected: {dep}',
                            'remediation': 'Review dependency for security risks',
                            'confidence': 0.8,
                            'package': dep
                        })

                    # Check for git URLs instead of registries
                    dep_value = pkg['dependencies'][dep]
                    if isinstance(dep_value, str):
                        if dep_value.startswith(('git://', 'git+ssh://', 'github:')):
                            threats.append({
                                'type': 'git_dependency',
                                'severity': 'MEDIUM',
                                'description': f'Git URL dependency detected: {dep}',
                                'remediation': 'Verify git dependency source',
                                'confidence': 0.6,
                                'package': dep,
                                'url': dep_value
                            })

                # Check for pre/post-install scripts
                for script_type in ['preinstall', 'postinstall', 'prepublish', 'postpublish']:
                    scripts = pkg.get('scripts', {}).get(script_type, [])
                    if scripts:
                        threats.append({
                            'type': 'install_script',
                            'severity': 'HIGH',
                            'description': f'{script_type} script detected',
                            'remediation': 'Review install script for malicious code',
                            'confidence': 0.75,
                            'scripts': scripts
                        })

        except json.JSONDecodeError:
            pass

        return threats

    def get_threat_statistics(self) -> Dict:
        """Get statistics about detected threats."""
        return {
            'total_patterns': len(self.ADVANCED_PATTERNS),
            'categories': list(self.ADVANCED_PATTERNS.keys()),
            'compiled_patterns': len(self._compiled),
        }
