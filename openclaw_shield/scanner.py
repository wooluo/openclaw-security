"""
Skill Scanner Module
Enhanced with advanced threat detection capabilities
Performs static analysis and security scanning of OpenClaw skills
"""

import ast
import re
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from loguru import logger

from .advanced_threats import AdvancedThreatDetector
from .updater import AutoUpdater
from .config import Config


class SkillScanner:
    """
    Scans OpenClaw skills for security threats using static analysis.
    Includes advanced threat detection for supply chain attacks, obfuscation, and etc.
    """

    # Dangerous Python functions that should be flagged
    DANGEROUS_FUNCTIONS = {
        # Code execution
        'eval': 'CRITICAL',
        'exec': 'CRITICAL',
        'compile': 'HIGH',
        'execfile': 'CRITICAL',

        # System access
        'system': 'HIGH',
        'popen': 'HIGH',
        'spawn': 'HIGH',
        'call': 'MEDIUM',
        'run': 'MEDIUM',

        # File operations
        'remove': 'MEDIUM',
        'unlink': 'MEDIUM',
        'rmdir': 'MEDIUM',
        'rename': 'MEDIUM',

        # Network operations
        'socket': 'HIGH',
        'connect': 'HIGH',
        'send': 'MEDIUM',
        'recv': 'MEDIUM',

        # Process control
        'fork': 'HIGH',
        'kill': 'CRITICAL',
        'terminate': 'HIGH',
    }

    # Dangerous modules that require attention
    DANGEROUS_MODULES = {
        'subprocess': 'HIGH',
        'os': 'MEDIUM',
        'sys': 'LOW',
        'socket': 'HIGH',
        'pickle': 'HIGH',
        'marshal': 'HIGH',
        'ctypes': 'HIGH',
        'multiprocessing': 'MEDIUM',
        'threading': 'LOW',
    }

    # Patterns that indicate malicious behavior
    MALICIOUS_PATTERNS = [
        # Reverse shell patterns
        (r'socket\.socket\s*\(\s*socket\.AF_INET\s*,\s*socket\.SOCK_STREAM\s*\)', 'CRITICAL', 'reverse_shell'),
        (r'\.connect\s*\(\s*[\(\'\"]', 'HIGH', 'suspicious_connection'),
        (r'subprocess\.(Popen|call|run)\s*\([^)]*(bash|sh|cmd)', 'HIGH', 'shell_execution'),

        # Data exfiltration patterns
        (r'requests\.(post|get|put)\s*\([^)]*http', 'MEDIUM', 'external_request'),
        (r'urllib\.request\.urlopen', 'MEDIUM', 'url_request'),
        (r'\.send\s*\(', 'MEDIUM', 'data_transmission'),

        # Credential theft patterns
        (r'os\.environ', 'HIGH', 'environment_access'),
        (r'getenv\s*\(', 'MEDIUM', 'env_variable_access'),
        (r'\.read\s*\(\s*\)\s*.*password|token|key', 'CRITICAL', 'credential_theft'),

        # Code injection patterns
        (r'eval\s*\(\s*[^)]*input', 'CRITICAL', 'code_injection'),
        (r'exec\s*\(\s*[^)]*input', 'CRITICAL', 'code_injection'),

        # File system attacks
        (r'shutil\.rmtree', 'HIGH', 'directory_deletion'),
        (r'os\.system\s*\(\s*[^)]*rm\s+-rf', 'CRITICAL', 'destructive_command'),

        # Obfuscation patterns
        (r'base64\.b64decode', 'MEDIUM', 'base64_decoding'),
        (r'__import__\s*\(', 'HIGH', 'dynamic_import'),
        (r'getattr\s*\(\s*[^,]+,\s*[^)]*\+', 'MEDIUM', 'dynamic_attribute_access'),

        # Hidden payloads
        (r'\\x[0-9a-fA-F]{2}', 'HIGH', 'hex_encoding'),
        (r'\\u[0-9a-fA-F]{4}', 'HIGH', 'unicode_escape'),
    ]

    def __init__(self, config: Config):
        """Initialize the scanner with configuration."""
        self.config = config
        self.advanced_detector = AdvancedThreatDetector(config)
        self.updater = AutoUpdater(config)
        self.results = {}

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file for security threats.

        Args:
            file_path: Path to the file to scan

        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Scanning file: {file_path}")

        results = {
            'file': file_path,
            'threats': [],
            'warnings': [],
            'info': [],
            'imports': [],
            'functions': [],
            'passed': True,
            'score': 100
        }

        path = Path(file_path)
        if not path.exists():
            results['error'] = f"File not found: {file_path}"
            return results

        # Read file content
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            results['error'] = f"Failed to read file: {e}"
            return results

        # Perform different types of analysis
        if file_path.endswith('.py'):
            self._analyze_python(content, results)
        elif file_path.endswith('.js'):
            self._analyze_javascript(content, results)

        # Pattern matching
        self._pattern_analysis(content, results)

        # Advanced threat detection
        self._advanced_analysis(content, file_path, results)

        # Check for dependency file attacks
        if 'package.json' in file_path or 'requirements.txt' in file_path:
            self._scan_dependency_file(file_path, content, results)

        # Calculate final score
        results['score'] = self._calculate_score(results)
        results['passed'] = results['score'] >= 60

        return results

    def _analyze_python(self, content: str, results: Dict):
        """Analyze Python code using AST."""
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            results['warnings'].append({
                'type': 'syntax_error',
                'message': f"Syntax error: {e}",
                'severity': 'MEDIUM'
            })
            return

        # Analyze imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split('.')[0]
                    results['imports'].append(module)
                    self._check_dangerous_import(module, results)

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module = node.module.split('.')[0]
                    results['imports'].append(module)
                    self._check_dangerous_import(module, results)

            # Check for dangerous function calls
            elif isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name:
                    results['functions'].append(func_name)
                    self._check_dangerous_function(func_name, node, results)

            # Check for environment variable access
            elif isinstance(node, ast.Attribute):
                if node.attr in ['environ', 'getenv']:
                    self._add_threat(results, {
                        'type': 'environment_access',
                        'severity': 'HIGH',
                        'message': f"Access to environment variables detected: {node.attr}",
                        'line': getattr(node, 'lineno', 0)
                    })

    def _analyze_javascript(self, content: str, results: Dict):
        """Analyze JavaScript code for threats."""
        # Check for eval usage
        if re.search(r'\beval\s*\(', content):
            self._add_threat(results, {
                'type': 'eval_usage',
                'severity': 'CRITICAL',
                'message': "Use of eval() detected - potential code injection risk",
                'line': self._find_line_number(content, 'eval(')
            })

        # Check for Function constructor
        if re.search(r'new\s+Function\s*\(', content):
            self._add_threat(results, {
                'type': 'function_constructor',
                'severity': 'HIGH',
                'message': "Use of Function constructor detected",
                'line': self._find_line_number(content, 'new Function')
            })

        # Check for child_process
        if re.search(r'require\s*\(\s*[\'"]child_process[\'"]\s*\)', content):
            self._add_threat(results, {
                'type': 'child_process',
                'severity': 'HIGH',
                'message': "Access to child_process module",
                'line': self._find_line_number(content, 'child_process')
            })

        # Check for fetch/XMLHttpRequest to external URLs
        if re.search(r'(fetch|XMLHttpRequest)\s*\([^)]*https?://', content):
            self._add_threat(results, {
                'type': 'external_request',
                'severity': 'MEDIUM',
                'message': "External HTTP request detected",
                'line': self._find_line_number(content, 'fetch')
            })

        # Check for prototype pollution
        if re.search(r'__proto__|prototype\s*\[', content):
            self._add_threat(results, {
                'type': 'prototype_pollution',
                'severity': 'HIGH',
                'message': "Prototype pollution pattern detected",
                'line': self._find_line_number(content, '__proto__')
            })

        # Check for DOM-based XSS
        if re.search(r'innerHTML|outerHTML|document\.write', content):
            self._add_threat(results, {
                'type': 'dom_xss',
                'severity': 'HIGH',
                'message': "DOM-based XSS risk detected",
                'line': self._find_line_number(content, 'innerHTML')
            })

    def _pattern_analysis(self, content: str, results: Dict):
        """Perform pattern-based analysis."""
        for pattern, severity, threat_type in self.MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self._add_threat(results, {
                    'type': threat_type,
                    'severity': severity,
                    'message': f"Suspicious pattern detected: {threat_type}",
                    'line': line_num,
                    'match': match.group(0)[:100]
                })

    def _advanced_analysis(self, content: str, file_path: str, results: Dict):
        """Perform advanced threat analysis."""
        # Run advanced threat detection using the analyze method
        static_results = {}
        advanced_threats = self.advanced_detector.analyze(file_path, content, static_results)
        results['threats'].extend(advanced_threats)

    def _scan_dependency_file(self, file_path: str, content: str, results: Dict):
        """Scan dependency files for supply chain attacks."""
        dep_threats = self.advanced_detector.scan_dependency_file(file_path, content)
        results['threats'].extend(dep_threats)

    def _check_dangerous_import(self, module: str, results: Dict):
        """Check if an import is dangerous."""
        if module in self.DANGEROUS_MODULES:
            severity = self.DANGEROUS_MODULES[module]
            if severity in ['HIGH', 'CRITICAL']:
                self._add_threat(results, {
                    'type': 'dangerous_import',
                    'severity': severity,
                    'message': f"Dangerous module imported: {module}",
                    'detail': module
                })
            else:
                results['warnings'].append({
                    'type': 'suspicious_import',
                    'message': f"Suspicious module imported: {module}",
                    'severity': severity
                })

    def _check_dangerous_function(self, func_name: str, node, results: Dict):
        """Check if a function call is dangerous."""
        base_name = func_name.split('.')[-1]

        if base_name in self.DANGEROUS_FUNCTIONS:
            severity = self.DANGEROUS_FUNCTIONS[base_name]

            # Special handling for eval and exec
            if base_name in ['eval', 'exec']:
                self._add_threat(results, {
                    'type': 'code_execution',
                    'severity': 'CRITICAL',
                    'message': f"Dangerous function call: {func_name}()",
                    'line': getattr(node, 'lineno', 0)
                })
            elif severity in ['HIGH', 'CRITICAL']:
                self._add_threat(results, {
                    'type': 'dangerous_function',
                    'severity': severity,
                    'message': f"Potentially dangerous function: {func_name}()",
                    'line': getattr(node, 'lineno', 0)
                })

    def _get_func_name(self, node) -> Optional[str]:
        """Extract function name from AST node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{self._get_attribute_chain(node.func)}.{node.func.attr}"
        return None

    def _get_attribute_chain(self, node) -> str:
        """Get full attribute chain (e.g., 'os.system')."""
        if isinstance(node.value, ast.Name):
            return node.value.id
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_attribute_chain(node.value)}.{node.value.attr}"
        return ""

    def _find_line_number(self, content: str, pattern: str) -> int:
        """Find line number of a pattern in content."""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 0

    def _add_threat(self, results: Dict, threat: Dict):
        """Add a threat to results."""
        results['threats'].append(threat)
        results['passed'] = False

    def _calculate_score(self, results: Dict) -> int:
        """Calculate security score based on findings."""
        score = 100

        severity_penalties = {
            'CRITICAL': -30,
            'HIGH': -20,
            'MEDIUM': -10,
            'LOW': -5,
            'INFO': -1
        }

        for threat in results.get('threats', []):
            severity = threat.get('severity', 'LOW')
            score += severity_penalties.get(severity, -5)

        for warning in results.get('warnings', []):
            severity = warning.get('severity', 'LOW')
            score += severity_penalties.get(severity, -5) // 2

        return max(0, min(100, score))

    def scan_directory(self, directory: str) -> Dict[str, Any]:
        """
        Scan all skill files in a directory.

        Args:
            directory: Path to directory to scan

        Returns:
            Dictionary containing all scan results
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        results = {
            'directory': directory,
            'files_scanned': 0,
            'total_threats': 0,
            'file_results': {},
            'summary': {}
        }

        # Find all skill files
        skill_files = list(dir_path.rglob('*.py')) + list(dir_path.rglob('*.js'))

        for file_path in skill_files:
            file_result = self.scan_file(str(file_path))
            results['file_results'][str(file_path)] = file_result
            results['files_scanned'] += 1
            results['total_threats'] += len(file_result.get('threats', []))

        # Generate summary
        results['summary'] = self._generate_summary(results['file_results'])

        return results

    def _generate_summary(self, file_results: Dict) -> Dict:
        """Generate a summary of all scan results."""
        summary = {
            'total_files': len(file_results),
            'files_with_threats': 0,
            'threat_breakdown': {},
            'severity_distribution': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }

        for file_path, result in file_results.items():
            if result.get('threats'):
                summary['files_with_threats'] += 1

            for threat in result.get('threats', []):
                threat_type = threat.get('type', 'unknown')
                summary['threat_breakdown'][threat_type] = \
                    summary['threat_breakdown'].get(threat_type, 0) + 1

                severity = threat.get('severity', 'LOW')
                summary['severity_distribution'][severity] += 1

        return summary
