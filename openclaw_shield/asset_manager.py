"""
Asset Manager Module
Provides comprehensive asset discovery, inventory management, and classification
for OpenClaw Security Shield Phase 1 enhancements.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    logger.warning("python-magic not available, MIME detection will be limited")


class AssetType(Enum):
    """Asset classification types."""
    CODE = "code"
    CONFIG = "config"
    DATA = "data"
    BINARY = "binary"
    DOCUMENT = "document"
    SCRIPT = "script"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


class AssetRiskLevel(Enum):
    """Asset risk classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"
    UNKNOWN = "unknown"


@dataclass
class AssetFingerprint:
    """Fingerprint information for an asset."""
    md5: str
    sha1: str
    sha256: str
    size: int
    mime_type: str
    created: Optional[str] = None
    modified: Optional[str] = None


@dataclass
class AssetMetadata:
    """Additional metadata for an asset."""
    author: Optional[str] = None
    version: Optional[str] = None
    license: Optional[str] = None
    description: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)


@dataclass
class Asset:
    """Represents a discovered asset."""
    path: str
    asset_type: AssetType
    fingerprint: AssetFingerprint
    metadata: AssetMetadata
    risk_level: AssetRiskLevel = AssetRiskLevel.UNKNOWN
    tags: List[str] = field(default_factory=list)
    last_scanned: Optional[str] = None
    scan_results: List[Dict] = field(default_factory=list)
    is_quarantined: bool = False

    def to_dict(self) -> Dict:
        """Convert asset to dictionary."""
        return {
            'path': self.path,
            'asset_type': self.asset_type.value,
            'fingerprint': asdict(self.fingerprint),
            'metadata': asdict(self.metadata),
            'risk_level': self.risk_level.value,
            'tags': self.tags,
            'last_scanned': self.last_scanned,
            'scan_results': self.scan_results,
            'is_quarantined': self.is_quarantined
        }


class AssetDiscovery:
    """
    Discovers and categorizes assets within a directory.
    Supports multiple file types and programming languages.
    """

    # File extension mappings
    EXTENSION_MAP = {
        # Code files
        '.py': AssetType.CODE,
        '.js': AssetType.CODE,
        '.ts': AssetType.CODE,
        '.jsx': AssetType.CODE,
        '.tsx': AssetType.CODE,
        '.java': AssetType.CODE,
        '.kt': AssetType.CODE,
        '.go': AssetType.CODE,
        '.rs': AssetType.CODE,
        '.c': AssetType.CODE,
        '.cpp': AssetType.CODE,
        '.h': AssetType.CODE,
        '.hpp': AssetType.CODE,
        '.cs': AssetType.CODE,
        '.php': AssetType.CODE,
        '.rb': AssetType.CODE,
        '.swift': AssetType.CODE,
        '.dart': AssetType.CODE,
        '.lua': AssetType.CODE,
        '.r': AssetType.CODE,
        '.m': AssetType.CODE,
        '.mm': AssetType.CODE,

        # Config files
        '.yaml': AssetType.CONFIG,
        '.yml': AssetType.CONFIG,
        '.json': AssetType.CONFIG,
        '.xml': AssetType.CONFIG,
        '.toml': AssetType.CONFIG,
        '.ini': AssetType.CONFIG,
        '.cfg': AssetType.CONFIG,
        '.conf': AssetType.CONFIG,
        '.properties': AssetType.CONFIG,
        '.env': AssetType.CONFIG,
        '.dockerfile': AssetType.CONFIG,
        'docker-compose.yml': AssetType.CONFIG,
        'docker-compose.yaml': AssetType.CONFIG,

        # Script files
        '.sh': AssetType.SCRIPT,
        '.bash': AssetType.SCRIPT,
        '.zsh': AssetType.SCRIPT,
        '.fish': AssetType.SCRIPT,
        '.ps1': AssetType.SCRIPT,
        '.bat': AssetType.SCRIPT,
        '.cmd': AssetType.SCRIPT,

        # Data files
        '.sql': AssetType.DATA,
        '.csv': AssetType.DATA,
        '.tsv': AssetType.DATA,
        '.parquet': AssetType.DATA,
        '.feather': AssetType.DATA,
        '.pickle': AssetType.DATA,
        '.pkl': AssetType.DATA,

        # Document files
        '.md': AssetType.DOCUMENT,
        '.txt': AssetType.DOCUMENT,
        '.pdf': AssetType.DOCUMENT,
        '.doc': AssetType.DOCUMENT,
        '.docx': AssetType.DOCUMENT,
        '.rst': AssetType.DOCUMENT,
        '.adoc': AssetType.DOCUMENT,

        # Archive files
        '.zip': AssetType.ARCHIVE,
        '.tar': AssetType.ARCHIVE,
        '.gz': AssetType.ARCHIVE,
        '.bz2': AssetType.ARCHIVE,
        '.xz': AssetType.ARCHIVE,
        '.7z': AssetType.ARCHIVE,
        '.rar': AssetType.ARCHIVE,

        # Binary files
        '.exe': AssetType.BINARY,
        '.dll': AssetType.BINARY,
        '.so': AssetType.BINARY,
        '.dylib': AssetType.BINARY,
        '.bin': AssetType.BINARY,
        '.app': AssetType.BINARY,
    }

    # Patterns that suggest high-risk assets
    HIGH_RISK_PATTERNS = [
        r'password',
        r'secret',
        r'api[_-]?key',
        r'token',
        r'credential',
        r'private[_-]?key',
        r'\.pem$',
        r'\.key$',
        r'\.p12$',
        r'\.pfx$',
        r'wallet',
        r'backup',
        r'dump',
        r'\.sql$',
    ]

    # Patterns that suggest low-risk/safe assets
    SAFE_PATTERNS = [
        r'readme',
        r'license',
        r'changelog',
        r'contributing',
        r'\.md$',
        r'test',
        r'spec',
        r'mock',
    ]

    def __init__(self, config):
        """Initialize asset discovery."""
        self.config = config
        self._max_size = config.get('asset_discovery.max_file_size', 100 * 1024 * 1024)  # 100MB
        self._exclude_patterns = config.get('asset_discovery.exclude_patterns', [
            r'__pycache__',
            r'\.git',
            r'\.svn',
            r'\.hg',
            r'node_modules',
            r'\.venv',
            r'venv',
            r'\.egg-info',
            r'\.pytest_cache',
            r'\.mypy_cache',
            r'build',
            r'dist',
            r'\.tox',
        ])

    def discover(self, directory: str, recursive: bool = True) -> List[Asset]:
        """
        Discover all assets in a directory.

        Args:
            directory: Path to directory to scan
            recursive: Whether to scan recursively

        Returns:
            List of discovered assets
        """
        logger.info(f"Starting asset discovery in: {directory}")
        dir_path = Path(directory)

        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return []

        assets = []
        files = self._collect_files(dir_path, recursive)

        for file_path in files:
            try:
                asset = self._analyze_file(file_path)
                if asset:
                    assets.append(asset)
            except Exception as e:
                logger.warning(f"Failed to analyze {file_path}: {e}")

        logger.info(f"Discovered {len(assets)} assets")
        return assets

    def _collect_files(self, directory: Path, recursive: bool) -> List[Path]:
        """Collect all files to analyze, excluding unwanted patterns."""
        files = []
        exclude_regex = [re.compile(p) for p in self._exclude_patterns]

        if recursive:
            iterator = directory.rglob('*')
        else:
            iterator = directory.glob('*')

        for item in iterator:
            if not item.is_file():
                continue

            # Check exclude patterns
            relative_path = item.relative_to(directory)
            if any(pattern.search(str(relative_path)) for pattern in exclude_regex):
                continue

            # Check file size
            try:
                if item.stat().st_size > self._max_size:
                    logger.debug(f"Skipping large file: {item}")
                    continue
            except OSError:
                continue

            files.append(item)

        return files

    def _analyze_file(self, file_path: Path) -> Optional[Asset]:
        """Analyze a single file and create an asset record."""
        try:
            stat = file_path.stat()
            fingerprint = self._create_fingerprint(file_path, stat)
            asset_type = self._classify_asset(file_path, fingerprint)
            metadata = self._extract_metadata(file_path, asset_type)
            risk_level = self._assess_risk(file_path, asset_type, metadata)

            return Asset(
                path=str(file_path),
                asset_type=asset_type,
                fingerprint=fingerprint,
                metadata=metadata,
                risk_level=risk_level,
                tags=self._generate_tags(file_path, asset_type),
                last_scanned=datetime.now().isoformat()
            )
        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")
            return None

    def _create_fingerprint(self, file_path: Path, stat) -> AssetFingerprint:
        """Create cryptographic fingerprint of a file."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        mime_type = self._detect_mime_type(file_path)

        return AssetFingerprint(
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
            size=stat.st_size,
            mime_type=mime_type,
            created=datetime.fromtimestamp(stat.st_ctime).isoformat(),
            modified=datetime.fromtimestamp(stat.st_mtime).isoformat()
        )

    def _detect_mime_type(self, file_path: Path) -> str:
        """Detect MIME type of a file."""
        if HAS_MAGIC:
            try:
                mime = magic.Magic(mime=True)
                return mime.from_file(str(file_path))
            except Exception:
                pass

        # Fallback to extension-based detection
        ext = file_path.suffix.lower()
        mime_map = {
            '.py': 'text/x-python',
            '.js': 'text/javascript',
            '.json': 'application/json',
            '.yaml': 'text/yaml',
            '.yml': 'text/yaml',
            '.xml': 'application/xml',
            '.txt': 'text/plain',
            '.md': 'text/markdown',
            '.pdf': 'application/pdf',
            '.zip': 'application/zip',
            '.tar': 'application/x-tar',
            '.gz': 'application/gzip',
        }
        return mime_map.get(ext, 'application/octet-stream')

    def _classify_asset(self, file_path: Path, fingerprint: AssetFingerprint) -> AssetType:
        """Classify asset by type."""
        # Check extension map
        ext = file_path.suffix.lower()
        if ext in self.EXTENSION_MAP:
            return self.EXTENSION_MAP[ext]

        # Check filename for special cases
        filename = file_path.name.lower()
        if filename == 'dockerfile':
            return AssetType.CONFIG
        if filename == 'makefile':
            return AssetType.SCRIPT
        if filename.startswith('.'):
            return AssetType.CONFIG

        # Use MIME type as fallback
        if fingerprint.mime_type.startswith('text/'):
            if 'python' in fingerprint.mime_type:
                return AssetType.CODE
            if 'javascript' in fingerprint.mime_type:
                return AssetType.CODE
            return AssetType.DOCUMENT

        # Check for binary
        if fingerprint.mime_type in ['application/x-executable', 'application/octet-stream']:
            return AssetType.BINARY

        return AssetType.UNKNOWN

    def _extract_metadata(self, file_path: Path, asset_type: AssetType) -> AssetMetadata:
        """Extract metadata from file based on type."""
        metadata = AssetMetadata()

        if asset_type == AssetType.CODE:
            self._extract_code_metadata(file_path, metadata)

        return metadata

    def _extract_code_metadata(self, file_path: Path, metadata: AssetMetadata):
        """Extract metadata from code files."""
        ext = file_path.suffix.lower()

        if ext == '.py':
            self._extract_python_metadata(file_path, metadata)
        elif ext in ['.js', '.ts', '.jsx', '.tsx']:
            self._extract_javascript_metadata(file_path, metadata)

    def _extract_python_metadata(self, file_path: Path, metadata: AssetMetadata):
        """Extract metadata from Python files."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract imports
            import_pattern = r'^(?:from|import)\s+(\S+)'
            metadata.imports = list(set(re.findall(import_pattern, content, re.MULTILINE)))

            # Look for common metadata patterns
            version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
            if version_match:
                metadata.version = version_match.group(1)

            author_match = re.search(r'__author__\s*=\s*["\']([^"\']+)["\']', content)
            if author_match:
                metadata.author = author_match.group(1)

        except Exception as e:
            logger.debug(f"Failed to extract Python metadata from {file_path}: {e}")

    def _extract_javascript_metadata(self, file_path: Path, metadata: AssetMetadata):
        """Extract metadata from JavaScript/TypeScript files."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract imports (ES6 and CommonJS)
            import_patterns = [
                r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
                r'require\(["\']([^"\']+)["\']\)'
            ]
            for pattern in import_patterns:
                metadata.imports.extend(re.findall(pattern, content))

            metadata.imports = list(set(metadata.imports))

        except Exception as e:
            logger.debug(f"Failed to extract JS metadata from {file_path}: {e}")

    def _assess_risk(self, file_path: Path, asset_type: AssetType,
                     metadata: AssetMetadata) -> AssetRiskLevel:
        """Assess the risk level of an asset."""
        path_lower = str(file_path).lower()

        # Check for high-risk patterns
        for pattern in self.HIGH_RISK_PATTERNS:
            if re.search(pattern, path_lower):
                return AssetRiskLevel.HIGH

        # Check for suspicious imports
        if asset_type == AssetType.CODE:
            dangerous_imports = ['subprocess', 'os', 'sys', 'pickle', 'marshal',
                                 'ctypes', 'socket', 'eval', 'exec']
            if any(imp in metadata.imports for imp in dangerous_imports):
                return AssetRiskLevel.MEDIUM

        # Check for safe patterns
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, path_lower):
                return AssetRiskLevel.SAFE

        # Default risk based on type
        type_risk_map = {
            AssetType.BINARY: AssetRiskLevel.HIGH,
            AssetType.SCRIPT: AssetRiskLevel.MEDIUM,
            AssetType.CONFIG: AssetRiskLevel.LOW,
            AssetType.DATA: AssetRiskLevel.MEDIUM,
            AssetType.CODE: AssetRiskLevel.MEDIUM,
            AssetType.DOCUMENT: AssetRiskLevel.SAFE,
            AssetType.ARCHIVE: AssetRiskLevel.HIGH,
            AssetType.UNKNOWN: AssetRiskLevel.MEDIUM,
        }

        return type_risk_map.get(asset_type, AssetRiskLevel.MEDIUM)

    def _generate_tags(self, file_path: Path, asset_type: AssetType) -> List[str]:
        """Generate tags for an asset."""
        tags = [asset_type.value]

        # Add extension tag
        if file_path.suffix:
            tags.append(file_path.suffix[1:])  # Remove dot

        # Add size-based tags
        try:
            size = file_path.stat().st_size
            if size < 1024:
                tags.append('small')
            elif size < 1024 * 1024:
                tags.append('medium')
            else:
                tags.append('large')
        except OSError:
            pass

        return tags


class AssetInventory:
    """
    Manages the asset inventory with persistence and querying capabilities.
    """

    def __init__(self, config):
        """Initialize asset inventory."""
        self.config = config
        self._inventory_file = Path(config.get('asset_discovery.inventory_file',
                                               './data/asset_inventory.json'))
        self._inventory: Dict[str, Asset] = {}
        self._load_inventory()

    def add_asset(self, asset: Asset):
        """Add an asset to the inventory."""
        self._inventory[asset.path] = asset
        self._save_inventory()
        logger.debug(f"Added asset: {asset.path}")

    def add_assets(self, assets: List[Asset]):
        """Add multiple assets to the inventory."""
        for asset in assets:
            self._inventory[asset.path] = asset
        self._save_inventory()
        logger.info(f"Added {len(assets)} assets to inventory")

    def get_asset(self, path: str) -> Optional[Asset]:
        """Get an asset by path."""
        return self._inventory.get(path)

    def remove_asset(self, path: str):
        """Remove an asset from the inventory."""
        if path in self._inventory:
            del self._inventory[path]
            self._save_inventory()
            logger.debug(f"Removed asset: {path}")

    def get_all_assets(self) -> List[Asset]:
        """Get all assets in the inventory."""
        return list(self._inventory.values())

    def query(self, **filters) -> List[Asset]:
        """
        Query assets with filters.

        Args:
            **filters: Filter criteria (asset_type, risk_level, tags, etc.)

        Returns:
            List of matching assets
        """
        results = list(self._inventory.values())

        for key, value in filters.items():
            if key == 'asset_type':
                if isinstance(value, str):
                    value = AssetType(value)
                results = [a for a in results if a.asset_type == value]
            elif key == 'risk_level':
                if isinstance(value, str):
                    value = AssetRiskLevel(value)
                results = [a for a in results if a.risk_level == value]
            elif key == 'tag':
                results = [a for a in results if value in a.tags]
            elif key == 'is_quarantined':
                results = [a for a in results if a.is_quarantined == value]
            elif key == 'path_contains':
                results = [a for a in results if value in a.path]

        return results

    def get_statistics(self) -> Dict:
        """Get inventory statistics."""
        assets = self.get_all_assets()

        stats = {
            'total_assets': len(assets),
            'by_type': {},
            'by_risk': {},
            'quarantined': 0,
            'last_updated': datetime.now().isoformat()
        }

        for asset in assets:
            # Count by type
            atype = asset.asset_type.value
            stats['by_type'][atype] = stats['by_type'].get(atype, 0) + 1

            # Count by risk
            risk = asset.risk_level.value
            stats['by_risk'][risk] = stats['by_risk'].get(risk, 0) + 1

            # Count quarantined
            if asset.is_quarantined:
                stats['quarantined'] += 1

        return stats

    def export_report(self, output_file: str = None, format: str = 'json') -> str:
        """
        Export inventory report.

        Args:
            output_file: Output file path
            format: Output format (json, csv)

        Returns:
            Report content or file path
        """
        assets = [a.to_dict() for a in self.get_all_assets()]

        if format == 'json':
            report = json.dumps({
                'generated_at': datetime.now().isoformat(),
                'statistics': self.get_statistics(),
                'assets': assets
            }, indent=2)

            if output_file:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(report)
                logger.info(f"Report exported to: {output_file}")
                return output_file

            return report

        elif format == 'csv':
            import csv
            output = []
            fieldnames = ['path', 'asset_type', 'risk_level', 'size', 'mime_type']

            for asset_dict in assets:
                output.append({
                    'path': asset_dict['path'],
                    'asset_type': asset_dict['asset_type'],
                    'risk_level': asset_dict['risk_level'],
                    'size': asset_dict['fingerprint']['size'],
                    'mime_type': asset_dict['fingerprint']['mime_type']
                })

            if output_file:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(output)
                logger.info(f"CSV report exported to: {output_file}")
                return output_file

            return str(output)

    def cleanup_stale(self, days: int = 30):
        """Remove assets that haven't been scanned recently."""
        cutoff = datetime.now() - timedelta(days=days)
        stale_paths = []

        for path, asset in self._inventory.items():
            if asset.last_scanned:
                scan_date = datetime.fromisoformat(asset.last_scanned)
                if scan_date < cutoff:
                    stale_paths.append(path)

        for path in stale_paths:
            self.remove_asset(path)

        logger.info(f"Cleaned up {len(stale_paths)} stale assets")

    def _load_inventory(self):
        """Load inventory from disk."""
        if not self._inventory_file.exists():
            logger.debug("No existing inventory found")
            return

        try:
            with open(self._inventory_file, 'r') as f:
                data = json.load(f)

            for asset_data in data.get('assets', []):
                asset = self._dict_to_asset(asset_data)
                self._inventory[asset.path] = asset

            logger.info(f"Loaded {len(self._inventory)} assets from inventory")
        except Exception as e:
            logger.error(f"Failed to load inventory: {e}")

    def _save_inventory(self):
        """Save inventory to disk."""
        try:
            self._inventory_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'version': '1.0',
                'generated_at': datetime.now().isoformat(),
                'statistics': self.get_statistics(),
                'assets': [a.to_dict() for a in self._inventory.values()]
            }
            with open(self._inventory_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save inventory: {e}")

    @staticmethod
    def _dict_to_asset(data: Dict) -> Asset:
        """Convert dictionary to Asset object."""
        fingerprint_data = data.pop('fingerprint')
        fingerprint = AssetFingerprint(**fingerprint_data)

        metadata_data = data.pop('metadata', {})
        metadata = AssetMetadata(**metadata_data)

        data['asset_type'] = AssetType(data['asset_type'])
        data['risk_level'] = AssetRiskLevel(data['risk_level'])

        return Asset(
            fingerprint=fingerprint,
            metadata=metadata,
            **data
        )


class AssetManager:
    """
    Main entry point for asset management functionality.
    Combines discovery and inventory management.
    """

    def __init__(self, config):
        """Initialize asset manager."""
        self.config = config
        self.discovery = AssetDiscovery(config)
        self.inventory = AssetInventory(config)

    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        """
        Scan a directory and update inventory.

        Args:
            directory: Path to directory
            recursive: Whether to scan recursively

        Returns:
            Scan results
        """
        logger.info(f"Starting directory scan: {directory}")
        assets = self.discovery.discover(directory, recursive)
        self.inventory.add_assets(assets)

        return {
            'directory': directory,
            'assets_discovered': len(assets),
            'timestamp': datetime.now().isoformat(),
            'statistics': self.inventory.get_statistics()
        }

    def get_asset(self, path: str) -> Optional[Dict]:
        """Get asset information by path."""
        asset = self.inventory.get_asset(path)
        return asset.to_dict() if asset else None

    def search_assets(self, **filters) -> List[Dict]:
        """Search assets with filters."""
        assets = self.inventory.query(**filters)
        return [a.to_dict() for a in assets]

    def get_risk_report(self) -> Dict:
        """Generate a risk assessment report."""
        stats = self.inventory.get_statistics()

        high_risk = self.inventory.query(risk_level=AssetRiskLevel.HIGH)
        critical_risk = self.inventory.query(risk_level=AssetRiskLevel.CRITICAL)

        return {
            'generated_at': datetime.now().isoformat(),
            'total_assets': stats['total_assets'],
            'risk_distribution': stats['by_risk'],
            'high_risk_assets': [a.to_dict() for a in high_risk],
            'critical_risk_assets': [a.to_dict() for a in critical_risk],
            'recommendations': self._generate_recommendations(stats)
        }

    def _generate_recommendations(self, stats: Dict) -> List[str]:
        """Generate security recommendations based on inventory."""
        recommendations = []

        if stats['by_risk'].get('critical', 0) > 0:
            recommendations.append(
                f"Found {stats['by_risk']['critical']} critical risk assets. "
                "Review and remediate immediately."
            )

        if stats['by_risk'].get('high', 0) > 5:
            recommendations.append(
                f"Found {stats['by_risk']['high']} high risk assets. "
                "Prioritize security review."
            )

        binary_count = stats['by_type'].get('binary', 0)
        if binary_count > 0:
            recommendations.append(
                f"Found {binary_count} binary files. "
                "Verify their source and scan for malware."
            )

        return recommendations
