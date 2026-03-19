"""
Access Control Module
Runtime access control with process execution allowlist/blocklist,
file access control, network access policies, and capability-based security.
"""

import os
import pwd
import grp
import subprocess
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Callable, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
import threading
import hashlib


class AccessLevel(Enum):
    """Access control levels."""
    DENY = "deny"
    ALLOW = "allow"
    AUDIT = "audit"
    QUARANTINE = "quarantine"


class ResourceType(Enum):
    """Types of resources that can be controlled."""
    PROCESS = "process"
    FILE = "file"
    DIRECTORY = "directory"
    NETWORK = "network"
    SOCKET = "socket"
    SYSCALL = "syscall"


@dataclass
class AccessRule:
    """Represents an access control rule."""
    id: str
    name: str
    resource_type: ResourceType
    pattern: str  # Process name, file path, network address, etc.
    access_level: AccessLevel
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['resource_type'] = self.resource_type.value
        d['access_level'] = self.access_level.value
        return d


@dataclass
class AccessEvent:
    """Represents an access event."""
    timestamp: str
    resource_type: ResourceType
    resource: str
    action: str  # 'execute', 'read', 'write', 'connect', etc.
    allowed: bool
    rule_matched: Optional[str]
    pid: Optional[int]
    user: Optional[str]
    command: Optional[str]

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class Capability:
    """Capability-based security model."""

    # Defined capabilities
    CAP_NET_RAW = "CAP_NET_RAW"
    CAP_NET_ADMIN = "CAP_NET_ADMIN"
    CAP_SYS_ADMIN = "CAP_SYS_ADMIN"
    CAP_SYS_PTRACE = "CAP_SYS_PTRACE"
    CAP_SYS_CHROOT = "CAP_SYS_CHROOT"
    CAP_SETUID = "CAP_SETUID"
    CAP_SETGID = "CAP_SETGID"
    CAP_DAC_OVERRIDE = "CAP_DAC_OVERRIDE"
    CAP_DAC_READ_SEARCH = "CAP_DAC_READ_SEARCH"
    CAP_FOWNER = "CAP_FOWNER"
    CAP_FSETID = "CAP_FSETID"
    CAP_KILL = "CAP_KILL"
    CAP_CHOWN = "CAP_CHOWN"


# Capability sets for different profiles (defined outside class to avoid reference issues)
PROFILE_CAPABILITIES = {
    'minimal': [],
    'basic': [Capability.CAP_FOWNER, Capability.CAP_FSETID],
    'network': [Capability.CAP_NET_RAW],
    'admin': [
        Capability.CAP_NET_ADMIN,
        Capability.CAP_SYS_ADMIN,
        Capability.CAP_SYS_PTRACE,
        Capability.CAP_DAC_OVERRIDE,
    ],
}


class ProcessAccessControl:
    """Controls process execution based on allowlist/blocklist."""

    def __init__(self, config):
        """Initialize process access control."""
        self.config = config
        self._allowlist: Set[str] = set(config.get('access_control.process_allowlist', []))
        self._blocklist: Set[str] = set(config.get('access_control.process_blocklist', []))
        self._mode = config.get('access_control.process_mode', 'allowlist')  # allowlist, blocklist, or off

        # Statistics
        self._execution_attempts: Dict[str, int] = {}
        self._blocked_attempts: int = 0

    def check_execution(self, executable: str, args: List[str],
                       user: str = None) -> Tuple[bool, Optional[str]]:
        """
        Check if process execution is allowed.

        Args:
            executable: Path to executable or command name
            args: Command arguments
            user: User attempting execution

        Returns:
            Tuple of (allowed, reason)
        """
        exe_name = os.path.basename(executable)

        # Track attempts
        self._execution_attempts[exe_name] = self._execution_attempts.get(exe_name, 0) + 1

        # Check blocklist first (always deny if in blocklist)
        if exe_name in self._blocklist or executable in self._blocklist:
            self._blocked_attempts += 1
            logger.warning(f"Blocked execution of blocklisted process: {exe_name}")
            return False, f"Process {exe_name} is blocklisted"

        # Check allowlist if in allowlist mode
        if self._mode == 'allowlist':
            if exe_name not in self._allowlist and executable not in self._allowlist:
                self._blocked_attempts += 1
                logger.warning(f"Blocked execution of non-allowlisted process: {exe_name}")
                return False, f"Process {exe_name} is not in allowlist"

        # Check for suspicious arguments
        if self._check_suspicious_args(args):
            self._blocked_attempts += 1
            logger.warning(f"Blocked execution with suspicious arguments: {exe_name} {' '.join(args)}")
            return False, "Suspicious command arguments detected"

        # Check user restrictions
        if user:
            restricted_users = self.config.get('access_control.restricted_users', [])
            if user in restricted_users and exe_name not in self._allowlist:
                self._blocked_attempts += 1
                logger.warning(f"Blocked execution for restricted user {user}: {exe_name}")
                return False, f"User {user} is restricted from executing {exe_name}"

        return True, None

    def _check_suspicious_args(self, args: List[str]) -> bool:
        """Check for suspicious command arguments."""
        suspicious_patterns = [
            '--insecure',
            '--disable-security',
            '--allow-all',
            'rm -rf /',
            'mkfs',
            'dd if=/dev/zero',
            ':(){ :|:& };:',  # Fork bomb
            '> /dev/sda',
        ]

        args_str = ' '.join(args)

        for pattern in suspicious_patterns:
            if pattern in args_str:
                return True

        return False

    def add_to_allowlist(self, executable: str):
        """Add executable to allowlist."""
        self._allowlist.add(executable)
        logger.info(f"Added to allowlist: {executable}")

    def add_to_blocklist(self, executable: str):
        """Add executable to blocklist."""
        self._blocklist.add(executable)
        logger.info(f"Added to blocklist: {executable}")

    def get_statistics(self) -> Dict:
        """Get access control statistics."""
        return {
            'mode': self._mode,
            'allowlist_size': len(self._allowlist),
            'blocklist_size': len(self._blocklist),
            'execution_attempts': dict(self._execution_attempts),
            'blocked_attempts': self._blocked_attempts
        }


class FileAccessControl:
    """Controls file system access."""

    def __init__(self, config):
        """Initialize file access control."""
        self.config = config
        self._protected_paths: Set[str] = set(config.get('access_control.protected_paths', []))
        self._write_restricted: Set[str] = set(config.get('access_control.write_restricted', []))
        self._allowed_extensions: Set[str] = set(config.get('access_control.allowed_extensions', []))

    def check_read(self, file_path: str, user: str = None) -> Tuple[bool, Optional[str]]:
        """
        Check if file read is allowed.

        Args:
            file_path: Path to file
            user: User attempting read

        Returns:
            Tuple of (allowed, reason)
        """
        # Check if file exists
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"

        # Check protected paths
        for protected in self._protected_paths:
            if file_path.startswith(protected):
                if user and not self._check_user_access(user, protected):
                    return False, f"User {user} not authorized to access protected path"

        # Check system files
        system_files = ['/etc/shadow', '/etc/passwd', '/etc/sudoers']
        if file_path in system_files:
            if user != 'root':
                return False, f"System file access restricted for {user}"

        return True, None

    def check_write(self, file_path: str, user: str = None) -> Tuple[bool, Optional[str]]:
        """
        Check if file write is allowed.

        Args:
            file_path: Path to file
            user: User attempting write

        Returns:
            Tuple of (allowed, reason)
        """
        # Check read access first
        read_allowed, read_reason = self.check_read(file_path, user)
        if not read_allowed:
            return False, read_reason

        # Check write restrictions
        for restricted in self._write_restricted:
            if file_path.startswith(restricted):
                return False, f"Write access restricted for path: {restricted}"

        # Check critical system files
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
            '/boot/', '/sys/', '/proc/sys/'
        ]

        for critical in critical_files:
            if file_path.startswith(critical):
                if user != 'root':
                    return False, f"Cannot write to critical system file: {file_path}"

        # Check file extensions (for execution control)
        if self._allowed_extensions:
            ext = os.path.splitext(file_path)[1].lower()
            if ext and ext not in self._allowed_extensions:
                return False, f"File extension {ext} not allowed for writing"

        return True, None

    def check_execute(self, file_path: str, user: str = None) -> Tuple[bool, Optional[str]]:
        """
        Check if file execution is allowed.

        Args:
            file_path: Path to file
            user: User attempting execution

        Returns:
            Tuple of (allowed, reason)
        """
        # Check if file exists and is executable
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"

        if not os.access(file_path, os.X_OK):
            return False, f"File is not executable: {file_path}"

        # Check write restrictions first
        write_allowed, write_reason = self.check_write(file_path, user)
        if not write_allowed:
            return False, write_reason

        # Check suspicious locations
        suspicious_locations = ['/tmp/', '/var/tmp/', '/dev/shm/']
        for location in suspicious_locations:
            if file_path.startswith(location):
                logger.warning(f"Execution from suspicious location: {file_path}")
                return True, "Warning: Executing from temporary directory"

        return True, None

    def _check_user_access(self, user: str, path: str) -> bool:
        """Check if user has access to path."""
        try:
            # Get user info
            user_info = pwd.getpwnam(user)
            user_groups = [g.gr_gid for g in grp.getgrall() if user_info.pw_name in g.gr_mem]

            # Get file stats
            stat_info = os.stat(path)

            # Check owner
            if stat_info.st_uid == user_info.pw_uid:
                return True

            # Check group
            if stat_info.st_gid in user_groups:
                return True

            # Check others
            return bool(stat_info.st_mode & 0o004)

        except (KeyError, FileNotFoundError):
            return False


class NetworkAccessControl:
    """Controls network access."""

    def __init__(self, config):
        """Initialize network access control."""
        self.config = config
        self._allowed_domains: Set[str] = set(config.get('access_control.allowed_domains', []))
        self._blocked_domains: Set[str] = set(config.get('access_control.blocked_domains', []))
        self._allowed_ports: Set[int] = set(config.get('access_control.allowed_ports', []))
        self._blocked_ports: Set[int] = set(config.get('access_control.blocked_ports', [4444, 5555, 6666, 31337]))
        self._allow_outbound: bool = config.get('access_control.allow_outbound', True)
        self._allow_inbound: bool = config.get('access_control.allow_inbound', False)

    def check_connection(self, host: str, port: int,
                        direction: str = 'outbound',
                        user: str = None) -> Tuple[bool, Optional[str]]:
        """
        Check if network connection is allowed.

        Args:
            host: Remote hostname or IP
            port: Remote port
            direction: 'outbound' or 'inbound'
            user: User initiating connection

        Returns:
            Tuple of (allowed, reason)
        """
        # Check direction
        if direction == 'inbound' and not self._allow_inbound:
            return False, "Inbound connections not allowed"

        if direction == 'outbound' and not self._allow_outbound:
            return False, "Outbound connections not allowed"

        # Check blocked ports first
        if port in self._blocked_ports:
            return False, f"Port {port} is blocklisted"

        # Check allowed ports if configured
        if self._allowed_ports and port not in self._allowed_ports:
            return False, f"Port {port} is not in allowlist"

        # Check blocked domains
        for blocked in self._blocked_domains:
            if host.endswith(blocked) or blocked.endswith(host):
                return False, f"Host {host} is blocklisted"

        # Check allowed domains if configured
        if self._allowed_domains:
            allowed = any(host.endswith(allowed) or allowed.endswith(host)
                         for allowed in self._allowed_domains)
            if not allowed:
                return False, f"Host {host} is not in allowlist"

        # Check for IP-based connections (suspicious)
        if self._is_ip_address(host) and not self._is_local_network(host):
            logger.warning(f"Connection to remote IP address: {host}:{port}")

        return True, None

    def _is_ip_address(self, host: str) -> bool:
        """Check if host is an IP address."""
        parts = host.split('.')
        if len(parts) != 4:
            return False

        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _is_local_network(self, ip: str) -> bool:
        """Check if IP is in local network range."""
        parts = ip.split('.')

        # Local ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
        if parts[0] == '10':
            return True
        if parts[0] == '172' and 16 <= int(parts[1]) <= 31:
            return True
        if parts[0] == '192' and parts[1] == '168':
            return True
        if parts[0] == '127':
            return True

        return False

    def add_allowed_domain(self, domain: str):
        """Add domain to allowed list."""
        self._allowed_domains.add(domain)
        logger.info(f"Added allowed domain: {domain}")

    def add_blocked_domain(self, domain: str):
        """Add domain to blocked list."""
        self._blocked_domains.add(domain)
        logger.info(f"Added blocked domain: {domain}")


class AccessController:
    """
    Main access controller that coordinates all access control mechanisms.
    """

    def __init__(self, config):
        """Initialize the access controller."""
        self.config = config
        self.process_control = ProcessAccessControl(config)
        self.file_control = FileAccessControl(config)
        self.network_control = NetworkAccessControl(config)

        # Event tracking
        self._events: List[AccessEvent] = []
        self._event_callbacks: List[Callable] = []
        self._max_events = config.get('access_control.max_events', 10000)

        # Rules storage
        self._rules: Dict[str, AccessRule] = {}

    def check_process_execution(self, executable: str, args: List[str],
                               user: str = None) -> bool:
        """Check and log process execution."""
        allowed, reason = self.process_control.check_execution(executable, args, user)

        event = AccessEvent(
            timestamp=datetime.now().isoformat(),
            resource_type=ResourceType.PROCESS,
            resource=executable,
            action='execute',
            allowed=allowed,
            rule_matched=reason,
            pid=None,
            user=user,
            command=' '.join([executable] + args)
        )

        self._log_event(event)

        return allowed

    def check_file_read(self, file_path: str, user: str = None) -> bool:
        """Check and log file read."""
        allowed, reason = self.file_control.check_read(file_path, user)

        event = AccessEvent(
            timestamp=datetime.now().isoformat(),
            resource_type=ResourceType.FILE,
            resource=file_path,
            action='read',
            allowed=allowed,
            rule_matched=reason,
            pid=None,
            user=user,
            command=None
        )

        self._log_event(event)

        return allowed

    def check_file_write(self, file_path: str, user: str = None) -> bool:
        """Check and log file write."""
        allowed, reason = self.file_control.check_write(file_path, user)

        event = AccessEvent(
            timestamp=datetime.now().isoformat(),
            resource_type=ResourceType.FILE,
            resource=file_path,
            action='write',
            allowed=allowed,
            rule_matched=reason,
            pid=None,
            user=user,
            command=None
        )

        self._log_event(event)

        return allowed

    def check_network_connection(self, host: str, port: int,
                                direction: str = 'outbound',
                                user: str = None) -> bool:
        """Check and log network connection."""
        allowed, reason = self.network_control.check_connection(host, port, direction, user)

        event = AccessEvent(
            timestamp=datetime.now().isoformat(),
            resource_type=ResourceType.NETWORK,
            resource=f"{host}:{port}",
            action='connect',
            allowed=allowed,
            rule_matched=reason,
            pid=None,
            user=user,
            command=f"{direction} connection to {host}:{port}"
        )

        self._log_event(event)

        return allowed

    def _log_event(self, event: AccessEvent):
        """Log access event and trigger callbacks."""
        self._events.append(event)

        # Trim events if necessary
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

        # Trigger callbacks
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

        # Log if denied
        if not event.allowed:
            logger.warning(f"Access denied: {event.resource_type.value} {event.resource} - {event.rule_matched}")

    def register_callback(self, callback: Callable):
        """Register an event callback."""
        self._event_callbacks.append(callback)

    def get_events(self, limit: int = 100) -> List[AccessEvent]:
        """Get recent access events."""
        return self._events[-limit:]

    def get_statistics(self) -> Dict:
        """Get comprehensive access control statistics."""
        events = self._events

        return {
            'total_events': len(events),
            'denied_events': sum(1 for e in events if not e.allowed),
            'by_type': {
                rt.value: sum(1 for e in events if e.resource_type == rt)
                for rt in ResourceType
            },
            'process_control': self.process_control.get_statistics(),
            'recent_denials': [
                {'resource': e.resource, 'reason': e.rule_matched, 'timestamp': e.timestamp}
                for e in events if not e.allowed
            ][-10:]
        }

    def add_rule(self, rule: AccessRule):
        """Add an access control rule."""
        self._rules[rule.id] = rule
        logger.info(f"Added access rule: {rule.name}")

    def remove_rule(self, rule_id: str):
        """Remove an access control rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Removed access rule: {rule_id}")
