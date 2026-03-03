"""
Auto-Updater Module
Automatically updates threat rules and signatures, and software
"""

import os
import json
import hashlib
import asyncio
import aiohttp
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from loguru import logger
import yaml
import requests


class AutoUpdater:
    """
    Automatically updates threat detection rules, signatures, and the software itself.
    Supports rollback, incremental updates, and verification.
    """

    # Update sources
    UPDATE_SOURCES = {
        'github': {
            'rules_url': 'https://raw.githubusercontent.com/wooluo/openclaw-SEC/main/config/threat_rules.yaml',
            'blacklist_url': 'https://raw.githubusercontent.com/wooluo/openclaw-SEC/main/config/blacklist.txt',
            'version_url': 'https://api.github.com/repos/wooluo/openclaw-SEC/releases/latest',
        },
        # Alternative sources (backup)
        'backup': {
            'rules_url': 'https://cdn.openclaw.ai/security/threat_rules.yaml',
            'blacklist_url': 'https://cdn.openclaw.ai/security/blacklist.txt',
        }
    }

    # Threat intelligence feeds (optional)
    threat_intel = {
        'otx_url': 'https://otx.alienvault.com/api/v1/indicators/hostname/',
        # Add your OTX API key in config
    }

    def __init__(self, config):
        """Initialize the auto-updater."""
        self.config = config
        self._update_dir = Path(config.get('updater.cache_dir', './data/updates'))
        self._update_dir.mkdir(parents=True, exist_ok=True)
        self._last_update = None
        self._update_history = self._load_update_history()
        self._current_version = self._get_current_version()
        logger.info(f"Auto-updater initialized (version: {self._current_version})")

    def _get_current_version(self) -> str:
        """Get current software version."""
        try:
            from openclaw_shield import __version__
            return __version__
        except ImportError:
            return "1.0.0"

    def _load_update_history(self) -> Dict:
        """Load update history from file."""
        history_file = self._update_dir / 'update_history.json'
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load update history: {e}")
        return {}

    def _save_update_history(self):
        """Save update history to file."""
        history_file = self._update_dir / 'update_history.json'
        try:
            with open(history_file, 'w') as f:
                json.dump(self._update_history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save update history: {e}")

    async def check_for_updates(self) -> Dict:
        """
        Check for available updates.

        Returns:
            Dictionary with update information
        """
        logger.info("Checking for updates...")

        updates = {
            'software_update': None,
            'rules_update': None,
            'blacklist_update': None,
            'current_version': self._current_version,
        }

        try:
            # Check GitHub for latest release
            async with aiohttp.ClientSession() as session:
                headers = {'Accept': 'application/vnd.github.v3+json'}
                async with session.get(
                    self.UPDATE_SOURCES['github']['version_url'],
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        latest_version = data.get('tag_name', 'v1.0.0')
                        updates['software_update'] = {
                            'available': latest_version != self._current_version,
                            'current': self._current_version,
                            'latest': latest_version,
                            'download_url': data.get('html_url'),
                            'release_notes': data.get('body', '')
                        }
        except Exception as e:
            logger.warning(f"Failed to check for software updates: {e}")

        # Check for rules updates
        rules_update = await self._check_rules_update()
        if rules_update:
            updates['rules_update'] = rules_update

        # Check for blacklist updates
        blacklist_update = await self._check_blacklist_update()
        if blacklist_update:
            updates['blacklist_update'] = blacklist_update

        return updates

    async def _check_rules_update(self) -> Optional[Dict]:
        """Check for threat rules updates."""
        local_rules_file = Path(self.config.get('threat_detection.rules_file',
                                     './config/threat_rules.yaml'))
        local_hash = None
        local_modified = None

        if local_rules_file.exists():
            local_modified = datetime.fromtimestamp(local_rules_file.stat().st_mtime)
            with open(local_rules_file, 'rb') as f:
                local_hash = hashlib.sha256(f.read()).hexdigest()

        # Try primary source
        for source_name, source in self.UPDATE_SOURCES.items():
            if 'rules_url' not in source:
                continue

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(source['rules_url']) as response:
                        if response.status == 200:
                            content = await response.text()
                            remote_hash = hashlib.sha256(content.encode()).hexdigest()

                            # Check if update is available
                            if remote_hash != local_hash:
                                return {
                                    'available': True,
                                    'local_hash': local_hash,
                                    'remote_hash': remote_hash,
                                    'local_modified': local_modified.isoformat() if local_modified else None,
                                    'source': source_name,
                                    'size': len(content)
                                }
                            else:
                                logger.debug(f"Rules up to date (source: {source_name})")
                                return None
            except Exception as e:
                logger.warning(f"Failed to check rules from {source_name}: {e}")
                continue

        return None

    async def _check_blacklist_update(self) -> Optional[Dict]:
        """Check for blacklist updates."""
        local_blacklist_file = Path(self.config.get('network.blacklist_file',
                                        './config/blacklist.txt'))
        local_hash = None
        local_modified = None

        if local_blacklist_file.exists():
            local_modified = datetime.fromtimestamp(local_blacklist_file.stat().st_mtime)
            with open(local_blacklist_file, 'rb') as f:
                local_hash = hashlib.sha256(f.read()).hexdigest()

        # Try sources
        for source_name, source in self.UPDATE_SOURCES.items():
            if 'blacklist_url' not in source:
                continue

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(source['blacklist_url']) as response:
                        if response.status == 200:
                            content = await response.text()
                            remote_hash = hashlib.sha256(content.encode()).hexdigest()

                            if remote_hash != local_hash:
                                return {
                                    'available': True,
                                    'local_hash': local_hash,
                                    'remote_hash': remote_hash,
                                    'local_modified': local_modified.isoformat() if local_modified else None,
                                    'source': source_name,
                                    'size': len(content),
                                    'entries': len([l for l in content.split('\n') if l.strip() and not l.startswith('#')])
                                }
                            else:
                                logger.debug(f"Blacklist up to date (source: {source_name})")
                                return None
            except Exception as e:
                logger.warning(f"Failed to check blacklist from {source_name}: {e}")
                continue

        return None

    async def apply_updates(self, updates: Dict, auto_confirm: bool = False) -> Dict:
        """
        Apply available updates.

        Args:
            updates: Update information from check_for_updates()
            auto_confirm: Automatically confirm updates without prompting
        Returns:
            Dictionary with update results
        """
        results = {
            'software': {'status': 'skipped', 'message': 'No update available'},
            'rules': {'status': 'skipped', 'message': 'No update available'},
            'blacklist': {'status': 'skipped', 'message': 'No update available'}
        }

        # Apply rules update
        if updates.get('rules_update', {}).get('available'):
            result = await self._apply_rules_update(updates['rules_update'])
            results['rules'] = result

        # Apply blacklist update
        if updates.get('blacklist_update', {}).get('available'):
            result = await self._apply_blacklist_update(updates['blacklist_update'])
            results['blacklist'] = result

        # Software update (requires manual intervention)
        if updates.get('software_update', {}).get('available'):
            if auto_confirm:
                results['software'] = {
                    'status': 'requires_manual',
                    'message': f"Software update available: {updates['software_update']['latest']}",
                    'current': updates['software_update']['current'],
                    'latest': updates['software_update']['latest'],
                    'download_url': updates['software_update']['download_url']
                }
            else:
                results['software'] = {
                    'status': 'available',
                    'message': f"Update available: {updates['software_update']['current']} -> {updates['software_update']['latest']}",
                    'download_url': updates['software_update']['download_url']
                }

        # Record update in history
        self._record_update(results)

        return results

    async def _apply_rules_update(self, update_info: Dict) -> Dict:
        """Apply rules update with backup and rollback capability."""
        logger.info("Applying threat rules update...")

        local_rules_file = Path(self.config.get('threat_detection.rules_file',
                                         './config/threat_rules.yaml'))
        backup_file = self._update_dir / f'threat_rules_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml'

        try:
            # Create backup
            if local_rules_file.exists():
                shutil.copy(local_rules_file, backup_file)
                logger.info(f"Created backup: {backup_file}")

            # Download new rules
            source = self.UPDATE_SOURCES[update_info['source']]
            async with aiohttp.ClientSession() as session:
                async with session.get(source['rules_url']) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Validate YAML before applying
                        try:
                            yaml.safe_load(content)
                        except yaml.YAMLError as e:
                            raise ValueError(f"Invalid YAML in update: {e}")

                        # Apply update
                        with open(local_rules_file, 'w') as f:
                            f.write(content)

                        logger.info("Threat rules updated successfully")

                        return {
                            'status': 'success',
                            'message': 'Threat rules updated successfully',
                            'backup': str(backup_file),
                            'rollback_available': True
                        }

        except Exception as e:
            logger.error(f"Failed to apply rules update: {e}")
            # Attempt rollback
            if backup_file.exists():
                try:
                    shutil.copy(backup_file, local_rules_file)
                    logger.info("Rolled back to previous rules")
                except Exception as rollback_error:
                    logger.error(f"Rollback failed: {rollback_error}")
            return {
                'status': 'failed',
                'message': str(e),
                'rollback_attempted': backup_file.exists()
            }

    async def _apply_blacklist_update(self, update_info: Dict) -> Dict:
        """Apply blacklist update with backup and rollback capability."""
        logger.info("Applying blacklist update...")

        local_blacklist_file = Path(self.config.get('network.blacklist_file',
                                               './config/blacklist.txt'))
        backup_file = self._update_dir / f'blacklist_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'

        try:
            # Create backup
            if local_blacklist_file.exists():
                shutil.copy(local_blacklist_file, backup_file)
                logger.info(f"Created backup: {backup_file}")

            # Download new blacklist
            source = self.UPDATE_SOURCES[update_info['source']]
            async with aiohttp.ClientSession() as session:
                async with session.get(source['blacklist_url']) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Apply update
                        with open(local_blacklist_file, 'w') as f:
                            f.write(content)
                        logger.info(f"Blacklist updated successfully ({update_info['entries']} entries)")

                        return {
                            'status': 'success',
                            'message': f"Blacklist updated: {update_info['entries']} entries",
                            'backup': str(backup_file),
                            'rollback_available': True,
                        }
        except Exception as e:
            logger.error(f"Failed to apply blacklist update: {e}")
            # Attempt rollback
            if backup_file.exists():
                try:
                    shutil.copy(backup_file, local_blacklist_file)
                    logger.info("Rolled back to previous blacklist")
                except Exception as rollback_error:
                    logger.error(f"Rollback failed: {rollback_error}")
            return {
                'status': 'failed',
                'message': str(e),
                'rollback_attempted': backup_file.exists()
            }

    def _record_update(self, results: Dict):
        """Record update in history."""
        update_record = {
            'timestamp': datetime.now().isoformat(),
            'results': results
        }
        self._update_history[datetime.now().isoformat()] = update_record
        self._save_update_history()

    def rollback_last_update(self, update_type: str) -> bool:
        """
        Rollback the last update of a specific type.

        Args:
            update_type: Type of update to rollback ('rules', 'blacklist')
        Returns:
            True if rollback successful, False otherwise
        """
        logger.info(f"Attempting rollback for {update_type}...")

        # Find the most recent backup
        pattern = f'{update_type}_backup_*.{"yaml" if update_type == "rules" else "txt"}'
        backups = list(self._update_dir.glob(pattern))

        if not backups:
            logger.warning(f"No backup found for {update_type}")
            return False

        # Get most recent backup
        latest_backup = max(backups, key=lambda p: p.stat().st_mtime)

        # Determine target file
        if update_type == 'rules':
            target_file = Path(self.config.get('threat_detection.rules_file',
                                           './config/threat_rules.yaml'))
        elif update_type == 'blacklist':
            target_file = Path(self.config.get('network.blacklist_file',
                                              './config/blacklist.txt'))
        else:
            logger.error(f"Unknown update type: {update_type}")
            return False

        try:
            shutil.copy(latest_backup, target_file)
            logger.info(f"Successfully rolled back {update_type} to {latest_backup}")
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    async def schedule_automatic_updates(self, interval_hours: int = 24) -> bool:
        """
        Schedule automatic update checks.

        Args:
            interval_hours: Hours between update checks
        """
        while True:
            try:
                await asyncio.sleep(interval_hours * 3600)
                logger.info("Running scheduled update check...")
                updates = await self.check_for_updates()
                if any(u.get('available', True) for u in [updates.get('rules_update'),
                                                      updates.get('blacklist_update')]):
                    results = await self.apply_updates(updates, auto_confirm=True)
                    logger.info(f"Automatic update completed: {results}")
                else:
                    logger.debug("No updates available")
            except asyncio.CancelledError:
                logger.info("Automatic update scheduler stopped")
                break
            except Exception as e:
                logger.error(f"Error in automatic update: {e}")

    def get_update_status(self) -> Dict:
        """Get current update status and history."""
        return {
            'current_version': self._current_version,
            'last_update': self._last_update,
            'update_history_count': len(self._update_history),
            'cached_updates': len(list(self._update_dir.glob('*')))
        }
