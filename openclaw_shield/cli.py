#!/usr/bin/env python3
"""
OpenClaw Security Shield CLI
Command-line interface for security operations
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from pathlib import Path
import sys

from .shield import SecurityShield
from .scanner import SkillScanner
from .config import Config

console = Console()


@click.group()
@click.version_option(version='1.0.0', prog_name='openclaw-shield')
def cli():
    """OpenClaw Security Shield - Comprehensive security protection for OpenClaw."""
    pass


@cli.command()
@click.option('--config', '-c', type=click.Path(), help='Path to configuration file')
def init(config):
    """Initialize OpenClaw Security Shield configuration."""
    console.print(Panel.fit(
        "[bold cyan]OpenClaw Security Shield - Initialization[/bold cyan]",
        border_style="cyan"
    ))

    config_path = config or './openclaw-shield.yaml'
    cfg = Config(config_path)

    # Create necessary directories
    directories = [
        cfg.get('security.quarantine_dir', './quarantine'),
        Path(cfg.get('logging.file', './logs/security.log')).parent,
        Path(cfg.get('audit.database', './data/audit.db')).parent,
        Path(cfg.get('security.keys_file', './config/.keyring')).parent,
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        console.print(f"[green]✓[/green] Created directory: {directory}")

    # Save configuration
    cfg.save(config_path)
    console.print(f"[green]✓[/green] Configuration saved to: {config_path}")

    console.print("\n[bold green]Initialization complete![/bold green]")
    console.print("\nNext steps:")
    console.print("  1. Review configuration: [cyan]openclaw-shield.yaml[/cyan]")
    console.print("  2. Scan your skills: [cyan]openclaw-shield scan-all ~/.openclaw/workspace/skills[/cyan]")
    console.print("  3. Start monitoring: [cyan]openclaw-shield monitor[/cyan]")


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(path, verbose):
    """Scan a single skill file for security threats."""
    shield = SecurityShield()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        result = shield.scan_skill(path)

    # Display results
    _display_scan_result(result, verbose)


@cli.command('scan-all')
@click.argument('directory', type=click.Path(exists=True))
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--output', '-o', type=click.Path(), help='Output file for report')
def scan_all(directory, verbose, output):
    """Scan all skills in a directory."""
    shield = SecurityShield()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning all skills...", total=None)
        results = shield.scan_all_skills(directory)

    # Display summary
    _display_scan_summary(results, verbose)

    # Save report if output specified
    if output:
        import json
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green]Report saved to: {output}[/green]")


@cli.command()
def monitor():
    """Start real-time security monitoring."""
    console.print(Panel.fit(
        "[bold cyan]Starting Security Monitor[/bold cyan]",
        border_style="cyan"
    ))

    shield = SecurityShield()

    console.print("[yellow]Starting real-time monitoring...[/yellow]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        import asyncio
        asyncio.run(shield.start_monitoring())
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped by user[/yellow]")
        shield.stop_monitoring()


@cli.command()
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html']),
              default='text', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file')
def report(format, output):
    """Generate a security report."""
    shield = SecurityShield()

    report_content = shield.generate_report(format)

    if output:
        with open(output, 'w') as f:
            f.write(report_content)
        console.print(f"[green]Report saved to: {output}[/green]")
    else:
        console.print(report_content)


@cli.command()
def status():
    """Show current security status."""
    shield = SecurityShield()
    status = shield.get_status()

    console.print(Panel.fit(
        "[bold cyan]OpenClaw Security Shield - Status[/bold cyan]",
        border_style="cyan"
    ))

    table = Table(show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Monitoring", "Active" if status['monitoring_active'] else "Inactive")
    table.add_row("Threats Detected", str(status['threats_detected']))
    table.add_row("Quarantine Dir", status['quarantine_dir'])

    console.print(table)

    # Component status
    console.print("\n[bold]Component Status:[/bold]")
    for component, state in status['components'].items():
        color = "green" if state == "active" else "red"
        console.print(f"  [{color}]●[/{color}] {component}: {state}")


@cli.command()
@click.argument('path', type=click.Path(exists=True))
def leaks(path):
    """Scan for API key leaks in a directory."""
    from .api_protection import APIKeyProtection

    shield = SecurityShield()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning for leaks...", total=None)
        results = shield.api_protection.scan_for_leaks(path)

    console.print(f"\n[cyan]Files scanned:[/cyan] {results['files_scanned']}")

    if results['leaks_found']:
        console.print(f"[red]Leaks found: {len(results['leaks_found'])}[/red]\n")

        table = Table(title="Detected Leaks")
        table.add_column("File", style="cyan")
        table.add_column("Line", style="yellow")
        table.add_column("Type", style="red")
        table.add_column("Preview", style="dim")

        for leak in results['leaks_found']:
            table.add_row(
                str(leak['file']),
                str(leak['line']),
                leak['key_type'],
                leak['preview']
            )

        console.print(table)
    else:
        console.print("[green]No API key leaks detected[/green]")


@cli.command()
@click.option('--limit', '-l', default=20, help='Number of alerts to show')
def alerts(limit):
    """Show recent security alerts."""
    from .audit import SecurityAuditor

    config = Config()
    auditor = SecurityAuditor(config)

    events = auditor.get_events(limit=limit, severity='HIGH')

    if not events:
        console.print("[green]No recent security alerts[/green]")
        return

    table = Table(title=f"Recent Security Alerts (Last {limit})")
    table.add_column("Time", style="dim")
    table.add_column("Type", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Message")

    for event in events:
        severity = event['severity']
        severity_color = {
            'CRITICAL': 'red',
            'HIGH': 'orange1',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }.get(severity, 'white')

        table.add_row(
            event['timestamp'][:19],
            event['event_type'],
            f"[{severity_color}]{severity}[/{severity_color}]",
            event['message'][:50]
        )

    console.print(table)


@cli.command()
def threats():
    """Show unresolved threats."""
    from .audit import SecurityAuditor

    config = Config()
    auditor = SecurityAuditor(config)

    threat_list = auditor.get_threats(resolved=False)

    if not threat_list:
        console.print("[green]No unresolved threats[/green]")
        return

    table = Table(title="Unresolved Threats")
    table.add_column("ID", style="dim")
    table.add_column("Type", style="red")
    table.add_column("Severity", style="yellow")
    table.add_column("Description")
    table.add_column("Remediation", style="cyan")

    for threat in threat_list:
        table.add_row(
            str(threat['id']),
            threat['threat_type'],
            threat['severity'],
            threat['description'][:40],
            (threat.get('remediation') or 'N/A')[:30]
        )

    console.print(table)
    console.print(f"\n[cyan]Total unresolved: {len(threat_list)}[/cyan]")


@cli.command()
@click.argument('threat_id', type=int)
def resolve(threat_id):
    """Mark a threat as resolved."""
    from .audit import SecurityAuditor

    config = Config()
    auditor = SecurityAuditor(config)

    auditor.resolve_threat(threat_id)
    console.print(f"[green]✓ Threat {threat_id} marked as resolved[/green]")


@cli.group()
def update():
    """Update threat detection rules and signatures."""
    pass


@update.command()
@click.option('--auto-confirm', is_flag=True, help='Automatically confirm updates')
@click.option('--source', '-s', type=click.Choice(['official', 'github', 'local']),
              default='official', help='Update source')
def rules(auto_confirm, source):
    """Update threat detection rules."""
    from .updater import AutoUpdater

    console.print(Panel.fit(
        "[bold cyan]Threat Rules Update[/bold cyan]",
        border_style="cyan"
    ))

    config = Config()
    updater = AutoUpdater(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Checking for updates...", total=None)
        import asyncio
        results = asyncio.run(updater.check_for_updates())

    if not any(u.get('available', False) for u in [results.get('rules_update'),
                                                    results.get('blacklist_update'),
                                                    results.get('software_update')]):
        console.print("[green]✓ All rules are up to date[/green]")
        return

    # Show available updates
    if results.get('rules_update', {}).get('available'):
        update_info = results['rules_update']
        console.print(f"\n[yellow]Rules update available:[/yellow]")
        console.print(f"  Current version: {update_info.get('current', 'unknown')}")
        console.print(f"  Latest version: {update_info.get('latest', 'unknown')}")

    if results.get('blacklist_update', {}).get('available'):
        update_info = results['blacklist_update']
        console.print(f"\n[yellow]Blacklist update available:[/yellow]")
        console.print(f"  Entries: {update_info.get('entries', 'unknown')}")

    # Apply updates
    if auto_confirm:
        console.print("\n[cyan]Auto-confirming updates...[/cyan]")
    else:
        if not click.confirm("\nApply these updates?", default=False):
            console.print("[yellow]Update cancelled[/yellow]")
            return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Applying updates...", total=None)
        import asyncio
        update_results = asyncio.run(updater.apply_updates(results, auto_confirm=True))

    # Show results
    for update_type, result in update_results.items():
        if result.get('status') == 'success':
            console.print(f"[green]✓ {update_type.title()} updated successfully[/green]")
        elif result.get('status') == 'failed':
            console.print(f"[red]✗ {update_type.title()} update failed: {result.get('message')}[/red]")
        else:
            console.print(f"[yellow]⊘ {update_type.title()}: {result.get('message')}[/yellow]")


@update.command()
@click.argument('update_type', type=click.Choice(['rules', 'blacklist']))
def rollback(update_type):
    """Rollback the last update of a specific type."""
    from .updater import AutoUpdater

    config = Config()
    updater = AutoUpdater(config)

    console.print(f"[cyan]Rolling back {update_type}...[/cyan]")

    success = updater.rollback_last_update(update_type)

    if success:
        console.print(f"[green]✓ Successfully rolled back {update_type}[/green]")
    else:
        console.print(f"[red]✗ Failed to rollback {update_type}[/red]")


@update.command()
def status():
    """Show update status and history."""
    from .updater import AutoUpdater

    config = Config()
    updater = AutoUpdater(config)

    status_info = updater.get_update_status()

    console.print(Panel.fit(
        "[bold cyan]Update Status[/bold cyan]",
        border_style="cyan"
    ))

    table = Table()
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Current Version", status_info.get('current_version', 'unknown'))
    table.add_row("Last Update", status_info.get('last_update', 'Never'))
    table.add_row("Update History Count", str(status_info.get('update_history_count', 0)))
    table.add_row("Cached Updates", str(status_info.get('cached_updates', 0)))

    console.print(table)


@update.command()
@click.option('--hours', '-h', default=24, help='Hours between automatic updates')
@click.option('--daemon', '-d', is_flag=True, help='Run as daemon')
def schedule(hours, daemon):
    """Schedule automatic updates."""
    from .updater import AutoUpdater

    config = Config()
    updater = AutoUpdater(config)

    if daemon:
        console.print(f"[cyan]Starting automatic update scheduler (every {hours} hours)...[/cyan]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        try:
            import asyncio
            asyncio.run(updater.schedule_automatic_updates(hours))
        except KeyboardInterrupt:
            console.print("\n[yellow]Scheduler stopped[/yellow]")
    else:
        console.print(f"[green]Scheduled automatic updates every {hours} hours[/green]")
        console.print("[dim]Use --daemon flag to start the scheduler[/dim]")


@cli.command()
def version():
    """Show version and update information."""
    console.print(Panel.fit(
        "[bold cyan]OpenClaw Security Shield[/bold cyan]\n"
        "[dim]Version 1.0.0[/dim]",
        border_style="cyan"
    ))

    # Check for updates
    from .updater import AutoUpdater

    config = Config()
    updater = AutoUpdater(config)

    import asyncio
    updates = asyncio.run(updater.check_for_updates())

    if updates.get('software_update', {}).get('available'):
        console.print(f"[yellow]⚠ Update available: {updates['software_update']['latest']}[/yellow]")
        console.print(f"[dim]Run 'openclaw-shield update rules' to update[/dim]")
    else:
        console.print("[green]✓ Running latest version[/green]")


def _display_scan_result(result, verbose=False):
    """Display scan result for a single file."""
    risk_level = result.get('risk_level', 'UNKNOWN')
    risk_colors = {
        'CRITICAL': 'red',
        'HIGH': 'orange1',
        'MEDIUM': 'yellow',
        'LOW': 'green'
    }
    risk_color = risk_colors.get(risk_level, 'white')

    console.print(f"\n[bold]File:[/bold] {result.get('path', 'unknown')}")
    console.print(f"[bold]Risk Level:[/bold] [{risk_color}]{risk_level}[/{risk_color}]")
    console.print(f"[bold]Passed:[/bold] {'Yes' if result.get('passed') else 'No'}")

    if result.get('threats'):
        console.print(f"\n[red]Threats Detected ({len(result['threats'])}):[/red]")

        threat_table = Table()
        threat_table.add_column("Type", style="cyan")
        threat_table.add_column("Severity", style="red")
        threat_table.add_column("Message")

        for threat in result['threats']:
            threat_table.add_row(
                threat.get('type', 'unknown'),
                threat.get('severity', 'UNKNOWN'),
                threat.get('message', '')[:60]
            )

        console.print(threat_table)

    if result.get('recommendations'):
        console.print("\n[yellow]Recommendations:[/yellow]")
        for rec in result['recommendations']:
            console.print(f"  • {rec}")

    if verbose:
        if result.get('imports'):
            console.print(f"\n[dim]Imports: {', '.join(result['imports'][:10])}[/dim]")


def _display_scan_summary(results, verbose=False):
    """Display summary of scan results."""
    console.print(Panel.fit(
        "[bold cyan]Scan Summary[/bold cyan]",
        border_style="cyan"
    ))

    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Skills", str(results['total_skills']))
    table.add_row("Scanned", str(results['scanned']))
    table.add_row("Passed", str(results['passed']))
    table.add_row("Failed", str(results['failed']))
    table.add_row("Quarantined", str(results['quarantined']))

    console.print(table)

    if results['summary']['total_threats'] > 0:
        console.print(f"\n[red]Total Threats: {results['summary']['total_threats']}[/red]")

        threat_table = Table(title="Threat Breakdown")
        threat_table.add_column("Type", style="red")
        threat_table.add_column("Count", style="yellow")

        for threat_type, count in results['summary']['threat_breakdown'].items():
            threat_table.add_row(threat_type, str(count))

        console.print(threat_table)


def main():
    """Main entry point."""
    try:
        cli()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()
