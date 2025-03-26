#!/usr/bin/env python3
import argparse
import os
import sys
import time
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

from scanner.local_scanner import LocalScanner
from scanner.github_scanner import GitHubScanner
from scanner.advanced_scanner import AdvancedScanner
from utils.logger import setup_logger, get_logger
from utils.config import get_config

# Import Flask app for web interface
try:
    from app import app
except ImportError:
    app = None

# Set up the logger
setup_logger()
logger = get_logger()
console = Console()

# Get configuration
config = get_config()

def parse_arguments():
    """Parse command line arguments."""
    # Get default values from config
    default_output_dir = config.get('scanner', 'output_dir')
    default_report_format = config.get('scanner', 'report_format')
    default_enable_call_graph = config.get('scanner', 'enable_call_graph')
    default_scan_secrets = config.get('scanner', 'enable_secrets_scan')
    
    parser = argparse.ArgumentParser(
        description='ZeroHuntAI - AI-powered Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan of a local directory
  python main.py --mode local --path /path/to/code

  # Basic scan of a GitHub repository
  python main.py --mode github --repo https://github.com/target/repo.git

  # Advanced scan with all features
  python main.py --mode local --path /path/to/code --advanced --scan-deps --enable-symbolic 
                 --enable-trace-graph --simulate-exploits

  # Advanced scan with specific file types
  python main.py --mode local --path /path/to/code --advanced --languages py,js,php

  # Generate a PDF report
  python main.py --mode local --path /path/to/code --report-format pdf

  # View/modify configuration
  python main.py --create-config
  python main.py --view-config
        '''
    )
    
    # Create mutually exclusive groups
    mode_group = parser.add_argument_group('Scan Mode')
    config_group = parser.add_argument_group('Configuration')
    scan_group = parser.add_argument_group('Scan Settings')
    
    # Main mode arguments
    mode_group.add_argument('--mode', choices=['local', 'github'],
                        help='Scan mode: local directory or GitHub repository')
    mode_group.add_argument('--path', help='Path to local code directory (for local mode)')
    mode_group.add_argument('--repo', help='URL of GitHub repository (for github mode)')
    
    # Configuration arguments
    config_group.add_argument('--create-config', action='store_true',
                        help='Create a default configuration file')
    config_group.add_argument('--view-config', action='store_true',
                        help='View current configuration settings')
    
    # Scan settings arguments
    scan_group.add_argument('--output-dir', default=default_output_dir,
                        help=f'Directory to store scan results (default: {default_output_dir})')
    scan_group.add_argument('--report-format', choices=['json', 'html', 'both', 'pdf'], 
                        default=default_report_format, help=f'Report format (default: {default_report_format})')
    scan_group.add_argument('--languages', 
                        help='Comma-separated list of file extensions to scan (default: all supported)')
    scan_group.add_argument('--enable-call-graph', action='store_true', default=default_enable_call_graph,
                        help='Enable call graph generation (experimental)')
    scan_group.add_argument('--enable-trace-graph', action='store_true', 
                        help='Enable vulnerability trace graph generation (advanced)')
    scan_group.add_argument('--advanced', '-a', action='store_true',
                        help='Use advanced scanning techniques (AST, data flow, symbolic execution)')
    scan_group.add_argument('--scan-deps', action='store_true',
                        help='Enable scanning of third-party dependencies (advanced)')
    scan_group.add_argument('--enable-symbolic', action='store_true',
                        help='Enable symbolic execution for vulnerability validation (advanced)')
    scan_group.add_argument('--max-files', type=int, default=10000,
                        help='Maximum number of files to scan (default: 10000)')
    scan_group.add_argument('--simulate-exploits', action='store_true',
                        help='Simulate exploits for discovered vulnerabilities (advanced)')
    scan_group.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    scan_group.add_argument('--skip-secret-scan', action='store_true', default=not default_scan_secrets,
                        help='Skip scanning for secrets in code')
    scan_group.add_argument('--search-pattern', 
                        help='Search for a specific pattern or function in code')
    scan_group.add_argument('--exclude-pattern', 
                        help='Exclude files containing a specific pattern from scan')
    scan_group.add_argument('--search-functions', 
                        help='Comma-separated list of function names to specifically search for')

    args = parser.parse_args()
    
    # Handle special configuration commands
    if args.create_config:
        return args
    
    if args.view_config:
        return args

    # Validate scan mode arguments
    if not args.mode:
        parser.error("--mode is required unless using --create-config or --view-config")
        
    if args.mode == 'local' and not args.path:
        parser.error("--path is required when mode is 'local'")
    if args.mode == 'github' and not args.repo:
        parser.error("--repo is required when mode is 'github'")

    return args

def display_banner():
    """Display the tool banner."""
    banner = """
    ███████╗███████╗██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ █████╗ ██╗
    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔══██╗██║
      ███╔╝ █████╗  ██████╔╝██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   ███████║██║
     ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══██║██║
    ███████╗███████╗██║  ██║╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║  ██║██║
    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝                                                                                
    """
    console.print(Panel(banner, title="[bold green]ZeroHuntAI[/bold green]", 
                  subtitle="[bold]AI-powered Vulnerability Scanner[/bold]"))
    console.print("\n[bold cyan]Version 1.0.0[/bold cyan] | [bold]https://github.com/zerohuntai/zerohuntai[/bold]\n")

def display_config(conf):

    console.print("\n[bold]Current Configuration Settings:[/bold]\n")
    
    # Create a table for each section
    for section_name, section in conf.export_config().items():
        table = Table(title=f"[bold]{section_name.upper()}[/bold]", show_header=True, header_style="bold cyan")
        table.add_column("Setting", style="dim")
        table.add_column("Value")
        
        for key, value in section.items():
            # Format complex values
            if isinstance(value, (list, dict)):
                value = json.dumps(value, indent=2)
            elif isinstance(value, bool):
                value = "✓ Enabled" if value else "✗ Disabled"
                
            table.add_row(key, str(value))
            
        console.print(table)
        console.print("")
    
    console.print(f"[dim]Configuration file: {conf._config_file}[/dim]\n")

def main():
    """Main function to run the scanner."""
    # Display banner
    display_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    # Handle configuration commands
    if args.create_config:
        if config.create_default_config_file():
            console.print("\n[green]✓[/green] Default configuration file created at: "
                         f"[bold]{config._config_file}[/bold]")
            console.print("[dim]You can now edit this file to customize ZeroHuntAI.[/dim]")
        else:
            console.print("\n[bold red]✗[/bold red] Configuration file already exists. "
                         "Use --view-config to view current settings.")
        return 0
        
    if args.view_config:
        display_config(config)
        return 0
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Set up language filters
    languages = None
    if args.languages:
        languages = [f".{ext.strip()}" for ext in args.languages.split(',')]
    
    # Start scanning
    start_time = time.time()
    
    try:
        target_path = args.path if args.mode == 'local' else args.repo
        scan_mode = args.mode
        
        # Determine if we should use the advanced scanner
        use_advanced = args.advanced or args.scan_deps or args.enable_symbolic or args.simulate_exploits
        
        if use_advanced:
            # Use advanced scanner
            if scan_mode == 'local':
                console.print(f"\n[bold]Advanced scanning of local directory:[/bold] {target_path}")
            else:
                console.print(f"\n[bold]Advanced scanning of GitHub repository:[/bold] {target_path}")
                
            scanner = AdvancedScanner(
                target_path, 
                output_dir=args.output_dir,
                language_extensions=languages,
                verbose=args.verbose,
                scan_secrets=(not args.skip_secret_scan),
                enable_call_graph=args.enable_call_graph,
                scan_mode=scan_mode,
                scan_deps=args.scan_deps,
                enable_symbolic=args.enable_symbolic,
                max_files=args.max_files
            )
        else:
            # Use regular scanners
            if scan_mode == 'local':
                # Local directory scan
                console.print(f"\n[bold]Scanning local directory:[/bold] {target_path}")
                scanner = LocalScanner(
                    target_path, 
                    output_dir=args.output_dir,
                    language_extensions=languages,
                    verbose=args.verbose,
                    scan_secrets=(not args.skip_secret_scan),
                    enable_call_graph=args.enable_call_graph
                )
            else:
                # GitHub repository scan
                console.print(f"\n[bold]Scanning GitHub repository:[/bold] {target_path}")
                scanner = GitHubScanner(
                    target_path, 
                    output_dir=args.output_dir,
                    language_extensions=languages,
                    verbose=args.verbose,
                    scan_secrets=(not args.skip_secret_scan),
                    enable_call_graph=args.enable_call_graph
                )
        
        # Start scanning (the scanner has its own progress display)
        console.print("\n[cyan]Starting scan...[/cyan]")
        scan_result = scanner.scan()
        
        # Generate reports
        if args.report_format in ['json', 'both']:
            json_path = scanner.generate_report(format='json')
            console.print(f"\n[green]✓[/green] JSON report saved to: [bold]{json_path}[/bold]")
            
        if args.report_format in ['html', 'both']:
            html_path = scanner.generate_report(format='html')
            console.print(f"[green]✓[/green] HTML report saved to: [bold]{html_path}[/bold]")
        
        if args.report_format in ['pdf']:
            pdf_path = scanner.generate_report(format='pdf')
            console.print(f"[green]✓[/green] PDF report saved to: [bold]{pdf_path}[/bold]")
            
        # Generate call graph if enabled
        if args.enable_call_graph:
            graph_path = scanner.generate_call_graph()
            if graph_path:
                console.print(f"[green]✓[/green] Call graph visualization saved to: [bold]{graph_path}[/bold]")
        
        # Generate trace graph for advanced scanning if enabled
        if use_advanced and args.enable_trace_graph:
            trace_path = scanner.generate_trace_graph()
            if trace_path:
                console.print(f"[green]✓[/green] Vulnerability trace graph saved to: [bold]{trace_path}[/bold]")
        
        # Simulate exploits if requested
        if use_advanced and args.simulate_exploits:
            console.print("\n[bold]Simulating exploits for discovered vulnerabilities...[/bold]")
            exploit_results = scanner.simulate_exploits()
            
            if exploit_results.get('simulation_count', 0) > 0:
                console.print(f"[yellow]⚠️[/yellow] Generated {exploit_results['simulation_count']} exploit proof-of-concepts")
            else:
                console.print("[green]✓[/green] No exploitable vulnerabilities identified")
                    
        # Print summary
        elapsed_time = time.time() - start_time
        console.print(f"\n[bold]Scan completed in[/bold] {elapsed_time:.2f} seconds")
        
        # Print more detailed summary for advanced scanning
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"- Files scanned: [bold]{scan_result['stats']['total_files']}[/bold]")
        
        # Add critical vulnerabilities if available
        if 'critical_severity' in scan_result['stats']:
            console.print(f"- Critical severity vulnerabilities: [bold red]{scan_result['stats']['critical_severity']}[/bold red]")
            
        console.print(f"- High severity vulnerabilities: [bold red]{scan_result['stats']['high_severity']}[/bold red]")
        console.print(f"- Medium severity vulnerabilities: [bold yellow]{scan_result['stats']['medium_severity']}[/bold yellow]")
        console.print(f"- Low severity vulnerabilities: [bold cyan]{scan_result['stats']['low_severity']}[/bold cyan]")
        
        # Print advanced scan stats if available
        if use_advanced:
            if 'analysis_coverage' in scan_result:
                coverage = scan_result['analysis_coverage']
                console.print(f"\n[bold]Analysis Coverage:[/bold]")
                console.print(f"- AST Analysis: [bold]{coverage['ast_analysis']}[/bold] files")
                console.print(f"- Data Flow Analysis: [bold]{coverage['dataflow_analysis']}[/bold] files")
                console.print(f"- Control Flow Analysis: [bold]{coverage['controlflow_analysis']}[/bold] files")
                
                if args.enable_symbolic:
                    console.print(f"- Symbolic Execution: [bold]{coverage['symbolic_execution']}[/bold] files")
                
                if args.scan_deps:
                    console.print(f"- Dependency Analysis: [bold]{'Completed' if coverage['dependency_analysis'] > 0 else 'None'}[/bold]")
                
                console.print(f"- Custom Queries: [bold]{coverage['custom_queries']}[/bold] executed")
        
        # Show warning for high severity vulnerabilities
        if scan_result['stats'].get('critical_severity', 0) > 0:
            console.print("\n[bold red]⚠️ Critical severity vulnerabilities found! Immediate attention required.[/bold red]")
        elif scan_result['stats']['high_severity'] > 0:
            console.print("\n[bold red]⚠️ High severity vulnerabilities found! Immediate attention required.[/bold red]")
        
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        logger.exception("An error occurred during scanning")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
