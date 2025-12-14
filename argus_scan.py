#!/usr/bin/env python3
"""
Shodan Pentest Automation - Ethical Pentest Automation
Author: ArgusScan
License: MIT
WARNING: Use only with written authorization (RoE). Unauthorized access is illegal.
"""

import sys
import json
import time
import argparse
import yaml
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from jinja2 import Template

try:
    import shodan
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
except ImportError as e:
    print(f"Error: Missing dependency. Run: pip install -r requirements.txt")
    print(f"   Details: {e}")
    sys.exit(1)

# Configuration
CONFIG_FILE = Path("config.yaml")
REPORTS_DIR = Path("reports")
TEMPLATE_FILE = Path("templates/pentest_report.md")

# Rate limiting Shodan (1 req/second)
SHODAN_RATE_LIMIT = 1.0
last_request_time = 0

console = Console()


def load_config(api_key: Optional[str] = None) -> Dict:
    """
    Loads configuration from config.yaml (fallback if token not provided)
    
    Args:
        api_key: Shodan token provided via CLI (takes priority)
    
    Returns:
        Dictionary with configuration
    """
    config = {}
    
    # If token provided via CLI, use it
    if api_key:
        config['shodan_api_key'] = api_key
        return config
    
    # Otherwise, try to load from config.yaml
    if not CONFIG_FILE.exists():
        console.print(f"[red]Error: Token not provided and file {CONFIG_FILE} not found![/red]")
        console.print(f"[yellow]Tip: Use --token YOUR_API_KEY or create config.yaml file[/yellow]")
        sys.exit(1)
    
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}
    
    if not config.get('shodan_api_key'):
        console.print("[red]Error: Token not provided and shodan_api_key not configured in config.yaml[/red]")
        console.print("[yellow]Tip: Use --token YOUR_API_KEY or configure in config.yaml[/yellow]")
        sys.exit(1)
    
    return config


def rate_limit():
    """Implements rate limiting for Shodan API"""
    global last_request_time
    current_time = time.time()
    elapsed = current_time - last_request_time
    
    if elapsed < SHODAN_RATE_LIMIT:
        time.sleep(SHODAN_RATE_LIMIT - elapsed)
    
    last_request_time = time.time()


def search_shodan(api: shodan.Shodan, query: str, filters: Optional[Dict] = None) -> List[Dict]:
    """
    Search hosts on Shodan with rate limiting
    
    Args:
        api: Shodan API instance
        query: Shodan query/dork (e.g., "vuln:CVE-2024-23897")
        filters: Additional filters (country, port, etc)
    
    Returns:
        List of found hosts
    """
    # Build complete query with filters
    full_query = query
    if filters:
        if filters.get('country'):
            full_query += f' country:"{filters["country"]}"'
        if filters.get('port'):
            full_query += f' port:{filters["port"]}'
    
    console.print(f"[cyan]Searching: {full_query}[/cyan]")
    
    try:
        rate_limit()
        results = api.search(full_query)
        
        hosts = []
        for result in results['matches']:
            host_data = {
                'ip': result.get('ip_str', 'N/A'),
                'hostnames': result.get('hostnames', []),
                'port': result.get('port', 'N/A'),
                'org': result.get('org', 'N/A'),
                'isp': result.get('isp', 'N/A'),
                'location': result.get('location', {}),
                'banner': result.get('data', 'N/A')[:500],  # First 500 chars
                'product': result.get('product', 'N/A'),
                'version': result.get('version', 'N/A'),
                'vulns': result.get('vulns', []),
                'timestamp': result.get('timestamp', 'N/A'),
                'shodan_link': f"https://www.shodan.io/host/{result.get('ip_str', '')}",
                'direct_link': f"http://{result.get('ip_str', '')}:{result.get('port', '')}" if result.get('port') else None
            }
            hosts.append(host_data)
        
        return hosts
    
    except shodan.APIError as e:
        console.print(f"[red]Shodan API Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)


def display_results_table(hosts: List[Dict], query: str):
    """Displays results in formatted table with Rich"""
    if not hosts:
        console.print("[yellow]Warning: No hosts found[/yellow]")
        return
    
    table = Table(title=f"Shodan Results: {query}", box=box.ROUNDED)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port", style="magenta")
    table.add_column("Organization", style="green")
    table.add_column("Product", style="yellow")
    table.add_column("Vulns", style="red")
    
    for host in hosts:
        vulns_str = ", ".join(list(host['vulns'].keys())[:3]) if host['vulns'] else "N/A"
        if len(host['vulns']) > 3:
            vulns_str += f" (+{len(host['vulns']) - 3})"
        
        table.add_row(
            host['ip'],
            str(host['port']),
            host['org'][:30] if len(host['org']) > 30 else host['org'],
            f"{host['product']} {host['version']}".strip()[:25],
            vulns_str
        )
    
    console.print(table)
    console.print(f"\n[green]Total: {len(hosts)} hosts found[/green]")


def generate_report(hosts: List[Dict], query: str, output_format: str = 'markdown'):
    """Generates report in Markdown or JSON"""
    if not hosts:
        console.print("[yellow]Warning: No hosts to generate report[/yellow]")
        return
    
    # Create reports directory
    REPORTS_DIR.mkdir(exist_ok=True)
    
    # File name based on query and timestamp
    safe_query = query.replace(':', '_').replace(' ', '_').replace('/', '_')[:50]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_format == 'json':
        # Export JSON
        json_file = REPORTS_DIR / f"shodan_{safe_query}_{timestamp}.json"
        report_data = {
            'query': query,
            'timestamp': datetime.now().isoformat(),
            'total_hosts': len(hosts),
            'hosts': hosts
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]JSON report saved: {json_file}[/green]")
        return json_file
    
    # Export Markdown with Jinja2 template
    if not TEMPLATE_FILE.exists():
        console.print(f"[yellow]Warning: Template not found, using basic template[/yellow]")
        markdown_content = generate_basic_markdown(hosts, query)
    else:
        with open(TEMPLATE_FILE, 'r', encoding='utf-8') as f:
            template = Template(f.read())
        
        # Extract CVE from query if present
        cve = 'N/A'
        if 'CVE-' in query.upper():
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', query.upper())
            if cve_match:
                cve = cve_match.group(0)
        
        markdown_content = template.render(
            query=query,
            cve=cve,
            hosts=hosts,
            total_hosts=len(hosts),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            date=datetime.now().strftime("%Y-%m-%d")
        )
    
    md_file = REPORTS_DIR / f"pentest_{safe_query}_{timestamp}.md"
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write(markdown_content)
    
    console.print(f"[green]Markdown report saved: {md_file}[/green]")
    return md_file


def generate_basic_markdown(hosts: List[Dict], query: str) -> str:
    """Generates basic Markdown if template doesn't exist"""
    cve = 'N/A'
    if 'CVE-' in query.upper():
        import re
        cve_match = re.search(r'CVE-\d{4}-\d+', query.upper())
        if cve_match:
            cve = cve_match.group(0)
    
    md = f"""# Ethical Pentest - {cve} - Shodan Report

## AUTHORIZATION REQUIRED

**LEGAL WARNING**: This report is for ethical security purposes. Penetration tests must be performed **ONLY** with written authorization (Rules of Engagement - RoE). 

Unauthorized access to computer systems is illegal and punishable by law in most jurisdictions.

**Use this report only for:**
- Authorized bug bounty
- Pentest with signed contract
- Authorized academic research
- Own defensive security

---

## Executive Summary

- **Query/Dork**: `{query}`
- **Total Hosts**: {len(hosts)}
- **Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## Vulnerable Hosts

"""
    
    for i, host in enumerate(hosts, 1):
        md += f"""### Host {i}: {host['ip']}

| Campo | Valor |
|-------|-------|
| **IP/Hostname** | {host['ip']} ({', '.join(host['hostnames']) if host['hostnames'] else 'N/A'}) |
| **Port** | {host['port']} |
| **Organization** | {host['org']} |
| **ISP** | {host['isp']} |
| **Product/Version** | {host['product']} {host['version']} |
| **Vulnerabilities** | {', '.join(list(host['vulns'].keys())) if host['vulns'] else 'N/A'} |
| **Shodan Link** | {host['shodan_link']} |
| **Direct Link** | {host['direct_link'] if host['direct_link'] else 'N/A'} |

#### Banner/Technical Summary
```
{host['banner'][:500]}
```

#### Pentest Phase (PTES/OWASP)

| PHASE | STEPS | TOOLS |
|------|--------|-------------|
| **Passive Recon** | 1. WHOIS<br>2. Banner grab<br>3. Shodan/OSINT | `nmap -sV -T1 {host['ip']}`<br>`whois {host['ip']}` |
| **Validation** | 1. Non-invasive PoC<br>2. CVE verification | `nuclei -u {host['direct_link']} -t cves/{cve}`<br>`curl -I {host['direct_link']}` |
| **Exploit*** | 1. GitHub PoC<br>2. Metasploit module | `python3 exploit.py {host['ip']}`<br>`msfconsole -x "use exploit/...; set RHOSTS {host['ip']}"` |
| **Report** | 1. CVSS Score<br>2. Mitigation<br>3. Remediation | WriteHat/Markdown<br>OWASP Risk Rating |

*WARNING: **ONLY WITH WRITTEN AUTHORIZATION (RoE)**

---

"""
    
    md += f"""## PTES/OWASP Methodology

This report follows the phases of **Penetration Testing Execution Standard (PTES)** and **OWASP Testing Guide**:

1. **Pre-engagement** - Scope definition and RoE
2. **Intelligence Gathering** - Passive recon (Shodan, OSINT)
3. **Threat Modeling** - Threat identification
4. **Vulnerability Analysis** - CVE analysis
5. **Exploitation** - Exploitation tests (WITH AUTHORIZATION)
6. **Post-Exploitation** - Impact analysis
7. **Reporting** - Documentation and mitigation

---

## Security Recommendations

1. **Immediate Update**: Apply patches for {cve}
2. **Firewall**: Restrict access to exposed ports
3. **Monitoring**: Implement SIEM/SOC
4. **Hardening**: Follow OWASP/CIS guidelines
5. **Bug Bounty**: Consider rewards program

---

## References

- [Shodan](https://www.shodan.io)
- [CVE Details](https://www.cvedetails.com/cve/{cve}/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES](http://www.pentest-standard.org/)

---

**Generated by**: ArgusScan - Shodan Pentest Automation
**License**: MIT
**Usage**: Only for ethical and authorized purposes
"""
    
    return md


def export_csv(hosts: List[Dict], query: str):
    """Exports results to CSV (compatible with Nuclei/OWASP ZAP)"""
    import csv
    
    REPORTS_DIR.mkdir(exist_ok=True)
    safe_query = query.replace(':', '_').replace(' ', '_').replace('/', '_')[:50]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = REPORTS_DIR / f"shodan_{safe_query}_{timestamp}.csv"
    
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Port', 'Hostname', 'Org', 'Product', 'Version', 'Vulns', 'Shodan_Link', 'Direct_Link'])
        
        for host in hosts:
            hostnames = ', '.join(host['hostnames']) if host['hostnames'] else 'N/A'
            vulns = ', '.join(list(host['vulns'].keys())) if host['vulns'] else 'N/A'
            writer.writerow([
                host['ip'],
                host['port'],
                hostnames,
                host['org'],
                host['product'],
                host['version'],
                vulns,
                host['shodan_link'],
                host['direct_link'] or 'N/A'
            ])
    
    console.print(f"[green]CSV exported: {csv_file}[/green]")
    return csv_file


def main():
    parser = argparse.ArgumentParser(
        description='Shodan Pentest Automation - Ethical Pentest Automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python argus_scan.py "vuln:CVE-2024-23897" --token YOUR_API_KEY
  python argus_scan.py "jenkins port:8080" --token YOUR_API_KEY --country BR
  python argus_scan.py "php-cgi" --token YOUR_API_KEY --port 80,443 --export csv
  python argus_scan.py "apache" --token YOUR_API_KEY --country BR --export json

Useful dorks:
  vuln:CVE-2024-23897          # Search for specific CVE
  jenkins port:8080            # Jenkins on port 8080
  php-cgi port:80              # Exposed PHP-CGI
  apache country:BR            # Apache in Brazil
  "Microsoft IIS" port:80      # IIS on port 80
        """
    )
    
    parser.add_argument('query', help='Shodan Query/Dork (e.g., "vuln:CVE-2024-23897")')
    parser.add_argument('--token', '-t', required=True, help='Shodan Token/API Key (required)')
    parser.add_argument('--country', '-c', help='Filter by country (e.g., BR, US)')
    parser.add_argument('--port', '-p', help='Filter by port (e.g., 80,443,8080)')
    parser.add_argument('--export', '-e', choices=['json', 'csv', 'both'], default='markdown',
                       help='Export format (json, csv, both)')
    parser.add_argument('--no-table', action='store_true', help='Do not display results table')
    parser.add_argument('--limit', '-l', type=int, default=100, help='Result limit (default: 100)')
    
    args = parser.parse_args()
    
    # Banner and legal warning
    console.print(Panel.fit(
        "[bold red]LEGAL WARNING[/bold red]\n\n"
        "This tool is for ethical security purposes.\n"
        "Use ONLY with written authorization (RoE).\n"
        "Unauthorized access is illegal.\n\n"
        "[cyan]ArgusScan - Shodan Pentest Automation[/cyan]",
        border_style="red"
    ))
    
    # Load configuration (CLI token takes priority)
    config = load_config(api_key=args.token)
    
    # Initialize Shodan API
    try:
        api = shodan.Shodan(config['shodan_api_key'])
    except Exception as e:
        console.print(f"[red]Error initializing Shodan API: {e}[/red]")
        sys.exit(1)
    
    # Filters
    filters = {}
    if args.country:
        filters['country'] = args.country
    if args.port:
        filters['port'] = args.port
    
    # Search hosts
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Searching hosts on Shodan...", total=None)
        hosts = search_shodan(api, args.query, filters if filters else None)
        progress.update(task, completed=True)
    
    # Limit results
    if len(hosts) > args.limit:
        hosts = hosts[:args.limit]
        console.print(f"[yellow]Warning: Limited to {args.limit} results[/yellow]")
    
    # Display table
    if not args.no_table:
        display_results_table(hosts, args.query)
    
    # Generate reports
    if args.export in ['json', 'both']:
        generate_report(hosts, args.query, 'json')
    
    if args.export in ['csv', 'both']:
        export_csv(hosts, args.query)
    
    if args.export == 'markdown' or args.export == 'both':
        generate_report(hosts, args.query, 'markdown')
    
    console.print("\n[bold green]Analysis completed![/bold green]")
    console.print("[yellow]Remember: Use results only with written authorization[/yellow]")


if __name__ == '__main__':
    main()

