import argparse
import os
import subprocess
import re
import sys
import shutil
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
# A list of essential command-line tools required for this script to run.
REQUIRED_TOOLS = [
    'subfinder', 'assetfinder', 'amass', 'findomain', 'httpx', 'aquatone',
    'katana', 'hakrawler', 'gau', 'waybackurls', 'gf', 'arjun', 'nuclei', 'ffuf'
]
# For tools that might not be installed (e.g., Shodan, GitHub), we'll warn instead of exiting.
OPTIONAL_TOOLS = ['shodan', 'github-subdomains']

# --- Helper Functions ---

class Bcolors:
    """A simple class for adding color to terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner(text):
    """Prints a formatted banner."""
    print(f"\n{Bcolors.HEADER}{'='*60}{Bcolors.ENDC}")
    print(f"{Bcolors.BOLD}{Bcolors.OKCYAN}{text.center(60)}{Bcolors.ENDC}")
    print(f"{Bcolors.HEADER}{'='*60}{Bcolors.ENDC}")

def run_command(cmd: str, description: str):
    """Runs a shell command, prints a description, and handles errors."""
    print(f"{Bcolors.OKBLUE}[*] Running: {description}{Bcolors.ENDC}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=False # Don't raise exception on non-zero exit code
        )
        if result.returncode != 0:
            print(f"{Bcolors.WARNING}[!] Warning for '{cmd}':\n{result.stderr}{Bcolors.ENDC}")
        return result.stdout
    except FileNotFoundError:
        tool_name = cmd.split()[0]
        print(f"{Bcolors.FAIL}[-] Error: Command '{tool_name}' not found. Please ensure it is installed and in your PATH.{Bcolors.ENDC}")
        return None
    except Exception as e:
        print(f"{Bcolors.FAIL}[-] An unexpected error occurred with command '{cmd}': {e}{Bcolors.ENDC}")
        return None

def check_tools():
    """Checks if all required tools are installed before running."""
    print_banner("Checking for Required Tools")
    missing_tools = []
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Bcolors.FAIL}[-] The following required tools are not installed or not in your PATH:")
        for tool in missing_tools:
            print(f"  - {tool}")
        print(f"{Bcolors.WARNING}Please install them to continue.{Bcolors.ENDC}")
        sys.exit(1)
        
    print(f"{Bcolors.OKGREEN}[+] All required tools are installed.{Bcolors.ENDC}")

def merge_and_unique_files(file_paths, output_file):
    """Reads multiple files, merges their content, and writes unique lines to an output file."""
    unique_lines = set()
    for file_path in file_paths:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                for line in f:
                    stripped_line = line.strip()
                    if stripped_line:
                        unique_lines.add(stripped_line)
    
    with open(output_file, 'w') as f:
        for line in sorted(list(unique_lines)):
            f.write(line + '\n')
    print(f"{Bcolors.OKGREEN}[+] Merged and deduplicated results into: {output_file}{Bcolors.ENDC}")


# --- Recon Functions ---

def discover_subdomains(domain, output_dir, shodan_api, github_token, sub_wordlist):
    """Runs various tools to discover subdomains concurrently."""
    print_banner("1. Discovering Subdomains")
    
    # Define commands to be run
    commands = {
        "Subfinder": f"subfinder -d {domain} -o {output_dir}/subfinder.txt -silent",
        "Assetfinder": f"assetfinder --subs-only {domain} > {output_dir}/assetfinder.txt",
        "Amass (Passive)": f"amass enum -passive -d {domain} -o {output_dir}/amass_passive.txt",
        "Findomain": f"findomain -t {domain} -u {output_dir}/findomain.txt"
    }
    
    # Run commands in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_command, cmd, desc) for desc, cmd in commands.items()]
        for future in futures:
            future.result() # Wait for all to complete
            
    # Conditional commands
    if shodan_api and shutil.which('shodan'):
        run_command(f"shodan init {shodan_api}", "Initializing Shodan")
        run_command(f"shodan domain {domain} > {output_dir}/shodan.txt", "Querying Shodan for subdomains")
    
    if github_token and shutil.which('github-subdomains'):
        run_command(f"github-subdomains -d {domain} -t {github_token} -o {output_dir}/github_subdomains.txt", "Enumerating GitHub for subdomains")

    # Merge results
    subdomain_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith('.txt')]
    merge_and_unique_files(subdomain_files, f"{output_dir}/all_subdomains.txt")


def find_live_hosts(domain, output_dir):
    """Uses httpx to find live hosts from the list of subdomains."""
    print_banner("2. Finding Live Hosts (HTTP/HTTPS Probing)")
    subdomain_file = f"{output_dir}/all_subdomains.txt"
    live_hosts_file = f"{output_dir}/live_hosts.txt"
    if os.path.exists(subdomain_file):
        run_command(f"httpx -l {subdomain_file} -o {live_hosts_file} -threads 50 -silent", "Probing for live hosts with httpx")
    else:
        print(f"{Bcolors.WARNING}[!] Subdomain file not found, skipping live host probing.{Bcolors.ENDC}")


def gather_urls(domain, output_dir):
    """Gathers URLs from live hosts and historical sources concurrently."""
    print_banner("3. Gathering URLs")
    live_hosts_file = f"{output_dir}/live_hosts.txt"
    
    if not os.path.exists(live_hosts_file):
        print(f"{Bcolors.WARNING}[!] Live hosts file not found, skipping URL gathering.{Bcolors.ENDC}")
        return
        
    commands = {
        "Katana": f"katana -l {live_hosts_file} -o {output_dir}/katana_urls.txt -silent",
        "Hakrawler": f"cat {live_hosts_file} | hakrawler -plain > {output_dir}/hakrawler_urls.txt",
        "Gau": f"gau {domain} > {output_dir}/gau_urls.txt",
        "Waybackurls": f"waybackurls {domain} > {output_dir}/wayback_urls.txt"
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_command, cmd, desc) for desc, cmd in commands.items()]
        for future in futures:
            future.result()
            
    url_files = [f"{output_dir}/katana_urls.txt", f"{output_dir}/hakrawler_urls.txt", f"{output_dir}/gau_urls.txt", f"{output_dir}/wayback_urls.txt"]
    merge_and_unique_files(url_files, f"{output_dir}/all_urls.txt")


def analyze_and_scan(output_dir, dir_wordlist):
    """Runs analysis and vulnerability scanning tools."""
    print_banner("4. Analysis & Vulnerability Scanning")
    all_urls_file = f"{output_dir}/all_urls.txt"
    live_hosts_file = f"{output_dir}/live_hosts.txt"
    
    if not os.path.exists(all_urls_file):
        print(f"{Bcolors.WARNING}[!] URL file not found, skipping analysis.{Bcolors.ENDC}")
        return

    # GF Patterns
    print(f"{Bcolors.OKBLUE}[*] Running GF patterns...{Bcolors.ENDC}")
    run_command(f"cat {all_urls_file} | gf xss > {output_dir}/gf_xss.txt", "Finding potential XSS with GF")
    run_command(f"cat {all_urls_file} | gf sqli > {output_dir}/gf_sqli.txt", "Finding potential SQLi with GF")
    run_command(f"cat {all_urls_file} | gf interestingparams > {output_dir}/gf_interesting_params.txt", "Finding interesting params with GF")
    
    # Parameter Discovery
    run_command(f"arjun -i {all_urls_file} -oJ {output_dir}/arjun_hidden_params.json", "Discovering hidden parameters with Arjun")

    # Nuclei Scan
    print(f"{Bcolors.OKBLUE}[*] Running Nuclei scan...{Bcolors.ENDC}")
    run_command("nuclei -update-templates -silent", "Updating Nuclei templates")
    run_command(f"nuclei -l {live_hosts_file} -o {output_dir}/nuclei_vulns.txt -c 50 -silent", "Scanning live hosts with Nuclei")
    
    # Directory Enumeration
    if os.path.exists(dir_wordlist) and os.path.exists(live_hosts_file):
        print(f"{Bcolors.OKBLUE}[*] Running directory enumeration with FFUF on first 5 hosts...{Bcolors.ENDC}")
        with open(live_hosts_file, 'r') as f:
            hosts = [host.strip() for host in f.readlines() if host.strip()]
        
        for host in hosts[:5]:
            host_safe_name = host.replace('://', '_').replace(':', '_')
            run_command(
                f"ffuf -w {dir_wordlist}:FUZZ -u {host}/FUZZ -mc 200,204,301,302,307,401,403 -o {output_dir}/ffuf_dir_{host_safe_name}.json -of json",
                f"Directory fuzzing on {host}"
            )
    else:
        print(f"{Bcolors.WARNING}[!] Directory wordlist '{dir_wordlist}' not found. Skipping FFUF scan.{Bcolors.ENDC}")

# --- Main Execution ---

def main():
    """Main function to parse arguments and orchestrate the recon process."""
    check_tools()
    
    parser = argparse.ArgumentParser(description="Automated Reconnaissance Tool for Bug Bounty Hunters.")
    parser.add_argument('-d', '--domain', required=True, help="Target domain (e.g., example.com)")
    parser.add_argument('-o', '--output', default=None, help="Output directory name (default: <domain>_recon)")
    parser.add_argument('--shodan-api', default=os.environ.get('SHODAN_API_KEY'), help="Shodan API key (or set SHODAN_API_KEY env var)")
    parser.add_argument('--github-token', default=os.environ.get('GITHUB_TOKEN'), help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument('--sub-wordlist', default=None, help="Path to wordlist for subdomain brute-forcing (not yet implemented)")
    parser.add_argument('--dir-wordlist', default='/usr/share/wordlists/dirb/common.txt', help="Path to wordlist for directory enumeration")

    args = parser.parse_args()
    
    domain = args.domain
    output_dir = args.output if args.output else f"{domain}_recon"
    os.makedirs(output_dir, exist_ok=True)
    
    print_banner(f"Starting Reconnaissance on: {domain}")
    
    # Run the recon workflow
    discover_subdomains(domain, output_dir, args.shodan_api, args.github_token, args.sub_wordlist)
    find_live_hosts(domain, output_dir)
    # Optional: Visual Recon
    # run_command(f"cat {output_dir}/live_hosts.txt | aquatone -out {output_dir}/aquatone", "Running Aquatone for visual recon")
    gather_urls(domain, output_dir)
    analyze_and_scan(output_dir, args.dir_wordlist)
    
    print_banner(f"Recon completed! Results are in '{output_dir}'")

if __name__ == "__main__":
    main()
