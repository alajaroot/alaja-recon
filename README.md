# alaja-recon
automated recon tools

How to Use :


Install Tools: Make sure all the tools listed in REQUIRED_TOOLS are installed and accessible in your shell's PATH.


REQUIRED_TOOLS = [
    'subfinder', 'assetfinder', 'amass', 'findomain', 'httpx', 'aquatone',
    'katana', 'hakrawler', 'gau', 'waybackurls', 'gf', 'arjun', 'nuclei', 'ffuf'
]


Set API Keys (Optional but Recommended):

Bash
export SHODAN_API_KEY="your_shodan_key"
export GITHUB_TOKEN="your_github_token"
Run it:

Bash
python3 alaja-recon.py -d example.com 
You can also specify an output directory:

Bash
python3 alaja-recon.py -d example.com -o /path/to/output
