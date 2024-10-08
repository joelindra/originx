![image](https://github.com/user-attachments/assets/4ff5e0dc-fcc8-41c7-b132-240337020273)

## Shodan Origin IP Recon
This tool combines Shodan search functionality with subdomain enumeration and target validation using httprobe. The primary goal is to automate the process of gathering IP addresses and checking live URLs for domains, enabling security researchers and penetration testers to streamline their reconnaissance efforts.

## Features
- Shodan Search Integration: Leverages Shodan API to search for a domain and extract associated IP addresses.
- Subdomain Enumeration: Automates subdomain discovery using subfinder, with results saved for further processing.
- URL Validation: Uses httprobe to check which IP addresses or domains are live, and automatically fetches the page titles for each validated URL.

## Flexible Target Input: 
### Supports:
- Single target domain input.
- Mass target input from a file.
- Mass target by enumerate subdomain from inputed target

## Installation
Ensure you have the necessary dependencies installed:

- Python 3.x
- Shodan API
- httprobe for live URL probing.
- subfinder for subdomain enumeration.
- Requests and BeautifulSoup Python libraries.
- pip install shodan requests beautifulsoup4
- go install github.com/tomnomnom/httprobe@latest
- go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# API Key Setup
To use this tool, you'll need a valid Shodan API key. Save your API key in a file named shodan_key.md in the tool's directory.
