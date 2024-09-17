import shodan
import subprocess
import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import re

# Color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BLUE = '\033[34m'  # Blue
LIGHT_BLUE = '\033[94m'  # Light Blue

def print_colored(message, color):
    print(f"{color}{message}{RESET}")

# File containing the Shodan API key
API_KEY_FILE = 'shodan_key.md'

# Function to read the Shodan API key from the file
def read_shodan_api_key():
    try:
        with open(API_KEY_FILE, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        print_colored(f"API key file '{API_KEY_FILE}' not found.", RED)
        exit(1)
    except Exception as e:
        print_colored(f"Error reading API key: {e}", RED)
        exit(1)

SHODAN_API_KEY = read_shodan_api_key()

def shodan_search(target_domain):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.search(target_domain)
        total = results.get('total', 0)
        if total > 0:
            print_colored(f"Shodan search results: Total = {total}", RED)
        else:
            print_colored("Shodan search results: Total = 0", LIGHT_BLUE)
        return results
    except shodan.APIError as e:
        print_colored(f"Error running Shodan search: {e}", RED)
        return None

def extract_ips(shodan_results):
    ips = [result['ip_str'] for result in shodan_results.get('matches', [])]
    return ips

def get_title_from_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else 'No title'
        return f"{GREEN}Found Title: {title}{RESET}"
    except requests.RequestException:
        return f"{RED}Forbidden or Blocked!{RESET}"

def check_ips_with_httprobe(ip_file):
    try:
        with open(ip_file, 'r') as file:
            ips = file.read().splitlines()

        process = subprocess.Popen(['httprobe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input='\n'.join(ips))
        
        urls = []
        if stdout:
            urls = stdout.splitlines()
            print_colored("\nURLs and Titles:", GREEN)
            for url in urls:
                title = get_title_from_url(url)
                print(f"{url} - {title}")
        if stderr:
            print_colored(f"Error running httprobe: {stderr}", RED)
        return urls
    except subprocess.CalledProcessError as e:
        print_colored(f"Error running httprobe: {e}", RED)
        return []

def sanitize_filename(filename):
    return re.sub(r'[<>:"/\\|?*]', '_', filename)

def process_single_target(target_domain):
    sanitized_domain = sanitize_filename(target_domain)
    shodan_results = shodan_search(target_domain)
    if shodan_results:
        total = shodan_results.get('total', 0)
        if total > 0:
            ips = extract_ips(shodan_results)
            if ips:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                folder = 'temp'
                os.makedirs(folder, exist_ok=True)
                filename = os.path.join(folder, f'{sanitized_domain}_ips_{timestamp}.txt')
                with open(filename, 'w') as f:
                    for ip in ips:
                        f.write(f"{ip}\n")
                print_colored(f"\nIP addresses for domain '{target_domain}' written to '{filename}'", GREEN)
                urls = check_ips_with_httprobe(filename)
                
                # Save URLs and Titles
                if urls:
                    result_filename = os.path.join(folder, f'{sanitized_domain}_results_{timestamp}.txt')
                    with open(result_filename, 'w') as f:
                        for url in urls:
                            title = get_title_from_url(url)
                            f.write(f"{url} - {title}\n")
                    print_colored(f"Results saved to '{result_filename}'", GREEN)
                
                # Clean up temporary files
                os.remove(filename)
            else:
                print_colored(f"No IP addresses found for domain '{target_domain}'.", YELLOW)
        else:
            print_colored("No output from Shodan search.", YELLOW)
    else:
        print_colored("No output from Shodan search.", YELLOW)

def process_targets_from_file(file_path):
    if not os.path.isfile(file_path):
        print_colored(f"File {file_path} does not exist.", RED)
        return
    
    processed_targets = set()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    with open(file_path, 'r') as file:
        targets = file.readlines()
    
    for target in targets:
        target = target.strip()
        if target and target not in processed_targets:
            print_colored(f"\nProcessing target: {target}", GREEN)
            process_single_target(target)
            processed_targets.add(target)
    
    print_colored(f"Processed targets logged.", GREEN)

def perform_subdomain_enumeration(domain, output_folder):
    try:
        os.makedirs(output_folder, exist_ok=True)
        output_file = os.path.join(output_folder, f'subdomains_{datetime.now().strftime("%Y%m%d")}.txt')
        print_colored("Running subfinder...", YELLOW)
        subprocess.run(['subfinder', '-d', domain, '-o', output_file], check=True)
        print_colored(f"Subdomain enumeration results saved to '{output_file}'", GREEN)
    except subprocess.CalledProcessError as e:
        print_colored(f"Error during subdomain enumeration: {e}", RED)

def main():
    choice = input(
        f"{YELLOW}Choose an option:\n"
        "1. Single Target\n"
        "2. Mass Targets from a File\n"
        "3. Mass Targets on the Server\n"
        "Enter your choice: "
    ).strip()
    
    if choice == '1':
        target_domain = input(f"{YELLOW}Enter the target domain: {RESET}").strip()
        if not target_domain:
            print_colored("Target domain cannot be empty.", RED)
            return
        process_single_target(target_domain)
    elif choice == '2':
        file_path = input(f"{YELLOW}Enter the file path containing target domains: {RESET}").strip()
        process_targets_from_file(file_path)
    elif choice == '3':
        target_domain = input(f"{YELLOW}Enter the target domain for mass check on same server: {RESET}").strip()
        if not target_domain:
            print_colored("Target domain cannot be empty.", RED)
            return
        
        output_folder = os.path.join('subdomain_target_' + sanitize_filename(target_domain))
        perform_subdomain_enumeration(target_domain, output_folder)
        process_targets_from_file(os.path.join(output_folder, f'subdomains_{datetime.now().strftime("%Y%m%d")}.txt'))
    else:
        print_colored("Invalid choice. Please enter '1', '2', or '3'.", RED)

if __name__ == "__main__":
    main()