import certstream
import requests
import urllib3
import dns.resolver
import shodan

def check_url_accessibility(url):
    try:
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            return False
    except:
        return False


def get_ip_address(hostname):
    resolver = dns.resolver.Resolver()
    answers = resolver.resolve(hostname, "A")
    for rdata in answers:
        return str(rdata.address)

def check_open_ports(ip):
    api_key = "SHODAN KEY"
    api = shodan.Shodan(api_key)
    try:
        host = api.host(ip)
        open_ports = []
        for item in host['data']:
            open_ports.append(item['port'])
        return open_ports
    except shodan.APIError as e:
        print(f"Error: {e}")
        return None

def check_url_accessibility(url):
    try:
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            return False
    except:
        return False

def on_message(message, context):
    domains = message['data']['leaf_cert']['all_domains']
    for domain in domains:
        if "cdn" in domain:
            color = "\033[36m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "api" in domain:
            color = "\033[33m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "dev" in domain:
            color = "\033[35m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "s3" in domain:
            color = "\033[31m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "ftp" in domain:
            color = "\033[32m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "cloud" in domain:
            color = "\033[34m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "archive" in domain:
            color = "\033[37m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "db" in domain:
            color = "\033[90m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "content" in domain:
            color = "\033[94m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "dl" in domain:
            color = "\033[96m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        elif "sql" in domain:
            color = "\033[93m"
            url = f"https://{domain}"
            if check_url_accessibility(url):
                print(f"{color}{url}\033[0m is accessible.")
                ip = get_ip_address(domain)
                if ip:
                    open_ports = check_open_ports(ip)
                    if open_ports:
                        for port in open_ports:
                            with open(f"port_{port}.txt", "a") as f:
                                f.write(f"{domain}  {ip}\n")
                        print(f"{url} ({ip}) has open ports: {open_ports}")
        else:
            pass
        

certstream.listen_for_events(on_message, url="wss://certstream.calidog.io/")
