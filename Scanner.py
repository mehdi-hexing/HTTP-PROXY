import requests
import concurrent.futures
import time
import csv
import os

TARGET_URL = 'http://clients3.google.com/generate_204'
TIMEOUT = 10
MAX_THREADS = 50
MAX_POOL_SIZE = 3000

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

PROTOCOLS = ['http', 'socks4', 'socks5']

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

def clean_proxy_string(proxy):
    proxy = proxy.strip()
    proxy_lower = proxy.lower()
    for prefix in ['http://', 'https://', 'socks4://', 'socks5://']:
        if proxy_lower.startswith(prefix):
            return proxy[len(prefix):]
    return proxy

def get_proxy_metadata(ip):
    default_metadata = {
        "country": "Unknown",
        "country_code": "N/A",
        "flag": "🏳️",
        "fraud_score": "N/A",
        "risk": "Unknown",
        "vpn": "Unknown",
        "isp": "Unknown"
    }
    
    def fetch_API(url):
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            if response.status_code == 200:
                data = response.json()
                info = data.get("info", {})
                details = data.get("details", {})
                country = details.get("country", "Unknown")
                if country != "Unknown" and country:
                    return {
                        "country": country,
                        "country_code": details.get("country_code", "N/A"),
                        "flag": details.get("flag", "🏳️"),
                        "fraud_score": info.get("fraud_score", "N/A"),
                        "risk": info.get("risk", "Unknown"),
                        "vpn": details.get("vpn", "Unknown"),
                        "isp": details.get("isp", "Unknown")
                    }
        except Exception:
            pass
        return None

    primary_url = f"https://cloudflare-scamalytics.pages.dev/{ip}"
    result = fetch_API(primary_url)
    if result:
        return result

    fallback_url = f"https://cf-scamalytics.mehdismart88.workers.dev/{ip}"
    result = fetch_API(fallback_url)
    if result:
        return result

    return default_metadata

def check_proxy(proxy, protocol):
    cleaned_proxy = clean_proxy_string(proxy)
    if not cleaned_proxy:
        return None

    if protocol == 'socks5':
        proxy_url = f"socks5://{cleaned_proxy}"
    elif protocol == 'socks4':
        proxy_url = f"socks4://{cleaned_proxy}"
    else:
        proxy_url = f"http://{cleaned_proxy}"

    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

    try:
        start_time = time.time()
        response = requests.get(
            TARGET_URL, 
            proxies=proxies, 
            headers=HEADERS, 
            timeout=TIMEOUT, 
            allow_redirects=False
        )
        if response.status_code in [200, 204]:
            elapsed = time.time() - start_time
            print(f"{GREEN}[SUCCESS] [{protocol.upper()}]{RESET} {cleaned_proxy} - {elapsed:.2f}s")
            ip = cleaned_proxy.split(':')[0]
            metadata = get_proxy_metadata(ip)
            return {
                "proxy": cleaned_proxy,
                "protocol": protocol,
                **metadata
            }
    except Exception:
        pass
    return None

def fetch_proxies(protocol):
    print(f"{CYAN}Fetching {protocol.upper()} proxy list from ProxyScrape...{RESET}")
    url = f"https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol={protocol}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            proxies = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"{GREEN}Successfully fetched {len(proxies)} {protocol.upper()} proxies.{RESET}")
            return proxies
    except Exception:
        pass
    return []

def sort_key(item):
    country = item.get("country", "Unknown")
    try:
        fraud_score = int(item.get("fraud_score", 101))
    except (ValueError, TypeError):
        fraud_score = 101
    return (country, fraud_score)

def process_protocol(protocol, proxy_list):
    print(f"\n{YELLOW}--- Starting {protocol.upper()} Proxy Verification ---{RESET}")
    if not proxy_list:
        print(f"{RED}No {protocol.upper()} proxies available to check.{RESET}")
        return

    protocol_dir = os.path.join("proxies", "protocol", protocol)
    countries_dir = os.path.join("proxies", "countries", protocol)
    
    os.makedirs(protocol_dir, exist_ok=True)
    os.makedirs(countries_dir, exist_ok=True)

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_proxy, proxy, protocol): proxy for proxy in proxy_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=sort_key)

    global_txt = os.path.join(protocol_dir, "all.txt")
    global_csv = os.path.join(protocol_dir, "all.csv")

    with open(global_txt, 'w', encoding='utf-8') as f:
        for item in results:
            f.write(item["proxy"] + '\n')

    with open(global_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Proxy", "Protocol", "Country", "Country Code", "Flag", "Fraud Score", "Risk", "VPN", "ISP"])
        for item in results:
            writer.writerow([
                item["proxy"],
                item["protocol"].upper(),
                item["country"],
                item["country_code"],
                item["flag"],
                item["fraud_score"],
                item["risk"],
                item["vpn"],
                item["isp"]
            ])

    by_country = {}
    for item in results:
        cc = str(item.get("country_code", "UNKNOWN")).strip().upper()
        if cc in ["N/A", "", "NONE"]:
            cc = "UNKNOWN"
        if cc not in by_country:
            by_country[cc] = []
        by_country[cc].append(item)

    for cc, items in by_country.items():
        txt_file = os.path.join(countries_dir, f"{cc}.txt")
        csv_file = os.path.join(countries_dir, f"{cc}.csv")

        with open(txt_file, 'w', encoding='utf-8') as f:
            for item in items:
                f.write(item["proxy"] + '\n')

        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Proxy", "Protocol", "Country", "Country Code", "Flag", "Fraud Score", "Risk", "VPN", "ISP"])
            for item in items:
                writer.writerow([
                    item["proxy"],
                    item["protocol"].upper(),
                    item["country"],
                    item["country_code"],
                    item["flag"],
                    item["fraud_score"],
                    item["risk"],
                    item["vpn"],
                    item["isp"]
                ])

    print(f"{BLUE}Finished {protocol.upper()} checks. Found {len(results)} live proxies.{RESET}")

def main():
    print(f"{YELLOW}Initializing Proxies Scan...{RESET}")
    print(f"{CYAN}=== Start Fetching ==={RESET}")
    
    pool_dir = "Raw_Sources"
    os.makedirs(pool_dir, exist_ok=True)
    
    fetched_data = {}
    for proto in PROTOCOLS:
        pool_file = os.path.join(pool_dir, f"raw_{proto}.txt")
        
        existing_pool = []
        if os.path.exists(pool_file):
            with open(pool_file, 'r', encoding='utf-8') as f:
                existing_pool = [line.strip() for line in f if line.strip()]
        
        new_proxies = fetch_proxies(proto)
        
        if new_proxies:
            merged_dict = {p: True for p in existing_pool}
            for p in new_proxies:
                merged_dict[p] = True
            merged_pool = list(merged_dict.keys())
            
            if len(merged_pool) > MAX_POOL_SIZE:
                merged_pool = merged_pool[-MAX_POOL_SIZE:]
                
            with open(pool_file, 'w', encoding='utf-8') as f:
                for p in merged_pool:
                    f.write(p + '\n')
            
            fetched_data[proto] = merged_pool
        else:
            print(f"{YELLOW}API unavailable. Scanning existing raw {proto.upper()} proxies from local cache...{RESET}")
            fetched_data[proto] = existing_pool
            
    print(f"\n{CYAN}=== Start Scanning ==={RESET}")
    for proto in PROTOCOLS:
        process_protocol(proto, fetched_data[proto])

if __name__ == "__main__":
    main()
