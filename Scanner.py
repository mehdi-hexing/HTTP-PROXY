import requests
import concurrent.futures
import time
import csv
import os
import qrcode

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

    fallback_url = f"https://cf-scamalytics.mehdismart.workers.dev/{ip}"
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
    sub_dir = os.path.join("proxies", "subscriptions")
    
    os.makedirs(protocol_dir, exist_ok=True)
    os.makedirs(countries_dir, exist_ok=True)
    os.makedirs(sub_dir, exist_ok=True)

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

    country_counters = {}
    mahsang_configs = []
    v2rayng_configs = []
    nekobox_configs = []

    for item in results:
        cc = str(item.get("country_code", "UNKNOWN")).strip().upper()
        country_counters[cc] = country_counters.get(cc, 0) + 1
        num = country_counters[cc]
        flag = item.get("flag", "🏳️")
        proxy = item.get("proxy")
        remark = f"{flag} {cc} {num}"

        if protocol == 'http':
            mahsang_configs.append(f"mahsa-http://Og==@{proxy}#{remark}")
            v2rayng_configs.append(f"http://Og@{proxy}#{remark}")
            nekobox_configs.append(f"http://{proxy}#{remark}")
        elif protocol == 'socks5':
            mahsang_configs.append(f"mahsa-socks://Og==@{proxy}#{remark}")
            v2rayng_configs.append(f"socks://{proxy}#{remark}")
            nekobox_configs.append(f"socks://{proxy}#{remark}")
        elif protocol == 'socks4':
            v2rayng_configs.append(f"socks://{proxy}#{remark}")
            nekobox_configs.append(f"socks://{proxy}#{remark}")

    if mahsang_configs:
        with open(os.path.join(sub_dir, f"mahsang_{protocol}.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(mahsang_configs) + '\n')
    if v2rayng_configs:
        with open(os.path.join(sub_dir, f"v2rayng_{protocol}.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(v2rayng_configs) + '\n')
    if nekobox_configs:
        with open(os.path.join(sub_dir, f"nekobox_{protocol}.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(nekobox_configs) + '\n')

    print(f"{BLUE}Finished {protocol.upper()} checks. Found {len(results)} live proxies.{RESET}")

def make_qr_image(text, file_path):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(file_path)

def build_qrs_and_readme():
    repo = os.environ.get("GITHUB_REPOSITORY", "username/repo")
    branch = os.environ.get("GITHUB_REF_NAME", "main")
    raw_prefix = f"https://raw.githubusercontent.com/{repo}/{branch}"
    
    sub_dir = os.path.join("proxies", "subscriptions")
    os.makedirs(sub_dir, exist_ok=True)
    
    sub_types = [
        ("mahsang_http.txt", "mahsang_http_qr.png"),
        ("v2rayng_http.txt", "v2rayng_http_qr.png"),
        ("nekobox_http.txt", "nekobox_http_qr.png"),
        ("v2rayng_socks5.txt", "v2rayng_socks5_qr.png"),
        ("nekobox_socks5.txt", "nekobox_socks5_qr.png")
    ]
    
    for txt_file, qr_file in sub_types:
        txt_path = os.path.join(sub_dir, txt_file)
        qr_path = os.path.join(sub_dir, qr_file)
        if os.path.exists(txt_path):
            sub_url = f"{raw_prefix}/{txt_path}"
            make_qr_image(sub_url, qr_path)
            
    readme_path = "README.md"
    if not os.path.exists(readme_path):
        return
        
    table = f"""<!-- SUBSCRIPTION_TABLE_START -->
| Client | Protocol | Raw Subscription Link (Copyable) | QR Code |
| :--- | :--- | :--- | :--- |
| **MahsaNG** | HTTP | `{raw_prefix}/proxies/subscriptions/mahsang_http.txt` | <img src="{raw_prefix}/proxies/subscriptions/mahsang_http_qr.png" width="120"/> |
| **V2rayNG** | HTTP | `{raw_prefix}/proxies/subscriptions/v2rayng_http.txt` | <img src="{raw_prefix}/proxies/subscriptions/v2rayng_http_qr.png" width="120"/> |
| **Nekobox** | HTTP | `{raw_prefix}/proxies/subscriptions/nekobox_http.txt` | <img src="{raw_prefix}/proxies/subscriptions/nekobox_http_qr.png" width="120"/> |
| **V2rayNG** | SOCKS5 | `{raw_prefix}/proxies/subscriptions/v2rayng_socks5.txt` | <img src="{raw_prefix}/proxies/subscriptions/v2rayng_socks5_qr.png" width="120"/> |
| **Nekobox** | SOCKS5 | `{raw_prefix}/proxies/subscriptions/nekobox_socks5.txt` | <img src="{raw_prefix}/proxies/subscriptions/nekobox_socks5_qr.png" width="120"/> |
<!-- SUBSCRIPTION_TABLE_END -->"""

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    start_tag = "<!-- SUBSCRIPTION_TABLE_START -->"
    end_tag = "<!-- SUBSCRIPTION_TABLE_END -->"
    
    if start_tag in content and end_tag in content:
        parts = content.split(start_tag)
        before = parts[0]
        after = parts[1].split(end_tag)[1]
        new_content = before + table + after
    else:
        new_content = content + "\n\n" + table
        
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

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
        
    print(f"\n{CYAN}=== Generating QR Codes & Updating README ==={RESET}")
    build_qrs_and_readme()

if __name__ == "__main__":
    main()
