import requests
import concurrent.futures
import time
import csv

TARGET_URL = 'http://clients3.google.com/generate_204'
TIMEOUT = 10
MAX_THREADS = 50

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

PROTOCOLS = ['http', 'socks4', 'socks5']

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
    url = f"https://cloudflare-scamalytics.pages.dev/{ip}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        if response.status_code == 200:
            data = response.json()
            info = data.get("info", {})
            details = data.get("details", {})
            return {
                "country": details.get("country", "Unknown"),
                "country_code": details.get("country_code", "N/A"),
                "flag": details.get("flag", "🏳️"),
                "fraud_score": info.get("fraud_score", "N/A"),
                "risk": info.get("risk", "Unknown"),
                "vpn": details.get("vpn", "Unknown"),
                "isp": details.get("isp", "Unknown")
            }
    except Exception:
        pass
    return default_metadata

def check_proxy(proxy, protocol):
    cleaned_proxy = clean_proxy_string(proxy)
    if not cleaned_proxy:
        return None

    if protocol == 'socks5':
        proxy_url = f"socks5h://{cleaned_proxy}"
    elif protocol == 'socks4':
        proxy_url = f"socks4a://{cleaned_proxy}"
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
            print(f"[SUCCESS] [{protocol.upper()}] {cleaned_proxy} - {elapsed:.2f}s")
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
    print(f"Fetching {protocol.upper()} proxy list from ProxyScrape...")
    url = f"https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol={protocol}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            proxies = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"Successfully fetched {len(proxies)} {protocol.upper()} proxies.")
            return proxies
        else:
            print(f"Failed to fetch {protocol.upper()} proxies. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error fetching {protocol.upper()} proxies: {e}")
    return []

def sort_key(item):
    country = item.get("country", "Unknown")
    try:
        fraud_score = int(item.get("fraud_score", 101))
    except (ValueError, TypeError):
        fraud_score = 101
    return (country, fraud_score)

def process_protocol(protocol):
    print(f"\n--- Starting {protocol.upper()} Proxy Verification ---")
    proxy_list = fetch_proxies(protocol)
    if not proxy_list:
        print(f"No {protocol.upper()} proxies to check.")
        return

    txt_file = f"{protocol}_proxies.txt"
    csv_file = f"{protocol}_proxies.csv"

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_proxy, proxy, protocol): proxy for proxy in proxy_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=sort_key)

    with open(txt_file, 'w', encoding='utf-8') as f:
        for item in results:
            f.write(item["proxy"] + '\n')

    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
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

    print(f"Finished {protocol.upper()} checks. Found {len(results)} live proxies.")

def main():
    print("Initializing Proxies Scan..")
    for proto in PROTOCOLS:
        process_protocol(proto)

if __name__ == "__main__":
    main()
