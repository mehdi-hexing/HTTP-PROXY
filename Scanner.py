import requests
import concurrent.futures
import threading
import time
import csv
import os
import urllib3
import uuid
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_URL = 'http://clients3.google.com/generate_204'
SOCKS_TEST_URL = 'https://www.gstatic.com/generate_204'
VERIFY_URL = 'https://api.ipify.org?format=json'
TIMEOUT = 8
MAX_THREADS = 200
MAX_POOL_SIZE = 10000

CHECK_IRAN = os.environ.get("CHECK_IRAN", "false").lower() == "true"
IRAN_CHECK_MAX = int(os.environ.get("IRAN_CHECK_MAX", "50"))  # per protocol
IRAN_CHECK_THREADS = 8  # keep this low - it's hitting someone else's free service

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

PROTOCOLS = ['http', 'https', 'socks4', 'socks5']

PROXY_SOURCES = {
    'http': [
        'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=http',
        'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all',
        'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
        'https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/http.txt',
        'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt',
        'https://www.proxy-list.download/api/v1/get?type=http',
    ],
    'https': [
        'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=https',
        'https://api.proxyscrape.com/v2/?request=getproxies&protocol=https&timeout=10000&country=all',
        'https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/protocols/https.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
        'https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/https.txt',
        'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt',
    ],
    'socks4': [
        'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=socks4',
        'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all',
        'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt',
        'https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks4.txt',
        'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt',
        'https://www.proxy-list.download/api/v1/get?type=socks4',
    ],
    'socks5': [
        'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=socks5',
        'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all',
        'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt',
        'https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt',
        'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt',
        'https://www.proxy-list.download/api/v1/get?type=socks5',
    ],
}

JSON_PROXY_SOURCES = [
    'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json',
]

class SafeCounter:
    """Thread-safe counter used to summarize what's happening across worker threads
    without spamming the console line-by-line."""
    def __init__(self):
        self._lock = threading.Lock()
        self._counts = Counter()

    def increment(self, key):
        with self._lock:
            self._counts[key] += 1

    def snapshot(self):
        with self._lock:
            return Counter(self._counts)

    def reset(self):
        with self._lock:
            self._counts.clear()

exception_counter = SafeCounter()

metadata_fallback_counter = SafeCounter()

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
            if response.status_code != 200:
                metadata_fallback_counter.increment(f"http_{response.status_code}")
                return None
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
            metadata_fallback_counter.increment("no_country_data")
        except requests.exceptions.Timeout:
            metadata_fallback_counter.increment("timeout")
        except requests.exceptions.RequestException:
            metadata_fallback_counter.increment("connection_error")
        except (ValueError, KeyError):
            metadata_fallback_counter.increment("bad_response_format")
        return None

    primary_url = f"https://cloudflare-scamalytics.pages.dev/{ip}"
    result = fetch_API(primary_url)
    if result:
        return result

    fallback_url = f"https://cf-scamalytics.mehdismart.workers.dev/{ip}"
    result = fetch_API(fallback_url)
    if result:
        return result

    metadata_fallback_counter.increment("both_sources_failed")
    return default_metadata

def check_iran_reachability(ip):
    """Uses the check-host.net pass-through on cloudflare-scamalytics.pages.dev
    to ping this IP from check-host.net's Iran-based nodes. This answers a
    different question than get_proxy_metadata()'s fraud/risk score: it tells
    you whether the proxy is actually *reachable from inside Iran*, which is
    the thing that matters for this project's users.

    Confirmed live response shape (2026):
    {
      "ok": true, "is_accessible": true, "nodes_checked": 7,
      "details": {
        "ir1.node.check-host.net": {
          "status": "OK", "sent": 4, "received": 4, "loss_percent": 0,
          "ping_ms": 76.28, "ping_ms_min": 76.1, "ping_ms_avg": 76.28, "ping_ms_max": 76.4
        }, ...
      }
    }
    """
    default = {"ir_reachable": "Unknown", "ir_latency": "", "ir_nodes_ok": ""}
    url = f"https://cloudflare-scamalytics.pages.dev/checkhost/ping/ir/{ip}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=40)
        if response.status_code != 200:
            return default
        data = response.json()

        if not data.get("ok"):
            return default

        details = data.get("details", {})
        nodes_checked = data.get("nodes_checked", len(details))

        ok_nodes = [n for n in details.values()
                    if isinstance(n, dict) and n.get("status") == "OK"]

        avg_pings = [n["ping_ms_avg"] for n in ok_nodes if isinstance(n.get("ping_ms_avg"), (int, float))]
        avg_latency = round(sum(avg_pings) / len(avg_pings), 1) if avg_pings else ""

        is_accessible = data.get("is_accessible", bool(ok_nodes))

        return {
            "ir_reachable": "Yes" if is_accessible else "No",
            "ir_latency": avg_latency,
            "ir_nodes_ok": f"{len(ok_nodes)}/{nodes_checked}",
        }
    except requests.exceptions.Timeout:
        return {"ir_reachable": "Timeout", "ir_latency": "", "ir_nodes_ok": ""}
    except Exception:
        return default

def check_proxy(proxy, protocol):
    cleaned_proxy = clean_proxy_string(proxy)
    if not cleaned_proxy:
        return None

    if protocol == 'socks5':
        proxy_url = f"socks5://{cleaned_proxy}"
    elif protocol == 'socks4':
        proxy_url = f"socks4://{cleaned_proxy}"
    elif protocol == 'https':
        proxy_url = f"https://{cleaned_proxy}"
    else:
        proxy_url = f"http://{cleaned_proxy}"

    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

    try:
        start_time = time.time()

        if protocol in ('socks4', 'socks5'):
            test_url = f"{SOCKS_TEST_URL}?__proxytest={uuid.uuid4().hex}"
            response = requests.get(
                test_url,
                proxies=proxies,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=False
            )
            if response.status_code not in [200, 204]:
                exception_counter.increment(f"bad_status_{response.status_code}")
                return None
        else:
            response = requests.get(
                TARGET_URL,
                proxies=proxies,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=False
            )
            if response.status_code not in [200, 204]:
                exception_counter.increment(f"bad_status_{response.status_code}")
                return None
                
            verify_response = requests.get(
                VERIFY_URL,
                proxies=proxies,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=False
            )
            if verify_response.status_code != 200:
                exception_counter.increment("failed_cross_check")
                return None

        elapsed = time.time() - start_time
        print(f"{GREEN}[SUCCESS] [{protocol.upper()}]{RESET} {cleaned_proxy} - {elapsed:.2f}s")
        ip = cleaned_proxy.split(':')[0]
        metadata = get_proxy_metadata(ip)
        return {
            "proxy": cleaned_proxy,
            "protocol": protocol,
            "latency": round(elapsed * 1000),
            **metadata
        }
    except requests.exceptions.Timeout:
        exception_counter.increment("timeout")
    except requests.exceptions.ProxyError:
        exception_counter.increment("proxy_error")
    except requests.exceptions.ConnectionError:
        exception_counter.increment("connection_error")
    except requests.exceptions.MissingSchema:
        exception_counter.increment("missing_schema")
    except requests.exceptions.RequestException as e:
        if "socks" in str(e).lower() or "pysocks" in str(e).lower():
            exception_counter.increment("missing_pysocks_dependency")
        else:
            exception_counter.increment("other_request_error")
    except Exception:
        exception_counter.increment("unexpected_error")
    return None

def parse_proxifly_json(data):
    """Splits Proxifly's combined all/data.json (a single JSON array covering
    every protocol) into per-protocol lists of "ip:port" strings. Verified
    live field names: protocol, ip, port (int), geolocation.country/city."""
    buckets = {p: [] for p in PROTOCOLS}
    if not isinstance(data, list):
        return buckets
    for entry in data:
        if not isinstance(entry, dict):
            continue
        proto = str(entry.get('protocol', '')).lower()
        ip = entry.get('ip')
        port = entry.get('port')
        if proto in buckets and ip and port:
            buckets[proto].append(f"{ip}:{port}")
    return buckets

def fetch_json_proxies():
    """Fetches all JSON-format sources once (not once per protocol, since
    Proxifly's feed already covers every protocol in a single file) and
    returns a dict of protocol -> list of "ip:port" strings."""
    buckets = {p: [] for p in PROTOCOLS}
    for url in JSON_PROXY_SOURCES:
        source_name = url.split('/')[2]
        try:
            response = requests.get(url, headers=HEADERS, timeout=20)
            if response.status_code != 200:
                print(f"{YELLOW}  {source_name} (json): HTTP {response.status_code}, skipped{RESET}")
                continue
            data = response.json()
            parsed = parse_proxifly_json(data)
            for proto, plist in parsed.items():
                buckets[proto].extend(plist)
            total = sum(len(v) for v in parsed.values())
            print(f"{GREEN}  {source_name} (json): {total} proxies across all protocols{RESET}")
        except Exception as e:
            print(f"{YELLOW}  {source_name} (json): unreachable or invalid JSON "
                  f"({type(e).__name__}), skipped{RESET}")
    return buckets

def fetch_proxies(protocol, extra_proxies=None):
    sources = PROXY_SOURCES.get(protocol, [])
    if not sources and not extra_proxies:
        print(f"{RED}No sources configured for {protocol.upper()}.{RESET}")
        return []

    print(f"{CYAN}Fetching {protocol.upper()} proxies from {len(sources)} text source(s)...{RESET}")
    merged = {}
    for url in sources:
        source_name = url.split('/')[2]
        try:
            response = requests.get(url, headers=HEADERS, timeout=15)
            if response.status_code == 200:
                lines = [line.strip() for line in response.text.splitlines() if line.strip()]
                lines = [l for l in lines if ':' in l and ' ' not in l]
                for p in lines:
                    merged[p] = True
                print(f"{GREEN}  {source_name}: {len(lines)} proxies{RESET}")
            else:
                print(f"{YELLOW}  {source_name}: HTTP {response.status_code}, skipped{RESET}")
        except Exception as e:
            print(f"{YELLOW}  {source_name}: unreachable ({type(e).__name__}), skipped{RESET}")

    if extra_proxies:
        for p in extra_proxies:
            merged[p] = True

    proxies = list(merged.keys())
    print(f"{GREEN}Total unique {protocol.upper()} proxies after merging: {len(proxies)}.{RESET}")
    return proxies

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

    exception_counter.reset()
    metadata_fallback_counter.reset()

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_proxy, proxy, protocol): proxy for proxy in proxy_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    if CHECK_IRAN and results:
        # Pick the shortlist by quality (lowest fraud score, then latency)
        # BEFORE the final country-grouped sort below - otherwise "top N"
        # would really just mean "first N alphabetically by country".
        def quality_key(item):
            try:
                fraud_score = int(item.get("fraud_score", 101))
            except (ValueError, TypeError):
                fraud_score = 101
            return (fraud_score, item.get("latency", 99999))
        shortlist = sorted(results, key=quality_key)[:IRAN_CHECK_MAX]
        print(f"{CYAN}Checking Iran reachability for the top {len(shortlist)} "
              f"{protocol.upper()} proxies (of {len(results)} alive)...{RESET}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=IRAN_CHECK_THREADS) as executor:
            futures = {executor.submit(check_iran_reachability, item["proxy"].split(':')[0]): item
                       for item in shortlist}
            for future in concurrent.futures.as_completed(futures):
                item = futures[future]
                item.update(future.result())
        for item in results:
            item.setdefault("ir_reachable", "Not Checked")
            item.setdefault("ir_latency", "")
            item.setdefault("ir_nodes_ok", "")

    results.sort(key=sort_key)

    global_txt = os.path.join(protocol_dir, "all.txt")
    global_csv = os.path.join(protocol_dir, "all.csv")

    with open(global_txt, 'w', encoding='utf-8') as f:
        for item in results:
            f.write(item["proxy"] + '\n')

    csv_header = ["Proxy", "Protocol", "Country", "Country Code", "Flag", "Fraud Score", "Risk", "VPN", "ISP", "Latency (ms)"]
    if CHECK_IRAN:
        csv_header += ["Iran Reachable", "Iran Latency (ms)", "Iran Nodes OK"]

    def csv_row(item):
        row = [
            item["proxy"],
            item["protocol"].upper(),
            item["country"],
            item["country_code"],
            item["flag"],
            item["fraud_score"],
            item["risk"],
            item["vpn"],
            item["isp"],
            item.get("latency", "")
        ]
        if CHECK_IRAN:
            row += [item.get("ir_reachable", ""), item.get("ir_latency", ""), item.get("ir_nodes_ok", "")]
        return row

    with open(global_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(csv_header)
        for item in results:
            writer.writerow(csv_row(item))

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
            writer.writerow(csv_header)
            for item in items:
                writer.writerow(csv_row(item))

    sub_dir = os.path.join("proxies", "subscriptions")
    os.makedirs(sub_dir, exist_ok=True)

    country_counters = {}
    mahsang_configs = []
    v2rayng_configs = []
    exclave_configs = []

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
            exclave_configs.append(f"http://{proxy}#{remark}")
        elif protocol == 'https':
            exclave_configs.append(f"https://{proxy}#{remark}")
        elif protocol == 'socks5':
            mahsang_configs.append(f"socks://Og==@{proxy}#{remark}")
            v2rayng_configs.append(f"socks://Og@{proxy}#{remark}")
            exclave_configs.append(f"socks5://{proxy}#{remark}")
        elif protocol == 'socks4':
            exclave_configs.append(f"socks4://{proxy}#{remark}")

    if mahsang_configs:
        with open(os.path.join(sub_dir, f"mahsang_{protocol}.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(mahsang_configs) + '\n')
    if v2rayng_configs:
        with open(os.path.join(sub_dir, f"v2rayng_{protocol}.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(v2rayng_configs) + '\n')
    if exclave_configs:
        with open(os.path.join(sub_dir, f"exclave_{protocol}.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(exclave_configs) + '\n')

    print(f"{BLUE}Finished {protocol.upper()} checks. Found {len(results)} live proxies out of {len(proxy_list)} checked.{RESET}")

    fail_counts = exception_counter.snapshot()
    if fail_counts:
        print(f"{YELLOW}  Failure breakdown for {protocol.upper()}:{RESET}")
        for reason, count in fail_counts.most_common():
            print(f"    {reason}: {count}")
        if fail_counts.get("missing_pysocks_dependency"):
            print(f"{RED}  WARNING: {fail_counts['missing_pysocks_dependency']} proxies failed because PySocks "
                  f"isn't installed. Run: pip install \"requests[socks]\"{RESET}")
        if fail_counts.get("failed_cross_check"):
            print(f"{YELLOW}  Note: {fail_counts['failed_cross_check']} proxies passed the primary check but "
                  f"failed the cross-check target — these were likely single-purpose relays and were excluded "
                  f"to avoid false positives.{RESET}")

    fallback_counts = metadata_fallback_counter.snapshot()
    if fallback_counts:
        total_fallback = sum(fallback_counts.values())
        print(f"{YELLOW}  Metadata lookups fell back to defaults {total_fallback} time(s):{RESET}")
        for reason, count in fallback_counts.most_common():
            print(f"    {reason}: {count}")

def make_qr_image(text, file_path):
    """Generates a QR code PNG for a subscription URL. qrcode is imported
    lazily here (not at module level) so a missing dependency only disables
    QR generation instead of crashing the whole scan — same lesson as the
    PySocks issue: don't let one optional feature take down the run."""
    try:
        import qrcode
    except ImportError:
        print(f"{YELLOW}  qrcode library not installed — skipping QR generation. "
              f"Install with: pip install \"qrcode[pil]\"{RESET}")
        return False
    try:
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
        return True
    except Exception as e:
        print(f"{YELLOW}  Failed to generate QR for {file_path}: {type(e).__name__}{RESET}")
        return False

def build_qrs_and_readme():
    repo = os.environ.get("GITHUB_REPOSITORY", "username/repo")
    branch = os.environ.get("GITHUB_REF_NAME", "main")
    raw_prefix = f"https://raw.githubusercontent.com/{repo}/{branch}"

    sub_dir = os.path.join("proxies", "subscriptions")
    os.makedirs(sub_dir, exist_ok=True)

    sub_types = [
        ("mahsang_http.txt", "mahsang_http_qr.png"),
        ("v2rayng_http.txt", "v2rayng_http_qr.png"),
        ("exclave_http.txt", "exclave_http_qr.png"),
        ("exclave_https.txt", "exclave_https_qr.png"),
        ("exclave_socks4.txt", "exclave_socks4_qr.png"),
        ("v2rayng_socks5.txt", "v2rayng_socks5_qr.png"),
        ("exclave_socks5.txt", "exclave_socks5_qr.png")
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
| **Exclave** | HTTP | `{raw_prefix}/proxies/subscriptions/exclave_http.txt` | <img src="{raw_prefix}/proxies/subscriptions/exclave_http_qr.png" width="120"/> |
| **Exclave** | HTTPS | `{raw_prefix}/proxies/subscriptions/exclave_https.txt` | <img src="{raw_prefix}/proxies/subscriptions/exclave_https_qr.png" width="120"/> |
| **Exclave** | SOCKS4 | `{raw_prefix}/proxies/subscriptions/exclave_socks4.txt` | <img src="{raw_prefix}/proxies/subscriptions/exclave_socks4_qr.png" width="120"/> |
| **V2rayNG** | SOCKS5 | `{raw_prefix}/proxies/subscriptions/v2rayng_socks5.txt` | <img src="{raw_prefix}/proxies/subscriptions/v2rayng_socks5_qr.png" width="120"/> |
| **Exclave** | SOCKS5 | `{raw_prefix}/proxies/subscriptions/exclave_socks5.txt` | <img src="{raw_prefix}/proxies/subscriptions/exclave_socks5_qr.png" width="120"/> |
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

def commit_and_push(message):
    """Commits and pushes whatever's changed so far under Raw_Sources/ and
    proxies/. Called after every protocol finishes, not just once at the very
    end - so if the job gets killed (workflow timeout, runner hiccup, GitHub's
    own 6h hard cap) partway through, the protocols that DID finish are
    already saved instead of being lost along with everything else.
    Best-effort: a failed commit/push here shouldn't crash the scan, since
    the workflow's own final commit step is still there as a backstop."""
    import subprocess
    try:
        subprocess.run(["git", "add", "-f", "proxies/", "Raw_Sources/"], check=True)
        diff = subprocess.run(["git", "diff", "--cached", "--quiet"])
        if diff.returncode == 0:
            return  # nothing changed, skip an empty commit
        subprocess.run(["git", "commit", "-m", message], check=True)
        subprocess.run(["git", "push"], check=True)
        print(f"{GREEN}  Pushed: {message}{RESET}")
    except Exception as e:
        print(f"{YELLOW}  Incremental commit/push skipped ({type(e).__name__}) - "
              f"the workflow's final commit step will catch it if the job finishes.{RESET}")

def main():
    print(f"{YELLOW}Initializing Proxies Scan...{RESET}")
    print(f"{CYAN}=== Start Fetching ==={RESET}")
    
    pool_dir = "Raw_Sources"
    os.makedirs(pool_dir, exist_ok=True)

    print(f"{CYAN}Fetching combined JSON proxy feed(s)...{RESET}")
    json_buckets = fetch_json_proxies()

    fetched_data = {}
    for proto in PROTOCOLS:
        pool_file = os.path.join(pool_dir, f"raw_{proto}.txt")
        
        existing_pool = []
        if os.path.exists(pool_file):
            with open(pool_file, 'r', encoding='utf-8') as f:
                existing_pool = [line.strip() for line in f if line.strip()]
        
        new_proxies = fetch_proxies(proto, extra_proxies=json_buckets.get(proto, []))
        
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
        commit_and_push(f"Update {proto.upper()} proxies list")

    print(f"\n{CYAN}=== Generating QR Codes & Updating README ==={RESET}")
    build_qrs_and_readme()
    commit_and_push("Update subscriptions, QR codes and README")

    print(f"\n{YELLOW}Reminder: free public proxies can go dead within minutes of being verified.{RESET}")
    print(f"{YELLOW}Use freshly-scanned proxies as soon as possible, and prefer lower values in the "
          f"'Latency (ms)' column in each CSV for the best chance of them working in your client.{RESET}")

if __name__ == "__main__":
    main()
