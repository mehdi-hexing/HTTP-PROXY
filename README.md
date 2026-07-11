# HTTP/SOCKS4/SOCKS5 PROXY

This repository automatically fetches free proxies from ProxyScrape, checks their connectivity and latency every 6 hours, and saves the verified working ones in both plain text and detailed CSV formats.

## 💡 Psiphon Compatibility
You can use these verified proxies in your Psiphon settings. To configure:
1. Open Psiphon on your device.
2. Go to **Options** -> **More Options**.
3. Check **Upstream Proxy**.
4. Enter one of the live proxy IPs and ports from the generated lists.

## 📋 Live Lists

### Plain Text Files (Proxy:Port only)
* 🌐 [HTTP Proxies](http_proxies.txt)
* 🧦 [SOCKS4 Proxies](socks4_proxies.txt)
* 🧦 [SOCKS5 Proxies](socks5_proxies.txt)

### Detailed CSV Reports (Includes Country, Flag, Fraud Score, Risk, VPN, and ISP)
* 🌐 [HTTP Detailed Report](http_proxies.csv)
* 🧦 [SOCKS4 Detailed Report](socks4_proxies.csv)
* 🧦 [SOCKS5 Detailed Report](socks5_proxies.csv)

## ⚙️ How It Works
1. A GitHub Actions workflow runs every 6 hours.
2. It fetches the latest public proxies from ProxyScrape.
3. It concurrently tests connection speed and status.
4. For every successful proxy, it queries the Scamalytics API to fetch IP metadata (such as Country, Fraud Score, Risk, VPN, and ISP info).
5. Both raw text lists and formatted CSV reports are committed back to this repository automatically.
