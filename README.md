# HTTP/SOCKS4/SOCKS5 PROXY

This repository automatically fetches free proxies from ProxyScrape, checks their connectivity and latency every 6 hours, and saves the verified working ones in both plain text and detailed CSV formats.

## 💡 Psiphon Compatibility
You can use these verified proxies in your Psiphon settings. To configure:
1. Open Psiphon on your device.
2. Go to **Options** -> **More Options**.
3. Check **Upstream Proxy**.
4. Enter one of the live Proxies and Ports from the generated lists.

## 📋 Live Lists

### 🌐 Global Lists
* **HTTP:** [Global List](proxies/protocol/http/all.txt) | [Detailed CSV](proxies/protocol/http/all.csv)
* **SOCKS4:** [Global List](proxies/protocol/socks4/all.txt) | [Detailed CSV](proxies/protocol/socks4/all.csv)
* **SOCKS5:** [Global List](proxies/protocol/socks5/all.txt) | [Detailed CSV](proxies/protocol/socks5/all.csv)

### 🗺️ Country-Specific Lists
* **HTTP:** [Browse Countries](proxies/countries/http/)
* **SOCKS4:** [Browse Countries](proxies/countries/socks4/)
* **SOCKS5:** [Browse Countries](proxies/countries/socks5/)

## ⚡ Client Subscription Links
The table below displays the dynamically updated subscription links and their respective QR codes. Scan the QR code using your client app or copy the raw link directly.

<!-- SUBSCRIPTION_TABLE_START -->
<!-- SUBSCRIPTION_TABLE_END -->

## ⚙️ How It Works
1. A GitHub Actions workflow runs every 6 hours.
2. It fetches the latest public proxies from ProxyScrape.
3. It concurrently tests connection speed and status.
