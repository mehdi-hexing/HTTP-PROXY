# HTTP/HTTPS/SOCKS4/SOCKS5 PROXY

This repository automatically fetches free proxies from multiple sources and checks their connectivity and latency every 6 hours, and saves the verified working ones in both plain text and detailed CSV formats.

## Psiphon Compatibility

You can use these verified proxies in your Psiphon settings. To configure:

1. Open Psiphon on your device.
2. Go to **Options** -> **More Options**.
3. Check **Upstream Proxy**.
4. Enter one of the live Proxies and Ports from the generated lists.

## Live Lists

### Global Lists

- **HTTP:** [Global List](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/http/all.txt) | [Detailed CSV](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/http/all.csv)
- **HTTPS:** [Global List](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/https/all.txt) | [Detailed CSV](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/https/all.csv)
- **SOCKS4:** [Global List](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/socks4/all.txt) | [Detailed CSV](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/socks4/all.csv)
- **SOCKS5:** [Global List](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/socks5/all.txt) | [Detailed CSV](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/protocol/socks5/all.csv)

### Country-Specific Lists

- **HTTP:** [Browse Countries](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/countries/http)
- **HTTPS:** [Browse Countries](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/countries/https)
- **SOCKS4:** [Browse Countries](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/countries/socks4)
- **SOCKS5:** [Browse Countries](https://github.com/mehdi-hexing/HTTP-PROXY/blob/main/proxies/countries/socks5)

## Client Subscription Links

The table below displays updated subscription links and their QR codes. Scan the QR code using your client app or copy the raw link directly.

<!-- SUBSCRIPTION_TABLE_START -->
| Client      | Protocol | Raw Subscription Link (Copyable)                                                                          | QR Code                                                                                                                                                                                                  |
| ----------- | -------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MahsaNG** | HTTP     | `https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/mahsang_http.txt`   | [![](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/mahsang_http_qr.png)](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/mahsang_http_qr.png) |
| **V2rayNG** | HTTP     | `https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/v2rayng_http.txt`   | [![](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/v2rayng_http_qr.png)](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/v2rayng_http_qr.png) |
| **Exclave** | HTTP     | `https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_http.txt`   | [![](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_http_qr.png)](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_http_qr.png) |
| **Exclave** | HTTPS     | `https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_https.txt`   | [![](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_https_qr.png)](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_https_qr.png) |
| **Exclave** | SOCKS4    | `https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_socks4.txt`   | [![](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_socks4_qr.png)](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_socks4_qr.png) |
| **V2rayNG** | SOCKS5   | `https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/v2rayng_socks5.txt` | [![](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/v2rayng_socks5_qr.png)](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/v2rayng_socks5_qr.png) |
| **Exclave** | SOCKS5   | `https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_socks5.txt` | [![](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_socks5_qr.png)](https://raw.githubusercontent.com/mehdi-hexing/HTTP-PROXY/main/proxies/subscriptions/exclave_socks5_qr.png) |
<!-- SUBSCRIPTION_TABLE_END -->

## How It Works

1. A GitHub Actions workflow runs every 6 hours.
2. It fetches the latest public proxies from multiple sources and merges/deduplicates them.
