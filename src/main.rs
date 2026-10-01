//! Rust port of Scanner.py.
//!
//! Environment variables:
//!   CHECK_IRAN       "true" to check reachability from Iran for the top proxies
//!   IRAN_CHECK_MAX   shortlist size per protocol (default 250)
//!   TIMEOUT_SECS     per-request proxy timeout in seconds (default 8)
//!   MAX_CONCURRENCY  parallel proxy checks (default 200)
//!   GIT_PUSH         "true"/"false" to force git commit+push (default: on in GitHub Actions)

use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{self, BufWriter};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qrcode::{Color, EcLevel, QrCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

type Res<T> = Result<T, Box<dyn Error>>;

const TARGET_HOST: &str = "clients3.google.com";
const TARGET_PATH: &str = "/generate_204";
const SOCKS_TEST_HOST: &str = "www.gstatic.com";
const SOCKS_TEST_PATH: &str = "/generate_204";
const VERIFY_HOST: &str = "api.ipify.org";
const VERIFY_PATH: &str = "/?format=json";

const MAX_POOL_SIZE: usize = 20000;
const IRAN_CHECK_THREADS: usize = 8;

const META_PRIMARY: &str = "https://cloudflare-scamalytics.pages.dev";
const META_FALLBACK: &str = "https://cf-scamalytics.mehdismart.workers.dev";

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const PROTOCOLS: [&str; 4] = ["http", "http_tls", "socks4", "socks5"];

const HTTP_SOURCES: &[&str] = &[
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=http",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/http.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
    "https://www.proxy-list.download/api/v1/get?type=http",
];
const HTTP_TLS_SOURCES: &[&str] = &[
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=https",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=https&timeout=10000&country=all",
    "https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/protocols/https.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/https.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/https/data.txt",
];
const SOCKS4_SOURCES: &[&str] = &[
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=socks4",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks4.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
    "https://www.proxy-list.download/api/v1/get?type=socks4",
];
const SOCKS5_SOURCES: &[&str] = &[
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&protocol=socks5",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
];

const JSON_PROXY_SOURCES: &[&str] =
    &["https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json"];

const GREEN: &str = "\x1b[92m";
const RED: &str = "\x1b[91m";
const YELLOW: &str = "\x1b[93m";
const BLUE: &str = "\x1b[94m";
const CYAN: &str = "\x1b[96m";
const RESET: &str = "\x1b[0m";

fn proxy_sources(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "http" => HTTP_SOURCES,
        "http_tls" => HTTP_TLS_SOURCES,
        "socks4" => SOCKS4_SOURCES,
        "socks5" => SOCKS5_SOURCES,
        _ => &[],
    }
}

struct Config {
    timeout: Duration,
    max_concurrency: usize,
    check_iran: bool,
    iran_check_max: usize,
    git_push: bool,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok();
        let check_iran = get("CHECK_IRAN")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        let iran_check_max = get("IRAN_CHECK_MAX")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(250);
        let timeout_secs = get("TIMEOUT_SECS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(8);
        let max_concurrency = get("MAX_CONCURRENCY")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(200);
        let git_push = match get("GIT_PUSH") {
            Some(v) => v.to_lowercase() == "true",
            None => get("GITHUB_ACTIONS").map(|v| v == "true").unwrap_or(false),
        };
        Config {
            timeout: Duration::from_secs(timeout_secs),
            max_concurrency,
            check_iran,
            iran_check_max,
            git_push,
        }
    }
}

#[derive(Default)]
struct SafeCounter {
    inner: Mutex<HashMap<String, u64>>,
}

impl SafeCounter {
    fn increment(&self, key: &str) {
        let mut map = self.inner.lock().unwrap();
        *map.entry(key.to_string()).or_insert(0) += 1;
    }

    fn get(&self, key: &str) -> u64 {
        self.inner.lock().unwrap().get(key).copied().unwrap_or(0)
    }

    fn snapshot(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .inner
            .lock()
            .unwrap()
            .iter()
            .map(|(k, c)| (k.clone(), *c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    fn reset(&self) {
        self.inner.lock().unwrap().clear();
    }
}

struct Ctx {
    cfg: Config,
    http: reqwest::Client,
    tls: TlsConnector,
    exceptions: SafeCounter,
    metadata_fallbacks: SafeCounter,
}

#[derive(Debug)]
struct NoVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("valid TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier { provider }))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxStream = Box<dyn Io>;

fn proxy_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

enum Fail {
    Timeout,
    Proxy,
    Connection,
    BadStatus(u16),
    CrossCheck,
}

impl Fail {
    fn key(&self) -> String {
        match self {
            Fail::Timeout => "timeout".to_string(),
            Fail::Proxy => "proxy_error".to_string(),
            Fail::Connection => "connection_error".to_string(),
            Fail::BadStatus(code) => format!("bad_status_{code}"),
            Fail::CrossCheck => "failed_cross_check".to_string(),
        }
    }
}

impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => Fail::Proxy,
            io::ErrorKind::TimedOut => Fail::Timeout,
            _ => Fail::Connection,
        }
    }
}

async fn tls_wrap(ctx: &Ctx, stream: BoxStream, host: &str) -> io::Result<BoxStream> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
    let tls = ctx.tls.connect(name, stream).await?;
    Ok(Box::new(tls))
}

async fn socks5_connect(stream: &mut BoxStream, host: &str, port: u16) -> io::Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(proxy_err("socks5 requires authentication or is invalid"));
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(proxy_err("hostname too long"));
    }
    let mut req = vec![5u8, 1, 0, 3, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 0 {
        return Err(proxy_err("socks5 connect rejected"));
    }
    let addr_len = match head[3] {
        1 => 4usize,
        4 => 16usize,
        3 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(proxy_err("socks5 bad address type")),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

async fn socks4_connect(stream: &mut BoxStream, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let mut req = vec![4u8, 1];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip.octets());
    req.push(0);
    stream.write_all(&req).await?;
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x5A {
        return Err(proxy_err("socks4 connect rejected"));
    }
    Ok(())
}

async fn resolve_ipv4(host: &str, port: u16) -> io::Result<Ipv4Addr> {
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no IPv4 address"))
}

async fn http_connect(stream: &mut BoxStream, host: &str, port: u16) -> io::Result<()> {
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {USER_AGENT}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(proxy_err("proxy closed during CONNECT"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(proxy_err("CONNECT response too large"));
        }
    }
    let code = parse_status(&buf)?;
    if code != 200 {
        return Err(proxy_err("CONNECT rejected"));
    }
    Ok(())
}

fn parse_status(buf: &[u8]) -> io::Result<u16> {
    let text = String::from_utf8_lossy(buf);
    let line = text.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(proxy_err("not an HTTP response"));
    }
    parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| proxy_err("bad status line"))
}

async fn read_status_line(stream: &mut BoxStream) -> io::Result<u16> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.contains(&b'\n') || buf.len() >= 8192 {
            break;
        }
    }
    parse_status(&buf)
}

async fn open_via_proxy(
    ctx: &Ctx,
    proxy: &str,
    protocol: &str,
    host: &str,
    tls_target: bool,
) -> Result<BoxStream, Fail> {
    let port: u16 = if tls_target { 443 } else { 80 };
    let tcp = TcpStream::connect(proxy).await?;
    let _ = tcp.set_nodelay(true);
    let mut stream: BoxStream = Box::new(tcp);

    match protocol {
        "socks5" => socks5_connect(&mut stream, host, port).await?,
        "socks4" => {
            let ip = resolve_ipv4(host, port).await?;
            socks4_connect(&mut stream, ip, port).await?;
        }
        "http" | "http_tls" => {
            if protocol == "http_tls" {
                let proxy_host = proxy.rsplit_once(':').map(|(h, _)| h).unwrap_or(proxy);
                stream = tls_wrap(ctx, stream, proxy_host).await?;
            }
            if tls_target {
                http_connect(&mut stream, host, port).await?;
            }
        }
        _ => return Err(Fail::Proxy),
    }

    if tls_target {
        stream = tls_wrap(ctx, stream, host).await?;
    }
    Ok(stream)
}

async fn fetch_status(
    ctx: &Ctx,
    proxy: &str,
    protocol: &str,
    tls_target: bool,
    host: &str,
    path: &str,
) -> Result<u16, Fail> {
    let fut = async {
        let mut stream = open_via_proxy(ctx, proxy, protocol, host, tls_target).await?;
        let http_proxy = matches!(protocol, "http" | "http_tls");
        let target = if http_proxy && !tls_target {
            format!("http://{host}{path}")
        } else {
            path.to_string()
        };
        let req = format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        let code = read_status_line(&mut stream).await?;
        Ok::<u16, Fail>(code)
    };
    match timeout(ctx.cfg.timeout, fut).await {
        Ok(result) => result,
        Err(_) => Err(Fail::Timeout),
    }
}

fn py_str(v: Option<&Value>, default: &str) -> String {
    match v {
        None => default.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => (if *b { "True" } else { "False" }).to_string(),
        Some(Value::Null) => "None".to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|x| x != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[derive(Clone)]
struct Metadata {
    country: String,
    country_code: String,
    flag: String,
    fraud_score: String,
    risk: String,
    vpn: String,
    isp: String,
}

impl Metadata {
    fn unknown() -> Self {
        Metadata {
            country: "Unknown".to_string(),
            country_code: "N/A".to_string(),
            flag: "\u{1F3F3}\u{FE0F}".to_string(),
            fraud_score: "N/A".to_string(),
            risk: "Unknown".to_string(),
            vpn: "Unknown".to_string(),
            isp: "Unknown".to_string(),
        }
    }
}

#[derive(Clone)]
struct IranInfo {
    reachable: String,
    latency: String,
    nodes_ok: String,
}

#[derive(Clone)]
struct ProxyResult {
    proxy: String,
    protocol: &'static str,
    latency: u64,
    meta: Metadata,
    ir: Option<IranInfo>,
}

async fn fetch_metadata_api(ctx: &Ctx, url: &str) -> Option<Metadata> {
    let resp = match ctx.http.get(url).timeout(Duration::from_secs(5)).send().await {
        Ok(r) => r,
        Err(e) => {
            if e.is_timeout() {
                ctx.metadata_fallbacks.increment("timeout");
            } else {
                ctx.metadata_fallbacks.increment("connection_error");
            }
            return None;
        }
    };
    if resp.status().as_u16() != 200 {
        ctx.metadata_fallbacks
            .increment(&format!("http_{}", resp.status().as_u16()));
        return None;
    }
    let body = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            if e.is_timeout() {
                ctx.metadata_fallbacks.increment("timeout");
            } else {
                ctx.metadata_fallbacks.increment("connection_error");
            }
            return None;
        }
    };
    let data: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            ctx.metadata_fallbacks.increment("bad_response_format");
            return None;
        }
    };

    let empty = Value::Null;
    let info = data.get("info").unwrap_or(&empty);
    let details = data.get("details").unwrap_or(&empty);
    let country_ok = match details.get("country") {
        Some(Value::String(s)) => !s.is_empty() && s != "Unknown",
        Some(other) => truthy(other),
        None => false,
    };
    if country_ok {
        return Some(Metadata {
            country: py_str(details.get("country"), "Unknown"),
            country_code: py_str(details.get("country_code"), "N/A"),
            flag: py_str(details.get("flag"), "\u{1F3F3}\u{FE0F}"),
            fraud_score: py_str(info.get("fraud_score"), "N/A"),
            risk: py_str(info.get("risk"), "Unknown"),
            vpn: py_str(details.get("vpn"), "Unknown"),
            isp: py_str(details.get("isp"), "Unknown"),
        });
    }
    ctx.metadata_fallbacks.increment("no_country_data");
    None
}

async fn get_proxy_metadata(ctx: &Ctx, ip: &str) -> Metadata {
    if let Some(m) = fetch_metadata_api(ctx, &format!("{META_PRIMARY}/{ip}")).await {
        return m;
    }
    if let Some(m) = fetch_metadata_api(ctx, &format!("{META_FALLBACK}/{ip}")).await {
        return m;
    }
    ctx.metadata_fallbacks.increment("both_sources_failed");
    Metadata::unknown()
}

async fn check_iran_reachability(ctx: &Ctx, ip: &str) -> IranInfo {
    let default = IranInfo {
        reachable: "Unknown".to_string(),
        latency: String::new(),
        nodes_ok: String::new(),
    };
    let url = format!("{META_PRIMARY}/checkhost/ping/ir/{ip}");

    let resp = match ctx.http.get(&url).timeout(Duration::from_secs(40)).send().await {
        Ok(r) => r,
        Err(e) => {
            if e.is_timeout() {
                return IranInfo {
                    reachable: "Timeout".to_string(),
                    latency: String::new(),
                    nodes_ok: String::new(),
                };
            }
            return default;
        }
    };
    if resp.status().as_u16() != 200 {
        return default;
    }
    let body = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            if e.is_timeout() {
                return IranInfo {
                    reachable: "Timeout".to_string(),
                    latency: String::new(),
                    nodes_ok: String::new(),
                };
            }
            return default;
        }
    };
    let data: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return default,
    };

    if !data.get("ok").map(truthy).unwrap_or(false) {
        return default;
    }

    let empty_map = serde_json::Map::new();
    let details = data
        .get("details")
        .and_then(|d| d.as_object())
        .unwrap_or(&empty_map);
    let nodes_checked = data
        .get("nodes_checked")
        .and_then(|n| n.as_u64())
        .unwrap_or(details.len() as u64);

    let ok_nodes: Vec<&Value> = details
        .values()
        .filter(|n| n.is_object() && n.get("status").and_then(|s| s.as_str()) == Some("OK"))
        .collect();

    let avg_pings: Vec<f64> = ok_nodes
        .iter()
        .filter_map(|n| n.get("ping_ms_avg").and_then(|p| p.as_f64()))
        .collect();
    let latency = if avg_pings.is_empty() {
        String::new()
    } else {
        let avg = avg_pings.iter().sum::<f64>() / avg_pings.len() as f64;
        format!("{:?}", (avg * 10.0).round() / 10.0)
    };

    let is_accessible = match data.get("is_accessible") {
        Some(v) => truthy(v),
        None => !ok_nodes.is_empty(),
    };

    IranInfo {
        reachable: if is_accessible { "Yes" } else { "No" }.to_string(),
        latency,
        nodes_ok: format!("{}/{}", ok_nodes.len(), nodes_checked),
    }
}

fn clean_proxy_string(proxy: &str) -> String {
    let proxy = proxy.trim();
    let lower = proxy.to_ascii_lowercase();
    for prefix in ["http://", "https://", "socks4://", "socks5://"] {
        if lower.starts_with(prefix) {
            return proxy[prefix.len()..].to_string();
        }
    }
    proxy.to_string()
}

async fn check_proxy(ctx: &Ctx, proxy: &str, protocol: &'static str) -> Option<ProxyResult> {
    let cleaned = clean_proxy_string(proxy);
    if cleaned.is_empty() {
        return None;
    }

    let start = Instant::now();
    let outcome: Result<(), Fail> = async {
        if protocol == "socks4" || protocol == "socks5" {
            let path = format!(
                "{SOCKS_TEST_PATH}?__proxytest={}",
                uuid::Uuid::new_v4().simple()
            );
            let code = fetch_status(ctx, &cleaned, protocol, true, SOCKS_TEST_HOST, &path).await?;
            if code != 200 && code != 204 {
                return Err(Fail::BadStatus(code));
            }
        } else {
            let code = fetch_status(ctx, &cleaned, protocol, false, TARGET_HOST, TARGET_PATH).await?;
            if code != 200 && code != 204 {
                return Err(Fail::BadStatus(code));
            }
            let verify = fetch_status(ctx, &cleaned, protocol, true, VERIFY_HOST, VERIFY_PATH).await;
            match verify {
                Ok(200) => {}
                _ => return Err(Fail::CrossCheck),
            }
        }
        Ok(())
    }
    .await;

    if let Err(fail) = outcome {
        ctx.exceptions.increment(&fail.key());
        return None;
    }

    let elapsed = start.elapsed();
    println!(
        "{GREEN}[SUCCESS] [{}]{RESET} {} - {:.2}s",
        protocol.to_uppercase(),
        cleaned,
        elapsed.as_secs_f64()
    );
    let ip = cleaned.split(':').next().unwrap_or("").to_string();
    let meta = get_proxy_metadata(ctx, &ip).await;
    Some(ProxyResult {
        proxy: cleaned,
        protocol,
        latency: elapsed.as_millis() as u64,
        meta,
        ir: None,
    })
}

fn source_name(url: &str) -> &str {
    url.split('/').nth(2).unwrap_or(url)
}

fn describe_err(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect error"
    } else {
        "request error"
    }
}

fn parse_proxifly_json(data: &Value) -> HashMap<&'static str, Vec<String>> {
    let mut buckets: HashMap<&'static str, Vec<String>> = HashMap::new();
    for p in PROTOCOLS {
        buckets.insert(p, Vec::new());
    }
    let Some(entries) = data.as_array() else {
        return buckets;
    };
    for entry in entries {
        if !entry.is_object() {
            continue;
        }
        let proto = py_str(entry.get("protocol"), "").to_lowercase();
        let proto = if proto == "https" { "http_tls".to_string() } else { proto };
        let ip = entry.get("ip");
        let port = entry.get("port");
        let ip_ok = ip.map(truthy).unwrap_or(false);
        let port_ok = port.map(truthy).unwrap_or(false);
        if ip_ok && port_ok {
            if let Some(bucket) = PROTOCOLS
                .iter()
                .find(|p| **p == proto.as_str())
                .and_then(|p| buckets.get_mut(p))
            {
                bucket.push(format!("{}:{}", py_str(ip, ""), py_str(port, "")));
            }
        }
    }
    buckets
}

async fn fetch_json_proxies(ctx: &Ctx) -> HashMap<&'static str, Vec<String>> {
    let mut buckets: HashMap<&'static str, Vec<String>> = HashMap::new();
    for p in PROTOCOLS {
        buckets.insert(p, Vec::new());
    }
    for url in JSON_PROXY_SOURCES {
        let name = source_name(url);
        let resp = match ctx.http.get(*url).timeout(Duration::from_secs(20)).send().await {
            Ok(r) => r,
            Err(e) => {
                println!(
                    "{YELLOW}  {name} (json): unreachable or invalid JSON ({}), skipped{RESET}",
                    describe_err(&e)
                );
                continue;
            }
        };
        if resp.status().as_u16() != 200 {
            println!(
                "{YELLOW}  {name} (json): HTTP {}, skipped{RESET}",
                resp.status().as_u16()
            );
            continue;
        }
        let parsed: Option<Value> = match resp.text().await {
            Ok(t) => serde_json::from_str(&t).ok(),
            Err(_) => None,
        };
        let Some(data) = parsed else {
            println!("{YELLOW}  {name} (json): unreachable or invalid JSON (parse error), skipped{RESET}");
            continue;
        };
        let parsed = parse_proxifly_json(&data);
        let total: usize = parsed.values().map(|v| v.len()).sum();
        for (proto, list) in parsed {
            if let Some(bucket) = buckets.get_mut(proto) {
                bucket.extend(list);
            }
        }
        println!("{GREEN}  {name} (json): {total} proxies across all protocols{RESET}");
    }
    buckets
}

async fn fetch_proxies(ctx: &Ctx, protocol: &str, extra: &[String]) -> Vec<String> {
    let sources = proxy_sources(protocol);
    let up = protocol.to_uppercase();
    if sources.is_empty() && extra.is_empty() {
        println!("{RED}No sources configured for {up}.{RESET}");
        return Vec::new();
    }

    println!(
        "{CYAN}Fetching {up} proxies from {} text source(s)...{RESET}",
        sources.len()
    );
    let mut merged: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for url in sources {
        let name = source_name(url);
        let resp = match ctx.http.get(*url).timeout(Duration::from_secs(15)).send().await {
            Ok(r) => r,
            Err(e) => {
                println!("{YELLOW}  {name}: unreachable ({}), skipped{RESET}", describe_err(&e));
                continue;
            }
        };
        if resp.status().as_u16() != 200 {
            println!(
                "{YELLOW}  {name}: HTTP {}, skipped{RESET}",
                resp.status().as_u16()
            );
            continue;
        }
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                println!("{YELLOW}  {name}: unreachable ({}), skipped{RESET}", describe_err(&e));
                continue;
            }
        };
        let mut count = 0usize;
        for line in text.lines().map(str::trim) {
            if line.is_empty() || !line.contains(':') || line.contains(' ') {
                continue;
            }
            count += 1;
            if seen.insert(line.to_string()) {
                merged.push(line.to_string());
            }
        }
        println!("{GREEN}  {name}: {count} proxies{RESET}");
    }

    for p in extra {
        if seen.insert(p.clone()) {
            merged.push(p.clone());
        }
    }

    println!(
        "{GREEN}Total unique {up} proxies after merging: {}.{RESET}",
        merged.len()
    );
    merged
}

fn fraud_score_int(item: &ProxyResult) -> i64 {
    item.meta.fraud_score.trim().parse::<i64>().unwrap_or(101)
}

fn ir_nodes_ok_count(info: &IranInfo) -> i64 {
    info.nodes_ok
        .split('/')
        .next()
        .and_then(|n| n.trim().parse::<i64>().ok())
        .unwrap_or(-1)
}

fn sort_key(item: &ProxyResult) -> (u8, i64, String, i64) {
    let (was_checked, nodes_ok) = match &item.ir {
        Some(info) => (true, ir_nodes_ok_count(info)),
        None => (false, -1),
    };
    (
        if was_checked { 0 } else { 1 },
        -nodes_ok,
        item.meta.country.clone(),
        fraud_score_int(item),
    )
}

fn write_lines(path: &Path, lines: &[String]) -> Res<()> {
    let mut content = String::new();
    for l in lines {
        content.push_str(l);
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

fn csv_header(check_iran: bool) -> Vec<&'static str> {
    let mut h = vec![
        "Proxy",
        "Protocol",
        "Country",
        "Country Code",
        "Flag",
        "Fraud Score",
        "Risk",
        "VPN",
        "ISP",
        "Latency (ms)",
    ];
    if check_iran {
        h.extend(["Iran Reachable", "Iran Latency (ms)", "Iran Nodes OK"]);
    }
    h
}

fn csv_row(item: &ProxyResult, check_iran: bool) -> Vec<String> {
    let mut row = vec![
        item.proxy.clone(),
        item.protocol.to_uppercase(),
        item.meta.country.clone(),
        item.meta.country_code.clone(),
        item.meta.flag.clone(),
        item.meta.fraud_score.clone(),
        item.meta.risk.clone(),
        item.meta.vpn.clone(),
        item.meta.isp.clone(),
        item.latency.to_string(),
    ];
    if check_iran {
        match &item.ir {
            Some(info) => {
                row.push(info.reachable.clone());
                row.push(info.latency.clone());
                row.push(info.nodes_ok.clone());
            }
            None => {
                row.push("Not Checked".to_string());
                row.push(String::new());
                row.push(String::new());
            }
        }
    }
    row
}

fn write_csv(path: &Path, check_iran: bool, items: &[&ProxyResult]) -> Res<()> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_path(path)?;
    wtr.write_record(csv_header(check_iran))?;
    for item in items {
        wtr.write_record(csv_row(item, check_iran))?;
    }
    wtr.flush()?;
    Ok(())
}

fn normalize_cc(raw: &str) -> String {
    let cc = raw.trim().to_uppercase();
    if cc == "N/A" || cc.is_empty() || cc == "NONE" {
        return "UNKNOWN".to_string();
    }
    let safe: String = cc
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe.is_empty() {
        "UNKNOWN".to_string()
    } else {
        safe
    }
}

async fn process_protocol(ctx: &Arc<Ctx>, protocol: &'static str, proxy_list: &[String]) -> Res<()> {
    let up = protocol.to_uppercase();
    let check_iran = ctx.cfg.check_iran;
    println!("\n{YELLOW}--- Starting {up} Proxy Verification ---{RESET}");
    if proxy_list.is_empty() {
        println!("{RED}No {up} proxies available to check.{RESET}");
        return Ok(());
    }

    let protocol_dir = Path::new("proxies").join("protocol").join(protocol);
    let countries_dir = Path::new("proxies").join("countries").join(protocol);
    fs::create_dir_all(&protocol_dir)?;
    fs::create_dir_all(&countries_dir)?;

    ctx.exceptions.reset();
    ctx.metadata_fallbacks.reset();

    let sem = Arc::new(Semaphore::new(ctx.cfg.max_concurrency));
    let mut set: JoinSet<Option<ProxyResult>> = JoinSet::new();
    let mut results: Vec<ProxyResult> = Vec::new();
    for proxy in proxy_list {
        let permit = sem.clone().acquire_owned().await?;
        let proxy = proxy.clone();
        let ctx = Arc::clone(ctx);
        set.spawn(async move {
            let _permit = permit;
            check_proxy(&ctx, &proxy, protocol).await
        });
        while let Some(joined) = set.try_join_next() {
            if let Ok(Some(r)) = joined {
                results.push(r);
            }
        }
    }
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(r)) = joined {
            results.push(r);
        }
    }

    if check_iran && !results.is_empty() {
        let mut order: Vec<usize> = (0..results.len()).collect();
        order.sort_by_key(|&i| (fraud_score_int(&results[i]), results[i].latency));
        order.truncate(ctx.cfg.iran_check_max);
        println!(
            "{CYAN}Checking Iran reachability for the top {} {up} proxies (of {} alive)...{RESET}",
            order.len(),
            results.len()
        );

        let sem = Arc::new(Semaphore::new(IRAN_CHECK_THREADS));
        let mut set: JoinSet<(usize, IranInfo)> = JoinSet::new();
        for idx in order {
            let permit = sem.clone().acquire_owned().await?;
            let ip = results[idx].proxy.split(':').next().unwrap_or("").to_string();
            let ctx = Arc::clone(ctx);
            set.spawn(async move {
                let _permit = permit;
                (idx, check_iran_reachability(&ctx, &ip).await)
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok((idx, info)) = joined {
                results[idx].ir = Some(info);
            }
        }
    }

    results.sort_by_cached_key(sort_key);

    let all_lines: Vec<String> = results.iter().map(|r| r.proxy.clone()).collect();
    write_lines(&protocol_dir.join("all.txt"), &all_lines)?;
    let all_refs: Vec<&ProxyResult> = results.iter().collect();
    write_csv(&protocol_dir.join("all.csv"), check_iran, &all_refs)?;

    let mut by_country: BTreeMap<String, Vec<&ProxyResult>> = BTreeMap::new();
    for item in &results {
        by_country
            .entry(normalize_cc(&item.meta.country_code))
            .or_default()
            .push(item);
    }
    for (cc, items) in &by_country {
        let lines: Vec<String> = items.iter().map(|r| r.proxy.clone()).collect();
        write_lines(&countries_dir.join(format!("{cc}.txt")), &lines)?;
        write_csv(&countries_dir.join(format!("{cc}.csv")), check_iran, items)?;
    }

    let sub_dir = Path::new("proxies").join("subscriptions");
    fs::create_dir_all(&sub_dir)?;

    let mut country_counters: HashMap<String, usize> = HashMap::new();
    let mut mahsang: Vec<String> = Vec::new();
    let mut v2rayng: Vec<String> = Vec::new();
    let mut exclave: Vec<String> = Vec::new();

    for item in &results {
        let cc = item.meta.country_code.trim().to_uppercase();
        let counter = country_counters.entry(cc.clone()).or_insert(0);
        *counter += 1;
        let remark = format!("{} {} {}", item.meta.flag, cc, counter);
        let proxy = &item.proxy;

        match protocol {
            "http" => {
                mahsang.push(format!("mahsa-http://Og==@{proxy}#{remark}"));
                v2rayng.push(format!("http://Og@{proxy}#{remark}"));
                exclave.push(format!("http://{proxy}#{remark}"));
            }
            "http_tls" => {
                exclave.push(format!("http://{proxy}#{remark}"));
            }
            "socks5" => {
                mahsang.push(format!("socks://Og==@{proxy}#{remark}"));
                v2rayng.push(format!("socks://Og@{proxy}#{remark}"));
                exclave.push(format!("socks5://{proxy}#{remark}"));
            }
            "socks4" => {
                exclave.push(format!("socks4://{proxy}#{remark}"));
            }
            _ => {}
        }
    }

    if !mahsang.is_empty() {
        write_lines(&sub_dir.join(format!("mahsang_{protocol}.txt")), &mahsang)?;
    }
    if !v2rayng.is_empty() {
        write_lines(&sub_dir.join(format!("v2rayng_{protocol}.txt")), &v2rayng)?;
    }
    if !exclave.is_empty() {
        write_lines(&sub_dir.join(format!("exclave_{protocol}.txt")), &exclave)?;
    }

    println!(
        "{BLUE}Finished {up} checks. Found {} live proxies out of {} checked.{RESET}",
        results.len(),
        proxy_list.len()
    );

    let fail_counts = ctx.exceptions.snapshot();
    if !fail_counts.is_empty() {
        println!("{YELLOW}  Failure breakdown for {up}:{RESET}");
        for (reason, count) in &fail_counts {
            println!("    {reason}: {count}");
        }
        let cross = ctx.exceptions.get("failed_cross_check");
        if cross > 0 {
            println!(
                "{YELLOW}  Note: {cross} proxies passed the primary check but failed the cross-check target - these were likely single-purpose relays and were excluded to avoid false positives.{RESET}"
            );
        }
    }

    let fallback_counts = ctx.metadata_fallbacks.snapshot();
    if !fallback_counts.is_empty() {
        let total: u64 = fallback_counts.iter().map(|(_, c)| *c).sum();
        println!("{YELLOW}  Metadata lookups fell back to defaults {total} time(s):{RESET}");
        for (reason, count) in &fallback_counts {
            println!("    {reason}: {count}");
        }
    }
    Ok(())
}

fn make_qr_image(text: &str, file_path: &Path) -> bool {
    let code = match QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "{YELLOW}  Failed to generate QR for {}: {e}{RESET}",
                file_path.display()
            );
            return false;
        }
    };
    let width = code.width();
    let colors = code.to_colors();
    let box_size = 10usize;
    let border = 4usize;
    let dim = (width + 2 * border) * box_size;
    let mut pixels = vec![255u8; dim * dim];
    for (idx, color) in colors.iter().enumerate() {
        if !matches!(color, Color::Dark) {
            continue;
        }
        let mx = idx % width;
        let my = idx / width;
        for dy in 0..box_size {
            let row = ((my + border) * box_size + dy) * dim;
            let start = row + (mx + border) * box_size;
            for px in &mut pixels[start..start + box_size] {
                *px = 0;
            }
        }
    }

    let write = || -> Res<()> {
        let file = fs::File::create(file_path)?;
        let mut encoder = png::Encoder::new(BufWriter::new(file), dim as u32, dim as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&pixels)?;
        writer.finish()?;
        Ok(())
    };
    match write() {
        Ok(()) => true,
        Err(e) => {
            println!(
                "{YELLOW}  Failed to generate QR for {}: {e}{RESET}",
                file_path.display()
            );
            false
        }
    }
}

const SUB_ROWS: [(&str, &str, &str); 7] = [
    ("MahsaNG", "HTTP", "mahsang_http"),
    ("V2rayNG", "HTTP", "v2rayng_http"),
    ("Exclave", "HTTP", "exclave_http"),
    ("Exclave", "HTTP_TLS", "exclave_http_tls"),
    ("Exclave", "SOCKS4", "exclave_socks4"),
    ("V2rayNG", "SOCKS5", "v2rayng_socks5"),
    ("Exclave", "SOCKS5", "exclave_socks5"),
];

fn build_qrs_and_readme() -> Res<()> {
    let repo = std::env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| "username/repo".to_string());
    let branch = std::env::var("GITHUB_REF_NAME").unwrap_or_else(|_| "main".to_string());
    let raw_prefix = format!("https://raw.githubusercontent.com/{repo}/{branch}");

    let sub_dir = Path::new("proxies").join("subscriptions");
    fs::create_dir_all(&sub_dir)?;

    for (_, _, stem) in SUB_ROWS {
        let txt_path = sub_dir.join(format!("{stem}.txt"));
        let qr_path = sub_dir.join(format!("{stem}_qr.png"));
        if txt_path.exists() {
            let sub_url = format!("{raw_prefix}/proxies/subscriptions/{stem}.txt");
            make_qr_image(&sub_url, &qr_path);
        }
    }

    let readme_path = Path::new("README.md");
    if !readme_path.exists() {
        return Ok(());
    }

    let start_tag = "<!-- SUBSCRIPTION_TABLE_START -->";
    let end_tag = "<!-- SUBSCRIPTION_TABLE_END -->";

    let mut table = String::new();
    table.push_str(start_tag);
    table.push('\n');
    table.push_str("| Client | Protocol | Raw Subscription Link (Copyable) | QR Code |\n");
    table.push_str("| :--- | :--- | :--- | :--- |\n");
    for (client, proto, stem) in SUB_ROWS {
        table.push_str(&format!(
            "| **{client}** | {proto} | `{raw_prefix}/proxies/subscriptions/{stem}.txt` | <img src=\"{raw_prefix}/proxies/subscriptions/{stem}_qr.png\" width=\"120\"/> |\n"
        ));
    }
    table.push_str(end_tag);

    let content = fs::read_to_string(readme_path)?;
    let replaced = content.find(start_tag).and_then(|s| {
        content[s..]
            .find(end_tag)
            .map(|e| format!("{}{}{}", &content[..s], table, &content[s + e + end_tag.len()..]))
    });
    let new_content = match replaced {
        Some(c) => c,
        None => format!("{content}\n\n{table}"),
    };
    fs::write(readme_path, new_content)?;
    Ok(())
}

fn run_git(args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn commit_and_push(ctx: &Ctx, message: &str) {
    if !ctx.cfg.git_push {
        return;
    }
    let skipped = || {
        println!(
            "{YELLOW}  Incremental commit/push skipped - the workflow's final commit step will catch it if the job finishes.{RESET}"
        );
    };
    if !run_git(&["add", "-f", "proxies/", "Raw_Sources/", "README.md"]) {
        skipped();
        return;
    }
    if run_git(&["diff", "--cached", "--quiet"]) {
        return;
    }
    if !run_git(&["commit", "-m", message]) {
        skipped();
        return;
    }
    let pushed = run_git(&["push"])
        || (run_git(&["pull", "--rebase", "-X", "theirs"]) && run_git(&["push"]));
    if pushed {
        println!("{GREEN}  Pushed: {message}{RESET}");
    } else {
        skipped();
    }
}

fn read_pool(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .map(|c| {
            c.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Res<()> {
    let cfg = Config::from_env();
    let http = reqwest::Client::builder().user_agent(USER_AGENT).build()?;
    let ctx = Arc::new(Ctx {
        cfg,
        http,
        tls: build_tls_connector(),
        exceptions: SafeCounter::default(),
        metadata_fallbacks: SafeCounter::default(),
    });

    println!("{YELLOW}Initializing Proxies Scan (Rust)...{RESET}");
    println!("{CYAN}=== Start Fetching ==={RESET}");

    let pool_dir = Path::new("Raw_Sources");
    fs::create_dir_all(pool_dir)?;

    println!("{CYAN}Fetching combined JSON proxy feed(s)...{RESET}");
    let json_buckets = fetch_json_proxies(&ctx).await;

    let mut fetched: HashMap<&'static str, Vec<String>> = HashMap::new();
    for proto in PROTOCOLS {
        let pool_file = pool_dir.join(format!("raw_{proto}.txt"));
        let existing_pool = read_pool(&pool_file);

        let extra = json_buckets.get(proto).cloned().unwrap_or_default();
        let new_proxies = fetch_proxies(&ctx, proto, &extra).await;

        if !new_proxies.is_empty() {
            let mut merged_pool: Vec<String> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for p in existing_pool.into_iter().chain(new_proxies) {
                if seen.insert(p.clone()) {
                    merged_pool.push(p);
                }
            }
            if merged_pool.len() > MAX_POOL_SIZE {
                merged_pool = merged_pool.split_off(merged_pool.len() - MAX_POOL_SIZE);
            }
            write_lines(&pool_file, &merged_pool)?;
            fetched.insert(proto, merged_pool);
        } else {
            println!(
                "{YELLOW}API unavailable. Scanning existing raw {} proxies from local cache...{RESET}",
                proto.to_uppercase()
            );
            fetched.insert(proto, existing_pool);
        }
    }

    println!("\n{CYAN}=== Start Scanning ==={RESET}");
    for proto in PROTOCOLS {
        let list = fetched.remove(proto).unwrap_or_default();
        if let Err(e) = process_protocol(&ctx, proto, &list).await {
            println!("{RED}Error while processing {}: {e}{RESET}", proto.to_uppercase());
        }
        commit_and_push(&ctx, &format!("Update {} proxies list", proto.to_uppercase()));
    }

    println!("\n{CYAN}=== Generating QR Codes & Updating README ==={RESET}");
    if let Err(e) = build_qrs_and_readme() {
        println!("{YELLOW}  README/QR step failed: {e}{RESET}");
    }
    commit_and_push(&ctx, "Update subscriptions, QR codes and README");

    println!("\n{YELLOW}Reminder: free public proxies can go dead within minutes of being verified.{RESET}");
    println!(
        "{YELLOW}Use freshly-scanned proxies as soon as possible, and prefer lower values in the 'Latency (ms)' column in each CSV for the best chance of them working in your client.{RESET}"
    );
    Ok(())
}
