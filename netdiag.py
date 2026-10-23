#!/usr/bin/env python3
"""
NetDiag - Network & Censorship Diagnostic Tool
================================================
Version:  3.3.4 | License: MIT
Author:   Majid Mousavian Nezhadsadghi
Repo:     https://github.com/Iliad1598/NetDiag

Copyright (c) 2026 Majid Mousavian Nezhadsadghi

Comprehensive cross-platform diagnostic tool:
  • Connectivity: Ping, DNS, HTTP, SSL, MTU, Bandwidth, Speedtest
  • Route: Traceroute with IP classification (LAN/CGNAT/ISP/INT/DST)
  • CDN: Cloudflare, Akamai, Fastly, CloudFront detection
  • Censorship: SNI-DPI, DNS interception, HTTP blocking, blockpage
  • Advanced: TLS fragmentation test, IPv6, HTTP/3 (QUIC)

Install:
    pip install -r requirements.txt

Usage:
    python netdiag.py                        # GUI
    python netdiag.py --cli                  # CLI
    python netdiag.py --cli --quick          # Fast run
    python netdiag.py --cli --tls-frag       # Include fragmentation test
    python netdiag.py --selftest             # Verify installation

Changelog v3.3.4 (bug-fix release):
    • Speedtest: daemon thread + join(timeout) — timeout now truly aborts.
    • GUI: Tkinter variables snapshotted in main thread before worker starts.
    • DiagnosticModule.execute: removed retry-on-ValueError/TypeError that
      could run a method twice. Signature inspection is done once.
    • IPv6 module: TCP6 socket closed in finally (no leak).
    • QUIC module: Alt-Svc response closed via context manager.
    • TLS fragmentation test: ConnectionResetError mapped to TCP_RESET;
      socket closing centralized in one finally block.
    • SSL module: uses ssl.cert_time_to_seconds() for robust parsing.
    • interpret_domain_status: DNS_FAIL and CONN_ERROR now explicit.
    • Subprocess calls (MTU / traceroute fallback) no longer use shell=True
      with f-strings — argument lists are safe against special characters.
    • MTU discovery: locale-agnostic ping result parsing. Uses protocol-level
      tokens (TTL=, DF set) and Persian keywords, so MTU detection now works
      on Persian/Arabic Windows installations too — not only on English ones.
    • IPv6 renderer: no hardcoded "google.com" — shows tested domain.
    • Blockpage check: strips only leading "www." prefix.
    • HTTP health: proper User-Agent header; skips sleep after last ping.
    • Removed redundant "except (FutureTimeoutError, Exception)" patterns.
    • GUI "Clear All": also resets stdout redirect buffer.
"""

__version__ = "3.3.4"
__license__ = "MIT"
__author__ = "Majid Mousavian Nezhadsadghi"
__github__ = "https://github.com/YOUR_USERNAME/NetDiag"

# ============================================================
# Silence noisy libraries
# ============================================================
import warnings
warnings.filterwarnings("ignore")
import logging
for _n in ("scapy.runtime", "scapy.loading"):
    logging.getLogger(_n).setLevel(logging.ERROR)

# ============================================================
# Standard library
# ============================================================
import argparse
import contextlib
import csv
import inspect
import io
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ============================================================
# Third-party core
# ============================================================
import ping3
import dns.resolver
from dns import message as dns_message, query as dns_query
import requests
import urllib3
import psutil
import speedtest
import icmplib

# requests/urllib3 may emit InsecureRequestWarning if verification is
# intentionally disabled somewhere; keep the output clean.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# Optional dependencies
# ============================================================
try:
    from scapy.all import IP, ICMP, sr1  # noqa: F401
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from OpenSSL import SSL  # noqa: F401
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
    HAS_TK = True
except ImportError:
    HAS_TK = False


# ============================================================
# Constants
# ============================================================
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
SHARED_100_8 = ipaddress.ip_network("100.0.0.0/8")
USER_AGENT = f"Mozilla/5.0 (compatible; NetDiag/{__version__})"

IPV6_TEST_TARGETS = [
    ("Google DNS", "2001:4860:4860::8888", 53),
    ("Cloudflare DNS", "2606:4700:4700::1111", 53),
    ("Google HTTPS", "2001:4860:4860::8888", 443),
]

HOP_LABELS = {
    "loopback": "LOOP", "local": "LAN", "cgnat": "CGNAT", "isp": "ISP",
    "domestic": "DOM", "international": "INT", "target": "DST",
    "timeout": "---", "unknown": "???",
}


# ============================================================
# Utilities
# ============================================================
def classify_ip(ip_str, target_ips, prev_class):
    """Classify an IP address into a hop category (no GeoIP)."""
    if not ip_str:
        return "timeout"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj in CGNAT_NET:
        return "cgnat"
    if ip_obj.is_link_local:
        return "local"
    if ip_obj.is_private:
        # Private IP seen after leaving the local network => it belongs
        # to the ISP side (some ISPs use RFC1918 space in their core).
        if prev_class in ("international", "domestic", "isp", "cgnat"):
            return "isp"
        return "local"
    if ip_obj in SHARED_100_8:
        # Shared address space (100.0.0.0/8 minus CGNAT handled above):
        # near the user it is the ISP, otherwise we cannot tell.
        if prev_class in ("local", "cgnat", "isp", "timeout", "loopback"):
            return "isp"
        return "unknown"
    if ip_str in target_ips:
        return "target"
    return "international"


def is_private_or_special(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (ip_obj.is_private or ip_obj.is_loopback
                or ip_obj.is_link_local or ip_obj in CGNAT_NET)
    except (ValueError, TypeError):
        return False


def interpret_domain_status(status, detail):
    """Translate a raw test status into a normalized interpretation."""
    if status == "OK":
        return "allowed"
    if status == "DNS_FAIL":
        return "dns_fail"
    if status == "TIMEOUT":
        return "blocked_timeout"
    if status in ("TCP_RESET", "CONNECT_RESET"):
        return "blocked_rst"
    if status == "SSL_ERROR":
        du = (detail or "").upper()
        if "WRONG_VERSION_NUMBER" in du or "UNEXPECTED_EOF" in du:
            return "blocked_sni_dpi"
        return "blocked_ssl"
    if status == "ERROR":
        dl = (detail or "").lower()
        if any(x in dl for x in ["refused", "10061", "unreachable", "10051"]):
            return "blocked_error"
        return "error"
    if status == "CONN_ERROR":
        du = (detail or "").lower()
        if any(x in du for x in ["refused", "10061", "unreachable", "10051"]):
            return "blocked_error"
        return "conn_error"
    return "unknown"


# ============================================================
# Base Module
# ============================================================
class DiagnosticModule:
    """Runs a list of alternative methods until one returns a truthy result.

    FIX: the previous implementation re-invoked a method whenever it raised
    ValueError/TypeError, which was meant to handle argument-binding issues
    but actually re-executed methods whose *body* raised those errors
    (double side effects). Signature inspection is now performed once and
    failures simply move to the next method.
    """

    def __init__(self, name):
        self.name = name
        self.methods = []

    def add_method(self, method):
        self.methods.append(method)

    def execute(self, *args, progress_cb=None, **kwargs):
        total = len(self.methods)
        if total == 0:
            return None
        print(f"\n[*] [{self.name}] Trying {total} method(s)...")
        for idx, method in enumerate(self.methods, 1):
            name = method.__name__.lstrip("_")
            if progress_cb:
                progress_cb((idx - 1) / total, f"Method {idx}/{total}: {name}")
            print(f"    -> Method {idx}: {name}")
            # Inspect the signature once - never retry a failed method.
            try:
                sig = inspect.signature(method)
                wants_progress = "progress_cb" in sig.parameters
            except (TypeError, ValueError):
                wants_progress = False
            try:
                if wants_progress:
                    r = method(*args, progress_cb=progress_cb, **kwargs)
                else:
                    r = method(*args, **kwargs)
            except Exception as e:
                print(f"       [FAIL] {type(e).__name__}: {e}")
                continue
            if r:
                print("       [OK]")
                if progress_cb:
                    progress_cb(idx / total, f"[OK] {name}")
                return r
            print("       [FAIL] empty result")
        print("    [!] All methods failed.")
        if progress_cb:
            progress_cb(1.0, "[FAIL] all failed")
        return None


# ============================================================
# 1. Ping
# ============================================================
class PingModule(DiagnosticModule):
    def __init__(self):
        super().__init__("Ping")
        self.add_method(self._icmp)
        self.add_method(self._tcp)
        if HAS_SCAPY:
            self.add_method(self._scapy)

    def _icmp(self, host, count=4, timeout=2, **_):
        try:
            ds = []
            for i in range(count):
                d = ping3.ping(host, timeout=timeout, unit="ms")
                if d is not None and d is not False:
                    ds.append(float(d))
                # FIX: do not sleep after the last attempt (wasted time).
                if i < count - 1:
                    time.sleep(0.3)
            if not ds:
                return None
            return {"method": "ICMP (ping3)",
                    "avg_ms": round(sum(ds) / len(ds), 2),
                    "min_ms": round(min(ds), 2), "max_ms": round(max(ds), 2),
                    "loss_percent": round((count - len(ds)) / count * 100, 1)}
        except Exception:
            return None

    def _tcp(self, host, port=443, timeout=3, **_):
        try:
            s = time.time()
            with socket.create_connection((host, port), timeout=timeout):
                pass
            e = (time.time() - s) * 1000
            return {"method": f"TCP:{port}", "avg_ms": round(e, 2),
                    "min_ms": round(e, 2), "max_ms": round(e, 2),
                    "loss_percent": 0.0}
        except Exception:
            return None

    def _scapy(self, host, count=3, timeout=2, **_):
        try:
            ds = []
            for i in range(count):
                s = time.time()
                r = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=False)
                if r is not None:
                    ds.append((time.time() - s) * 1000)
                if i < count - 1:
                    time.sleep(0.3)
            if not ds:
                return None
            return {"method": "ICMP (Scapy)", "avg_ms": round(sum(ds) / len(ds), 2),
                    "min_ms": round(min(ds), 2), "max_ms": round(max(ds), 2),
                    "loss_percent": round((count - len(ds)) / count * 100, 1)}
        except Exception:
            return None


# ============================================================
# 2. DNS
# ============================================================
class DNSModule(DiagnosticModule):
    def __init__(self):
        super().__init__("DNS")
        self.add_method(self._udp)
        self.add_method(self._tcp)
        self.add_method(self._doh)
        self.add_method(self._system)

    @staticmethod
    def _extract_records(answer):
        recs = []
        for a in answer:
            for i in a:
                addr = getattr(i, "address", None)
                if addr:
                    recs.append(str(addr))
        return recs

    def _udp(self, domain, server="8.8.8.8", timeout=3, **_):
        try:
            q = dns_message.make_query(domain, "A")
            r = dns_query.udp(q, server, timeout=timeout)
            recs = self._extract_records(r.answer)
            if recs:
                return {"method": f"UDP DNS ({server})", "records": recs}
        except Exception:
            pass
        return None

    def _tcp(self, domain, server="8.8.8.8", timeout=3, **_):
        try:
            q = dns_message.make_query(domain, "A")
            r = dns_query.tcp(q, server, timeout=timeout)
            recs = self._extract_records(r.answer)
            if recs:
                return {"method": f"TCP DNS ({server})", "records": recs}
        except Exception:
            pass
        return None

    def _doh(self, domain, server="https://cloudflare-dns.com/dns-query", **_):
        try:
            q = dns_message.make_query(domain, "A")
            r = dns_query.https(q, server, timeout=5)
            recs = self._extract_records(r.answer)
            if recs:
                return {"method": "DoH", "records": recs}
        except Exception:
            pass
        return None

    def _system(self, domain, **_):
        try:
            ips = socket.getaddrinfo(domain, None)
            recs = sorted({a[4][0] for a in ips if a[0] == socket.AF_INET})
            if recs:
                return {"method": "System resolver", "records": recs}
        except Exception:
            pass
        return None


# ============================================================
# 3. HTTP
# ============================================================
class HTTPHealthModule(DiagnosticModule):
    def __init__(self):
        super().__init__("HTTP")
        self.add_method(self._head)

    def _head(self, url, timeout=8, **_):
        headers = {"User-Agent": USER_AGENT}
        try:
            # Warm-up request (DNS + TCP + TLS caches get populated).
            try:
                requests.head(url, timeout=timeout, allow_redirects=True,
                              headers=headers)
            except Exception:
                pass
            s = time.time()
            r = requests.head(url, timeout=timeout, allow_redirects=True,
                              headers=headers)
            return {"method": "HEAD (warmed)", "status_code": r.status_code,
                    "response_time_ms": round((time.time() - s) * 1000, 2)}
        except Exception:
            return None


# ============================================================
# 4. SSL
# ============================================================
class SSLModule(DiagnosticModule):
    def __init__(self):
        super().__init__("SSL")
        self.add_method(self._check)

    def _check(self, hostname, port=443, timeout=5, **_):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                    cert = s.getpeercert()
                    if not cert or "notAfter" not in cert:
                        return None
                    # FIX: ssl.cert_time_to_seconds() is the robust stdlib
                    # way to parse the ASN.1/SSL "notAfter" string.
                    exp = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(cert["notAfter"]),
                        tz=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    issuer = dict(x[0] for x in cert["issuer"])
                    subject = dict(x[0] for x in cert["subject"])
                    return {"method": "ssl (stdlib)",
                            "issuer": issuer.get("organizationName", "N/A"),
                            "subject": subject.get("commonName", "N/A"),
                            "expiry": cert["notAfter"], "days_left": days,
                            "version": s.version()}
        except Exception:
            return None


# ============================================================
# 5. Public IP
# ============================================================
class PublicIPModule(DiagnosticModule):
    PROVIDERS = [
        ("ipify-https", "https://api.ipify.org?format=json", "json", "ip"),
        ("ipify-http", "http://api.ipify.org?format=json", "json", "ip"),
        ("ipinfo", "https://ipinfo.io/ip", "text", None),
        ("ifconfig-co", "https://ifconfig.co/ip", "text", None),
        ("ip-api", "http://ip-api.com/line/?fields=query", "text", None),
        ("icanhazip", "https://icanhazip.com", "text", None),
    ]
    HEADERS = {"User-Agent": USER_AGENT}

    def __init__(self):
        super().__init__("Public IP")
        for n, u, f, k in self.PROVIDERS:
            self.add_method(self._make(n, u, f, k))

    def _make(self, name, url, fmt, key):
        # Closure created through a factory => no late-binding problem.
        def m(**_):
            try:
                r = requests.get(url, timeout=10, headers=self.HEADERS)
                ip = r.json().get(key) if fmt == "json" else r.text.strip()
                if ip and self._valid(str(ip)):
                    return {"method": f"API: {name}", "ip": str(ip)}
            except Exception:
                pass
            return None
        m.__name__ = f"_ip_{name.replace('.', '_').replace('-', '_')}"
        return m

    @staticmethod
    def _valid(ip):
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(fam, ip.strip())
                return True
            except (OSError, ValueError):
                continue
        return False


# ============================================================
# 6. MTU  (locale-agnostic parsing - FIX v3.3.4)
# ============================================================
class MTUModule(DiagnosticModule):
    def __init__(self):
        super().__init__("MTU")
        self.add_method(self._binsearch)

    @staticmethod
    def _ping_succeeded(returncode, output_lower):
        """Locale-agnostic ping result parser.

        Success indicators:
          - 'ttl=' appears only in successful replies; TTL is a protocol
            field shown in English even on localized Windows.
          - 'reply from' / 'bytes from' (English Windows/Linux)
          - 'پاسخ از' / 'بایت از' (Persian "reply from" / "bytes from")
              as a fallback for older Persian Windows that localize labels.

        Failure indicators:
          - 'fragmented' / 'packet needs' / 'df set' (Windows DF error)
          - 'message too long' / 'too long' (Linux)
          - 'تکه' (Persian "fragment")
          - '100% loss/lost' (total packet loss — packet was dropped)

        Note: on Windows, *both* success and fragmentation errors return
        exit code 0, so exit code alone is not sufficient; the text check
        is required. On Linux, exit code is 0 only on success, but we still
        validate the text for consistency across platforms.
        """
        out = output_lower

        has_reply = (
            "ttl=" in out
            or "ttl =" in out
            or "reply from" in out
            or "bytes from" in out
            or "پاسخ از" in out
            or "بایت از" in out
        )

        is_frag_error = (
            "fragmented" in out
            or "packet needs" in out
            or "df set" in out
            or "message too long" in out
            or "too long" in out
            or "تکه" in out
        )

        is_total_loss = (
            "100%" in out
            and ("loss" in out or "lost" in out or "از دست" in out)
        )

        return (
            returncode == 0
            and has_reply
            and not is_frag_error
            and not is_total_loss
        )

    def _binsearch(self, target="8.8.8.8", timeout=2, progress_cb=None):
        system = platform.system().lower()
        low, high, best = 500, 1472, None
        it = 0
        try:
            while low <= high and it < 12:
                it += 1
                if progress_cb:
                    progress_cb(it / 12, f"payload={(low + high) // 2}")
                mid = (low + high) // 2

                # Arguments passed as a list (no shell=True) - safe against
                # special characters in the target.
                if "windows" in system:
                    cmd = ["ping", "-n", "1", "-f", "-l", str(mid),
                           "-w", str(timeout * 1000), target]
                else:
                    cmd = ["ping", "-c", "1", "-M", "do", "-s", str(mid),
                           "-W", str(timeout), target]

                try:
                    r = subprocess.run(cmd, capture_output=True,
                                       text=True, timeout=timeout + 2)
                    out = (r.stdout + r.stderr).lower()
                    if self._ping_succeeded(r.returncode, out):
                        best = mid
                        low = mid + 1
                    else:
                        high = mid - 1
                except (subprocess.TimeoutExpired, OSError):
                    high = mid - 1

            if best:
                if progress_cb:
                    progress_cb(1.0, f"MTU={best + 28}")
                return {"method": "Binary search (ping DF)",
                        "mtu": best + 28, "payload": best}
        except Exception:
            pass
        return None


# ============================================================
# 7. Speedtest
# ============================================================
class SpeedtestModule(DiagnosticModule):
    def __init__(self):
        super().__init__("Speedtest")
        self.add_method(self._run)

    def _run(self, timeout=90, progress_cb=None):
        def _inner():
            if progress_cb:
                progress_cb(0.05, "Finding server...")
            st = speedtest.Speedtest()
            st.get_best_server()
            if progress_cb:
                progress_cb(0.15, "Download...")
            d = st.download() / 1_000_000
            if progress_cb:
                progress_cb(0.60, "Upload...")
            u = st.upload() / 1_000_000
            if progress_cb:
                progress_cb(1.0, "Done")
            return {"method": "Ookla", "download_mbps": round(d, 2),
                    "upload_mbps": round(u, 2), "ping_ms": st.results.ping}

        # FIX: the old code used `with ThreadPoolExecutor(...)`, whose
        # __exit__ waits for the worker thread to finish (shutdown(wait=True)),
        # making the `timeout` parameter completely ineffective - a hung
        # speedtest froze the whole application. A daemon worker thread with
        # join(timeout) is used instead: the timeout truly aborts AND the
        # (possibly still-hung) thread cannot block interpreter exit.
        result_holder = []

        def _worker():
            try:
                result_holder.append(_inner())
            except Exception:
                result_holder.append(None)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            print(f"       [!] Speedtest timed out after {timeout}s")
            return None
        return result_holder[0] if result_holder else None


# ============================================================
# 8. DPI/SNI
# ============================================================
class DPISNIModule(DiagnosticModule):
    def __init__(self):
        super().__init__("DPI/SNI")
        self.add_method(self._check)

    def _check(self, hostname, port=443, timeout=5, **_):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                    return {"method": "TLS handshake", "status": "OK",
                            "tls_version": s.version(),
                            "cipher": s.cipher()[0] if s.cipher() else None}
        except ssl.SSLError as e:
            return {"method": "TLS handshake", "status": "SSL_ERROR",
                    "detail": str(e)[:80]}
        except Exception as e:
            return {"method": "TLS handshake", "status": "CONN_ERROR",
                    "detail": str(e)[:80]}


# ============================================================
# 9. Bandwidth Monitor
# ============================================================
class BandwidthMonitor:
    def __init__(self, interval=2):
        self.interval = interval

    def sample(self, progress_cb=None):
        try:
            if progress_cb:
                progress_cb(0.1, "Sampling...")
            n1 = psutil.net_io_counters()
            time.sleep(self.interval)
            n2 = psutil.net_io_counters()
            s = n2.bytes_sent - n1.bytes_sent
            r = n2.bytes_recv - n1.bytes_recv
            if progress_cb:
                progress_cb(1.0, "Done")
            return {"upload_kbps": round(s * 8 / (self.interval * 1024), 2),
                    "download_kbps": round(r * 8 / (self.interval * 1024), 2),
                    "upload_mbps": round(s * 8 / (self.interval * 1_000_000), 3),
                    "download_mbps": round(r * 8 / (self.interval * 1_000_000), 3)}
        except Exception:
            return None


# ============================================================
# 10. Traceroute (NO GeoIP — IP classification only)
# ============================================================
class TracerouteModule(DiagnosticModule):
    def __init__(self, probes=2, max_hops=20):
        super().__init__("Traceroute")
        self.probes = probes
        self.max_hops = max_hops
        self.add_method(self._run)

    def _run(self, target, timeout=2, progress_cb=None):
        if progress_cb:
            progress_cb(0.1, "Collecting hops...")
        hops = self._collect(target, timeout)
        if not hops:
            return None
        if progress_cb:
            progress_cb(0.9, "Classifying hops...")
        try:
            target_ips = set(socket.gethostbyname_ex(target)[2])
        except Exception:
            target_ips = {target}

        prev_class = None
        for h in hops:
            h["class"] = classify_ip(h.get("ip"), target_ips, prev_class)
            if h["class"] != "timeout":
                prev_class = h["class"]

        last_rtt = None
        for h in reversed(hops):
            if h.get("rtt_avg") is not None:
                last_rtt = h["rtt_avg"]
                break

        timeouts = sum(1 for h in hops if not h.get("ip"))
        hop_numbers = [h["hop"] for h in hops]
        expected = set(range(min(hop_numbers), max(hop_numbers) + 1)) if hop_numbers else set()
        missing = sorted(expected - set(hop_numbers))

        if progress_cb:
            progress_cb(1.0, "Done")
        return {"method": "Traceroute", "target": target,
                "total_hops": len(hops), "hops": hops,
                "summary": {
                    "total_hops": len(hops),
                    "timeouts": timeouts,
                    "total_rtt_ms": last_rtt,
                    "missing_hops": missing,
                }}

    def _collect(self, target, timeout):
        # Primary: icmplib (pure python)
        try:
            raw = icmplib.traceroute(target, max_hops=self.max_hops,
                                     timeout=timeout, count=self.probes)
            hops = [{"hop": h.distance,
                     "ip": h.address if h.is_alive else None,
                     "rtt_min": round(h.min_rtt, 2) if h.is_alive else None,
                     "rtt_avg": round(h.avg_rtt, 2) if h.is_alive else None,
                     "rtt_max": round(h.max_rtt, 2) if h.is_alive else None}
                    for h in raw]
            if hops:
                return hops
        except Exception:
            pass
        # Fallback: system traceroute binary
        # FIX: no shell=True with f-strings - argument list is safe.
        try:
            if platform.system().lower() == "windows":
                cmd = ["tracert", "-d", "-h", str(self.max_hops),
                       "-w", str(timeout * 1000), target]
            else:
                cmd = ["traceroute", "-n", "-m", str(self.max_hops),
                       "-w", str(timeout), target]
            r = subprocess.run(cmd, capture_output=True,
                               text=True, timeout=180)
            hops = []
            for line in r.stdout.splitlines():
                m = re.match(r"^(\d+)\s+(.+)$", line.strip())
                if not m:
                    continue
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", m.group(2))
                rtts = [float(x) for x in re.findall(r"<?(\d+)\s*ms", m.group(2))]
                hops.append({"hop": int(m.group(1)),
                             "ip": ip_m.group(1) if ip_m else None,
                             "rtt_min": min(rtts) if rtts else None,
                             "rtt_avg": round(sum(rtts) / len(rtts), 2) if rtts else None,
                             "rtt_max": max(rtts) if rtts else None})
            return hops if hops else None
        except Exception:
            return None


# ============================================================
# 11. TLS Fragmentation
# ============================================================
class TLSFragmentationModule:
    """
    Tests whether fragmenting the TLS ClientHello bypasses SNI-based DPI.

    Mechanism:
    1. Build a normal ClientHello via ssl.MemoryBIO
    2. Split it into N small TCP segments (default 3, 10, 50 bytes)
    3. Send each segment with TCP_NODELAY and a tiny delay
    4. See if the TLS handshake completes

    Verdicts:
    - NO_BYPASS_NEEDED: whole ClientHello works (target not blocked)
    - FRAGMENTATION_BYPASS_WORKS: whole fails but fragmented works -> DPI is
      not TCP-reassembly-aware
    - DPI_REASSEMBLES_FRAGMENTS: both fail -> DPI does TCP reassembly
    - INCONCLUSIVE: mixed results
    """

    def test(self, targets=None, fragment_sizes=(3, 10, 50), progress_cb=None):
        if targets is None:
            targets = ["twitter.com", "www.youtube.com", "www.google.com"]
        results = {"targets": targets, "by_target": {}, "conclusion": "UNKNOWN"}

        for ti, target in enumerate(targets):
            if progress_cb:
                progress_cb(ti / len(targets), f"Target {target}")
            print(f"\n    Testing fragmentation on {target}...")
            base = self._try_whole(target)
            print(f"      whole ClientHello: {base.get('status', '?')}")
            tr = {"whole": base, "fragmented": {}}
            for size in fragment_sizes:
                r = self._try_fragmented(target, size)
                tr["fragmented"][str(size)] = r
                print(f"      fragmented ({size}B): {r.get('status', '?')}")
            results["by_target"][target] = tr

        if progress_cb:
            progress_cb(1.0, "Done")
        results["conclusion"] = self._conclude(results)
        print(f"    Conclusion: {results['conclusion']}")
        return results

    @staticmethod
    def _conclude(results):
        bypass_works = False
        dpi_reassembles = False
        no_issue = True
        for target, data in results.get("by_target", {}).items():
            whole = data.get("whole", {}).get("status")
            frag_results = data.get("fragmented", {})
            if whole == "OK":
                continue
            no_issue = False
            any_frag_ok = any(r.get("status") == "OK" for r in frag_results.values())
            all_frag_failed = all(
                r.get("status") in ("SSL_ERROR", "TCP_RESET", "TIMEOUT", "CLOSED")
                for r in frag_results.values())
            if any_frag_ok:
                bypass_works = True
            elif all_frag_failed:
                dpi_reassembles = True
        if no_issue:
            return "NO_BYPASS_NEEDED"
        if bypass_works:
            return "FRAGMENTATION_BYPASS_WORKS"
        if dpi_reassembles:
            return "DPI_REASSEMBLES_FRAGMENTS"
        return "INCONCLUSIVE"

    def _try_whole(self, hostname, port=443, timeout=5):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return {"status": "OK"}
        except ssl.SSLError as e:
            return {"status": "SSL_ERROR", "detail": str(e)[:80]}
        except ConnectionResetError:
            # FIX: DPI resets were previously reported as generic ERROR,
            # while the verdict logic expects TCP_RESET.
            return {"status": "TCP_RESET"}
        except socket.timeout:
            return {"status": "TIMEOUT"}
        except Exception as e:
            return {"status": "ERROR", "detail": str(e)[:80]}

    def _try_fragmented(self, hostname, fragment_size, port=443, timeout=6):
        sock = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            incoming = ssl.MemoryBIO()
            outgoing = ssl.MemoryBIO()
            sslobj = ctx.wrap_bio(incoming, outgoing, server_hostname=hostname)
            try:
                sslobj.do_handshake()
            except ssl.SSLWantReadError:
                pass
            client_hello = outgoing.read()
            if not client_hello:
                return {"status": "ERROR", "detail": "no ClientHello generated"}

            sock = socket.create_connection((hostname, port), timeout=timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            for i in range(0, len(client_hello), fragment_size):
                sock.sendall(client_hello[i:i + fragment_size])
                time.sleep(0.003)

            for _ in range(30):
                try:
                    sslobj.do_handshake()
                    return {"status": "OK",
                            "client_hello_bytes": len(client_hello),
                            "fragment_size": fragment_size}
                except ssl.SSLWantReadError:
                    data = sock.recv(8192)
                    if not data:
                        return {"status": "CLOSED"}
                    incoming.write(data)
                except ssl.SSLError as e:
                    return {"status": "SSL_ERROR", "detail": str(e)[:80]}
            return {"status": "TIMEOUT", "detail": "handshake did not complete"}
        except ssl.SSLError as e:
            return {"status": "SSL_ERROR", "detail": str(e)[:80]}
        except ConnectionResetError:
            # FIX: mapped to TCP_RESET (expected by the verdict logic),
            # previously fell through to a generic ERROR.
            return {"status": "TCP_RESET"}
        except socket.timeout:
            return {"status": "TIMEOUT"}
        except Exception as e:
            return {"status": "ERROR", "detail": str(e)[:80]}
        finally:
            # FIX: single centralized close - the old code closed the socket
            # on several return paths AND again in finally (double close).
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


# ============================================================
# 12. IPv6 (with PRIVATE_ONLY verdict)
# ============================================================
class IPv6Module:
    def test(self, domain="google.com", progress_cb=None):
        print("\n[*] [IPv6] Analyzing IPv6 capability...")
        r = {"domain": domain}
        if progress_cb:
            progress_cb(0.0, "System addresses...")
        r["system_addresses"] = self._get_system_addrs()
        global_count = sum(1 for a in r["system_addresses"] if a.get("is_global"))
        print(f"    System IPv6 addresses: {len(r['system_addresses'])} ({global_count} global)")

        if progress_cb:
            progress_cb(0.3, f"AAAA for {domain}...")
        r["aaaa_resolution"] = self._resolve_aaaa(domain)
        print(f"    AAAA records ({domain}): {len(r['aaaa_resolution'])}")

        if progress_cb:
            progress_cb(0.5, "TCP6 tests...")
        r["tcp6_tests"] = {}
        for i, (label, ip, port) in enumerate(IPV6_TEST_TARGETS):
            if progress_cb:
                progress_cb(0.5 + i * 0.15, f"TCP6 to {label}...")
            rr = self._tcp6_test(ip, port)
            r["tcp6_tests"][label] = rr
            print(f"    TCP6 {label} ([{ip}]:{port}): {rr['status']}")

        if progress_cb:
            progress_cb(0.95, "Classifying...")
        r["verdict"], r["verdict_reason"] = self._classify(r)
        print(f"    IPv6 Verdict: {r['verdict']} ({r['verdict_reason']})")
        if progress_cb:
            progress_cb(1.0, f"IPv6: {r['verdict']}")
        return r

    def _get_system_addrs(self):
        out = []
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET6:
                        addr = a.address.split("%")[0]
                        is_loopback = addr == "::1"
                        is_linklocal = addr.lower().startswith("fe80")
                        is_ula = (addr.lower().startswith("fd")
                                  or addr.lower().startswith("fc"))
                        is_global = not (is_loopback or is_linklocal or is_ula)
                        out.append({"interface": iface, "address": addr,
                                    "is_loopback": is_loopback,
                                    "is_link_local": is_linklocal,
                                    "is_ula": is_ula,
                                    "is_global": is_global})
        except Exception:
            pass
        return out

    def _resolve_aaaa(self, domain):
        try:
            answers = dns.resolver.resolve(domain, "AAAA")
            return [str(r) for r in answers]
        except Exception:
            return []

    def _tcp6_test(self, ip, port, timeout=5):
        r = {"target": f"[{ip}]:{port}", "status": "UNKNOWN"}
        sock = None
        try:
            s = time.time()
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port, 0, 0))
            r["status"] = "OPEN"
            r["elapsed_ms"] = round((time.time() - s) * 1000, 2)
        except ConnectionRefusedError:
            r["status"] = "REFUSED"
        except socket.timeout:
            r["status"] = "TIMEOUT"
        except OSError as e:
            r["status"] = "NO_ROUTE"
            r["detail"] = str(e)[:60]
        except Exception as e:
            r["status"] = "ERROR"
            r["detail"] = str(e)[:60]
        finally:
            # FIX: the socket leaked (was never closed) on every error path.
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return r

    def _classify(self, r):
        addrs = r.get("system_addresses", [])
        global_addrs = [a for a in addrs if a.get("is_global")]
        ula_addrs = [a for a in addrs if a.get("is_ula")]
        linklocal_addrs = [a for a in addrs if a.get("is_link_local")]
        aaaa = r.get("aaaa_resolution", [])
        tcp6 = r.get("tcp6_tests", {})
        any_open = any(v.get("status") == "OPEN" for v in tcp6.values())
        all_timeout = all(v.get("status") in ("TIMEOUT", "NO_ROUTE")
                          for v in tcp6.values()) if tcp6 else False

        if not addrs and not aaaa:
            return "NO_IPV6", "no addresses, no AAAA"
        if global_addrs and any_open:
            return "FULL", "global IPv6 + TCP6 works"
        if not global_addrs and (ula_addrs or linklocal_addrs) and not any_open:
            # Distinguish PRIVATE_ONLY (ULA) from LOCAL_ONLY (link-local only)
            if ula_addrs:
                return "PRIVATE_ONLY", "only ULA (fd00::/8) + link-local"
            return "LOCAL_ONLY", "only link-local"
        if aaaa and not addrs and all_timeout:
            return "AAAA_NO_ROUTE", "AAAA resolves but no TCP6 route"
        if any_open:
            return "PARTIAL", "TCP6 works but no global IPv6"
        return "PARTIAL", "mixed results"


# ============================================================
# 13. HTTP/3 (QUIC)
# ============================================================
class QUICModule:
    def test(self, hostname="www.google.com", progress_cb=None):
        print(f"\n[*] [HTTP/3] Analyzing QUIC support for {hostname}...")
        r = {"hostname": hostname}
        if progress_cb:
            progress_cb(0.0, "Alt-Svc header...")
        r["alt_svc"] = self._check_alt_svc(hostname)
        print(f"    Alt-Svc: {r['alt_svc'].get('verdict', '?')}")

        if progress_cb:
            progress_cb(0.6, "UDP/443 probe...")
        r["udp_probe"] = self._probe_udp443(hostname)
        print(f"    UDP/443: {r['udp_probe'].get('status', '?')}")

        r["verdict"], r["verdict_reason"] = self._classify(r)
        print(f"    HTTP/3 Verdict: {r['verdict']}")
        if progress_cb:
            progress_cb(1.0, f"HTTP/3: {r['verdict']}")
        return r

    def _check_alt_svc(self, hostname, timeout=8):
        r = {"header": None, "verdict": "UNKNOWN"}
        try:
            # FIX: context manager guarantees the streamed response body is
            # released even if an exception occurs.
            with requests.get(f"https://{hostname}", timeout=timeout,
                              headers={"User-Agent": USER_AGENT},
                              stream=True) as resp:
                alt = resp.headers.get("Alt-Svc", "")
            r["header"] = alt[:200] if alt else "absent"
            if "h3" in alt.lower():
                r["verdict"] = "ADVERTISED"
                m = re.search(r"h3-(\d+)", alt)
                r["h3_version"] = f"h3-{m.group(1)}" if m else "h3"
            else:
                r["verdict"] = "NOT_ADVERTISED"
        except Exception as e:
            r["verdict"] = "ERROR"
            r["error"] = str(e)[:60]
        return r

    def _probe_udp443(self, hostname, timeout=3):
        r = {"status": "UNKNOWN"}
        try:
            ip = socket.gethostbyname(hostname)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(timeout)
                sock.sendto(b"\xc0\x00\x00\x00\x01", (ip, 443))
                try:
                    data, _ = sock.recvfrom(1024)
                    r["status"] = "RESPONSE"
                    r["bytes"] = len(data)
                except socket.timeout:
                    r["status"] = "NO_RESPONSE"
            finally:
                # FIX: guaranteed close also when sendto/recvfrom raise.
                sock.close()
        except socket.gaierror:
            r["status"] = "DNS_FAIL"
        except Exception as e:
            r["status"] = "ERROR"
            r["detail"] = str(e)[:60]
        return r

    def _classify(self, r):
        alt = r.get("alt_svc", {}).get("verdict", "?")
        udp = r.get("udp_probe", {}).get("status", "?")
        if alt == "ADVERTISED":
            return "SUPPORTED", "Alt-Svc advertises h3"
        if alt == "NOT_ADVERTISED" and udp == "RESPONSE":
            return "POSSIBLY_SUPPORTED", "no Alt-Svc but UDP responds"
        if alt == "NOT_ADVERTISED":
            return "NOT_DETECTED", "no Alt-Svc, no UDP response"
        if alt == "ERROR":
            return "INCONCLUSIVE", "Alt-Svc fetch failed"
        return "INCONCLUSIVE", "mixed/unknown"


# ============================================================
# 14. Censorship Detection (no port testing)
# ============================================================
class CensorshipDetectionModule:
    TEST_DOMAINS = [
        ("www.google.com", "allowed"),
        ("en.wikipedia.org", "allowed"),
        ("www.cloudflare.com", "allowed"),
        ("www.github.com", "allowed"),
        ("twitter.com", "blocked"),
        ("www.facebook.com", "blocked"),
        ("www.instagram.com", "blocked"),
        ("telegram.org", "blocked"),
        ("www.youtube.com", "blocked"),
    ]
    STUB_MARKERS = ["blocked", "access denied", "forbidden", "restricted",
                    "not allowed", "filtered", "unavailable in your country",
                    "this site has been blocked", "warning: this site"]

    def __init__(self):
        self.results = {}

    def run(self, progress_cb=None):
        print("\n[*] [Censorship Detection] Comprehensive analysis...")
        r = {}
        if progress_cb:
            progress_cb(0.0, "Testing domains...")
        r["domain_tests"] = self._test_domains(progress_cb)

        if progress_cb:
            progress_cb(0.45, "SNI variants...")
        r["sni_variants"] = self._test_sni_variants("www.google.com")

        if progress_cb:
            progress_cb(0.65, "DNS comparison...")
        r["dns_comparison"] = self._test_dns_comparison("twitter.com")

        if progress_cb:
            progress_cb(0.85, "Blockpage...")
        r["blockpage"] = self._test_blockpage()

        if progress_cb:
            progress_cb(0.96, "Classifying...")
        verdict, confidence, signals = self._classify(r)
        r["verdict"] = verdict
        r["confidence"] = confidence
        r["signals"] = signals
        print(f"    Verdict: {verdict} ({confidence})")
        for s in signals:
            print(f"      - {s}")
        if progress_cb:
            progress_cb(1.0, f"Done: {verdict}")
        self.results = r
        return r

    def _test_domains(self, progress_cb):
        out = []
        total = len(self.TEST_DOMAINS)
        for i, (domain, expected) in enumerate(self.TEST_DOMAINS):
            if progress_cb:
                progress_cb(0.02 + i / total * 0.42, f"{domain}")
            r = self._test_domain(domain)
            r["expected"] = expected
            r["interpreted"] = interpret_domain_status(r["status"], r.get("detail", ""))
            r["matches"] = self._matches(r["interpreted"], expected)
            out.append(r)
            mark = "OK" if r["matches"] is True else ("?" if r["matches"] is None else "XX")
            print(f"    [{mark}] {domain}: {r['status']} -> {r['interpreted']} (expected {expected})")
        return out

    def _test_domain(self, domain, port=443, timeout=5):
        r = {"domain": domain, "status": "UNKNOWN"}
        try:
            ip = socket.gethostbyname(domain)
            r["ip"] = ip
        except Exception:
            r["status"] = "DNS_FAIL"
            return r
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = time.time()
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                    r["status"] = "OK"
                    r["tls"] = ss.version()
                    r["elapsed_ms"] = round((time.time() - s) * 1000, 2)
            return r
        except ConnectionResetError:
            r["status"] = "TCP_RESET"
        except socket.timeout:
            r["status"] = "TIMEOUT"
        except ssl.SSLError as e:
            r["status"] = "SSL_ERROR"
            r["detail"] = str(e)[:80]
        except Exception as e:
            r["status"] = "ERROR"
            r["detail"] = str(e)[:80]
        return r

    @staticmethod
    def _matches(interpreted, expected):
        if expected == "allowed":
            return interpreted == "allowed"
        if expected == "blocked":
            return interpreted.startswith("blocked")
        return None

    def _test_sni_variants(self, hostname):
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            return {"error": "DNS failed"}
        variants = {}
        for name, sni in [("normal", hostname), ("no_sni", None),
                          ("blocked_sni", "twitter.com"),
                          ("random_sni", "random-xyz-987654.example")]:
            variants[name] = self._tls_with_sni(ip, sni)
            print(f"    SNI '{name}': {variants[name]['status']}")
        return variants

    def _tls_with_sni(self, ip, sni, port=443, timeout=5):
        r = {"sni": sni, "status": "UNKNOWN"}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = time.time()
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                ss = ctx.wrap_socket(sock, server_hostname=sni) if sni else ctx.wrap_socket(sock)
                r["status"] = "OK"
                r["elapsed_ms"] = round((time.time() - s) * 1000, 2)
                ss.close()
        except ConnectionResetError:
            r["status"] = "TCP_RESET"
        except socket.timeout:
            r["status"] = "TIMEOUT"
        except ssl.SSLError as e:
            r["status"] = "SSL_ERROR"
            r["detail"] = str(e)[:80]
        except Exception as e:
            r["status"] = "ERROR"
            r["detail"] = str(e)[:80]
        return r

    def _test_dns_comparison(self, domain):
        r = {"domain": domain, "results": {}, "status": "UNKNOWN"}
        resolvers = [("System", None), ("Google-8.8.8.8", "8.8.8.8"),
                     ("Cloudflare-1.1.1.1", "1.1.1.1"), ("Quad9-9.9.9.9", "9.9.9.9")]
        for name, server in resolvers:
            ips = self._resolve(domain, server)
            r["results"][name] = ips
            print(f"    DNS {name}: {ips[:2] if ips else 'FAILED'}")
        doh = self._resolve_doh(domain)
        r["results"]["DoH-Cloudflare"] = doh
        print(f"    DNS DoH: {doh[:2] if doh else 'FAILED'}")

        all_ips = []
        for ips in r["results"].values():
            all_ips.extend(ips)
        if not all_ips:
            r["status"] = "ALL_FAILED"
            return r
        pc = sum(1 for ip in all_ips if is_private_or_special(ip))
        total = len(all_ips)
        if pc == total and total >= 2:
            r["status"] = "DNS_INTERCEPTION"
            r["detail"] = f"All {total} responses private/special"
            return r
        if pc > 0:
            r["status"] = "PARTIAL_HIJACKING"
            r["detail"] = f"{pc}/{total} responses private"
            return r
        valid = {k: v for k, v in r["results"].items() if v}
        if len(valid) >= 2:
            sets = [set(v) for v in valid.values()]
            r["status"] = "CONSISTENT" if all(s == sets[0] for s in sets) else "MISMATCH"
        else:
            r["status"] = "INSUFFICIENT_DATA"
        return r

    def _resolve(self, domain, server=None):
        try:
            if server:
                q = dns_message.make_query(domain, "A")
                resp = dns_query.udp(q, server, timeout=3)
                return [i.address for a in resp.answer
                        for i in a if hasattr(i, "address")]
            return socket.gethostbyname_ex(domain)[2]
        except Exception:
            return []

    def _resolve_doh(self, domain):
        try:
            q = dns_message.make_query(domain, "A")
            resp = dns_query.https(q, "https://cloudflare-dns.com/dns-query", timeout=5)
            return [i.address for a in resp.answer
                    for i in a if hasattr(i, "address")]
        except Exception:
            return []

    def _test_blockpage(self):
        results = {}
        for hostname in ["www.google.com", "www.cloudflare.com"]:
            r = {"hostname": hostname,
                 "http": self._try_http(hostname),
                 "https": self._try_https(hostname)}
            r["status"], r["detail"] = self._interpret_blockpage(r)
            results[hostname] = r
            print(f"    Blockpage {hostname}: {r['status']}")
        return results

    def _try_http(self, hostname, timeout=6):
        try:
            resp = requests.get(f"http://{hostname}", timeout=timeout,
                                allow_redirects=True,
                                headers={"User-Agent": USER_AGENT})
            return {"status": "OK", "code": resp.status_code,
                    "final_url": resp.url,
                    "body_preview": resp.text[:500].lower()}
        except requests.Timeout:
            return {"status": "TIMEOUT"}
        except requests.ConnectionError as e:
            return {"status": "CONN_ERROR", "detail": str(e)[:60]}
        except Exception as e:
            return {"status": "ERROR", "detail": str(e)[:60]}

    def _try_https(self, hostname, timeout=6):
        try:
            resp = requests.get(f"https://{hostname}", timeout=timeout,
                                allow_redirects=True,
                                headers={"User-Agent": USER_AGENT})
            return {"status": "OK", "code": resp.status_code,
                    "final_url": resp.url}
        except requests.Timeout:
            return {"status": "TIMEOUT"}
        except requests.ConnectionError as e:
            return {"status": "CONN_ERROR", "detail": str(e)[:60]}
        except Exception as e:
            return {"status": "ERROR", "detail": str(e)[:60]}

    def _interpret_blockpage(self, r):
        http = r["http"]
        https = r["https"]
        # FIX: strip only the leading "www." (replace() used to remove every
        # occurrence anywhere in the hostname, corrupting e.g. foo.www.bar).
        hostname = r["hostname"]
        orig = hostname[4:] if hostname.lower().startswith("www.") else hostname

        if http["status"] == "OK":
            final = urlparse(http.get("final_url", "")).hostname or ""
            if final and orig not in final:
                return "REDIRECTED", f"-> {final}"
            body = http.get("body_preview", "")
            matched = [m for m in self.STUB_MARKERS if m in body]
            if matched:
                return "STUB_PAGE", f"markers: {matched[:2]}"
            return "OK", "no stub, no redirect"

        # HTTP failed
        if http["status"] in ("TIMEOUT", "CONN_ERROR"):
            if https["status"] == "OK":
                return "HTTP_BLOCKED", f"HTTP {http['status']} but HTTPS OK"
            return "HTTP_BLOCKED_AND_HTTPS_FAILED", "both HTTP and HTTPS unreachable"
        return "ERROR", http.get("detail", "")

    def _classify(self, r):
        signals = []
        mechs = set()

        for dt in r.get("domain_tests", []):
            if dt.get("matches") is True and dt.get("expected") == "blocked":
                signals.append(f"Domain {dt['domain']} blocked ({dt['interpreted']})")

        sv = r.get("sni_variants", {})
        if sv and "error" not in sv:
            normal = sv.get("normal", {}).get("status")
            no_sni = sv.get("no_sni", {}).get("status")
            blocked_sni = sv.get("blocked_sni", {}).get("status")
            if normal == "OK" and blocked_sni != "OK":
                mechs.add("SNI_DPI")
                signals.append(f"SNI-based DPI: normal OK, blocked failed ({blocked_sni})")
            elif normal != "OK" and no_sni == "OK":
                mechs.add("SNI_DPI")
                signals.append("SNI DPI: works without SNI")

        dns_r = r.get("dns_comparison", {})
        ds = dns_r.get("status", "")
        if ds == "DNS_INTERCEPTION":
            mechs.add("DNS_INTERCEPTION")
            signals.append(f"DNS interception: {dns_r.get('detail', '')}")
        elif ds == "PARTIAL_HIJACKING":
            mechs.add("DNS_INTERCEPTION")
            signals.append(f"Partial DNS hijacking: {dns_r.get('detail', '')}")
        elif ds == "MISMATCH":
            mechs.add("DNS_POISONING")
            signals.append("DNS mismatch across resolvers")

        bp = r.get("blockpage", {})
        for host, d in bp.items():
            status = d.get("status", "")
            if status in ("STUB_PAGE", "REDIRECTED"):
                mechs.add("HTTP_STUB_PAGE")
                signals.append(f"Stub page on {host} ({status})")
            elif status == "HTTP_BLOCKED":
                mechs.add("HTTP_FILTERING")
                signals.append(f"HTTP filtered on {host}: {d.get('detail', '')}")
            elif status == "HTTP_BLOCKED_AND_HTTPS_FAILED":
                mechs.add("HTTP_AND_HTTPS_FILTERING")
                signals.append(f"HTTP+HTTPS unreachable on {host}")

        if not mechs:
            allowed_ok = sum(1 for d in r.get("domain_tests", [])
                             if d.get("matches") is True and d.get("expected") == "allowed")
            if allowed_ok >= 2:
                return "NO_FILTERING_DETECTED", "HIGH", signals
            return "INCONCLUSIVE", "LOW", signals
        if len(mechs) >= 2:
            return "COMPREHENSIVE_FILTERING", "HIGH", signals
        return list(mechs)[0], "HIGH", signals


# ============================================================
# 15. CDN Connectivity
# ============================================================
class CDNConnectivityModule:
    HEADER_MAP = {
        "CF-Ray": "Cloudflare", "CF-Cache-Status": "Cloudflare",
        "X-Served-By": "Fastly", "X-Amz-Cf-Id": "CloudFront",
        "X-Akamai": "Akamai", "Akamai-GRN": "Akamai",
        "X-Azure-Ref": "Azure CDN",
    }

    def run(self, hostname="www.cloudflare.com", progress_cb=None):
        print(f"\n[*] [CDN] Analyzing {hostname}...")
        if progress_cb:
            progress_cb(0, "Provider...")
        provider = self._detect_provider(f"https://{hostname}")
        if progress_cb:
            progress_cb(0.5, "Edge node...")
        edge = self._detect_edge(hostname)
        if progress_cb:
            progress_cb(1.0, "Done")
        print(f"    Provider: {provider.get('provider', '?')}")
        print(f"    Edge: {edge.get('edge', '?')}")
        return {"cdn_provider": provider, "edge_node": edge}

    def _detect_provider(self, url):
        r = {"url": url}
        try:
            resp = requests.head(url, timeout=8, allow_redirects=True,
                                 headers={"User-Agent": USER_AGENT})
            hl = {k.lower(): v for k, v in resp.headers.items()}
            det = [p for h, p in self.HEADER_MAP.items() if h.lower() in hl]
            r["provider"] = det[0] if det else "Unknown"
        except Exception as e:
            r["provider"] = "ERROR"
            r["error"] = str(e)[:60]
        return r

    def _detect_edge(self, hostname):
        r = {"hostname": hostname}
        try:
            resp = requests.get(f"https://{hostname}/cdn-cgi/trace", timeout=8,
                                headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200 and "colo=" in resp.text:
                for line in resp.text.strip().split("\n"):
                    if "=" in line:
                        k, v = line.split("=", 1)
                        if k in ("colo", "loc", "ip", "http"):
                            r[k] = v
                r["edge"] = r.get("colo", "?")
                r["source"] = "Cloudflare trace"
                return r
        except Exception:
            pass
        r["edge"] = "?"
        return r


# ============================================================
# Renderers
# ============================================================
class TracerouteRenderer:
    WIDTH = 78

    @classmethod
    def render(cls, r):
        if not r or not r.get("hops"):
            return "No traceroute data."
        w = cls.WIDTH
        lines = ["+" + "-" * (w - 2) + "+",
                 "|" + " TRACEROUTE PATH ".center(w - 2) + "|",
                 "+" + "-" * (w - 2) + "+"]
        s = r.get("summary", {})
        rtt = s.get("total_rtt_ms")
        rtt_s = f"{rtt:.1f} ms" if rtt else "N/A"
        lines.append(f" Target: {r.get('target', '?'):<20} "
                     f"Hops: {s.get('total_hops', 0):<3} "
                     f"Timeouts: {s.get('timeouts', 0):<3} "
                     f"RTT: {rtt_s}")
        lines.append("+" + "-" * (w - 2) + "+")
        for h in r["hops"]:
            label = HOP_LABELS.get(h.get("class", ""), "???")
            ip = h.get("ip") or "*"
            lines.append(f" [{h['hop']:2d}] [{label:5s}] {ip}")
            ra = h.get("rtt_avg")
            lines.append(f"      |   {('%.2f ms' % ra) if ra else '(no response)'}")
        missing = s.get("missing_hops", [])
        if missing:
            lines.append(f" [!] Missing hop numbers: {missing}")
        return "\n".join(lines)


class IPv6Renderer:
    @staticmethod
    def render(r):
        if not r:
            return "No IPv6 data."
        w = 78
        lines = ["+" + "-" * (w - 2) + "+",
                 "|" + " IPv6 DIAGNOSTIC ".center(w - 2) + "|",
                 "+" + "-" * (w - 2) + "+"]
        addrs = r.get("system_addresses", [])
        gc = sum(1 for a in addrs if a.get("is_global"))
        lines.append(f" System addresses: {len(addrs)} ({gc} global)")
        for a in addrs[:5]:
            if a.get("is_global"):
                scope = "GLOBAL"
            elif a.get("is_ula"):
                scope = "ULA   "
            elif a.get("is_link_local"):
                scope = "LINK  "
            elif a.get("is_loopback"):
                scope = "LOOP  "
            else:
                scope = "OTHER "
            lines.append(f"   [{scope}] {a['interface']}: {a['address']}")
        aaaa = r.get("aaaa_resolution", [])
        # FIX: show the domain that was actually tested (was hardcoded
        # to "google.com" regardless of the user's domain).
        domain = r.get("domain", "google.com")
        lines.append(f" AAAA records ({domain}): {len(aaaa)}")
        for ip in aaaa[:3]:
            lines.append(f"   - {ip}")
        tcp6 = r.get("tcp6_tests", {})
        if tcp6:
            lines.append(" TCP6 connectivity:")
            for label, res in tcp6.items():
                status = res.get("status", "?")
                ms = res.get("elapsed_ms", "")
                lines.append(f"   {label:20s} -> {status:10s} {ms}ms" if ms else
                             f"   {label:20s} -> {status}")
        lines.append("+" + "-" * (w - 2) + "+")
        lines.append(f" VERDICT: {r.get('verdict', '?')}  ({r.get('verdict_reason', '')})")
        lines.append("+" + "-" * (w - 2) + "+")
        return "\n".join(lines)


# ============================================================
# Standards Comparator
# ============================================================
class StandardsComparator:
    REF = {
        "ping_avg": {"excellent": 50, "good": 100, "fair": 200, "unit": "ms"},
        "ping_loss": {"excellent": 0, "good": 1, "fair": 5, "unit": "%"},
        "http_ms": {"excellent": 200, "good": 500, "fair": 1000, "unit": "ms"},
        "http_ok": [200, 201, 202, 204, 301, 302, 303, 307, 308],
        "ssl_warn": 30, "ssl_crit": 7,
        "mtu_std": 1500, "mtu_pppoe": 1492, "mtu_vpn": 1480, "mtu_ipv6": 1280,
        "dl_mbps": {"excellent": 100, "good": 25, "fair": 10, "unit": "Mbps"},
        "ul_mbps": {"excellent": 50, "good": 10, "fair": 5, "unit": "Mbps"},
        "sp_ping": {"excellent": 20, "good": 50, "fair": 100, "unit": "ms"},
    }

    def __init__(self):
        self.rows = []

    def _lo(self, v, t):
        try:
            v = float(v)
        except (TypeError, ValueError):
            return "N/A", "?", "n/a"
        u = t["unit"]
        if v <= t["excellent"]: return "EXCELLENT", "OK", f"<= {t['excellent']} {u}"
        if v <= t["good"]:      return "GOOD", "OK", f"<= {t['good']} {u}"
        if v <= t["fair"]:      return "FAIR", "!!", f"<= {t['fair']} {u}"
        return "POOR", "XX", f"> {t['fair']} {u}"

    def _hi(self, v, t):
        try:
            v = float(v)
        except (TypeError, ValueError):
            return "N/A", "?", "n/a"
        u = t["unit"]
        if v >= t["excellent"]: return "EXCELLENT", "OK", f">= {t['excellent']} {u}"
        if v >= t["good"]:      return "GOOD", "OK", f">= {t['good']} {u}"
        if v >= t["fair"]:      return "FAIR", "!!", f">= {t['fair']} {u}"
        return "POOR", "XX", f"< {t['fair']} {u}"

    def _add(self, cat, metric, measured, std, status, sym):
        self.rows.append({"category": cat, "metric": metric, "measured": measured,
                          "standard": std, "status": status, "sym": sym})

    def compare_all(self, results):
        self.rows = []

        # Network
        p = results.get("ping") or {}
        if p:
            if "avg_ms" in p:
                s, sy, st = self._lo(p["avg_ms"], self.REF["ping_avg"])
                self._add("Network", "Ping Latency", f"{p['avg_ms']:.2f} ms", st, s, sy)
            if "loss_percent" in p:
                s, sy, st = self._lo(p["loss_percent"], self.REF["ping_loss"])
                self._add("Network", "Ping Loss", f"{p['loss_percent']:.1f} %", st, s, sy)

        d = results.get("dns") or {}
        if d and isinstance(d, dict):
            recs = d.get("records") or []
            if recs:
                self._add("Network", "DNS Resolution", f"{len(recs)} A record(s)",
                          ">= 1", "OK", "OK")
                self._add("Network", "DNS Method", d.get("method", "?"), "Any", "INFO", "--")
            else:
                self._add("Network", "DNS Resolution", "0 records", ">= 1", "FAILED", "XX")

        h = results.get("http") or results.get("http_health") or {}
        if h and isinstance(h, dict):
            code = h.get("status_code")
            if code is not None:
                ok = code in self.REF["http_ok"]
                self._add("Network", "HTTP Status", str(code), "200/3xx",
                          "OK" if ok else "ERROR", "OK" if ok else "XX")
            if "response_time_ms" in h:
                s, sy, st = self._lo(h["response_time_ms"], self.REF["http_ms"])
                self._add("Network", "HTTP Response", f"{h['response_time_ms']:.2f} ms",
                          st, s, sy)

        ssl_r = results.get("ssl") or {}
        if ssl_r and isinstance(ssl_r, dict):
            days = ssl_r.get("days_left")
            if days is not None:
                if days > self.REF["ssl_warn"]:
                    self._add("Network", "SSL Validity", f"{days} days", "> 30", "OK", "OK")
                elif days > self.REF["ssl_crit"]:
                    self._add("Network", "SSL Validity", f"{days} days", "> 7", "WARNING", "!!")
                else:
                    self._add("Network", "SSL Validity", f"{days} days", "> 7", "CRITICAL", "XX")
            ver = ssl_r.get("version")
            if ver:
                ok = ver in ("TLSv1.2", "TLSv1.3")
                self._add("Network", "TLS Version", ver, "1.2/1.3",
                          "OK" if ok else "OUTDATED", "OK" if ok else "!!")

        m = results.get("mtu") or {}
        if m and isinstance(m, dict) and "mtu" in m:
            mtu = m["mtu"]
            if mtu >= self.REF["mtu_std"]:
                self._add("Network", "MTU Size", f"{mtu} bytes", "1500", "OK", "OK")
            elif mtu >= self.REF["mtu_pppoe"]:
                self._add("Network", "MTU Size", f"{mtu} bytes", "1492 (PPPoE)", "OK", "OK")
            elif mtu >= self.REF["mtu_vpn"]:
                self._add("Network", "MTU Size", f"{mtu} bytes", "1480 (VPN)", "WARNING", "!!")
            elif mtu >= self.REF["mtu_ipv6"]:
                self._add("Network", "MTU Size", f"{mtu} bytes", "1280 (IPv6)", "POOR", "!!")
            else:
                self._add("Network", "MTU Size", f"{mtu} bytes", ">= 1280", "CRITICAL", "XX")

        # Speed
        st_ = results.get("speedtest") or {}
        if st_ and isinstance(st_, dict):
            if "download_mbps" in st_:
                s, sy, std = self._hi(st_["download_mbps"], self.REF["dl_mbps"])
                self._add("Speed", "Download", f"{st_['download_mbps']:.2f} Mbps", std, s, sy)
            if "upload_mbps" in st_:
                s, sy, std = self._hi(st_["upload_mbps"], self.REF["ul_mbps"])
                self._add("Speed", "Upload", f"{st_['upload_mbps']:.2f} Mbps", std, s, sy)
            if "ping_ms" in st_:
                s, sy, std = self._lo(st_["ping_ms"], self.REF["sp_ping"])
                self._add("Speed", "Speedtest Ping", f"{st_['ping_ms']} ms", std, s, sy)

        # Security
        dni = results.get("dpi_sni") or {}
        if dni and isinstance(dni, dict):
            stat = dni.get("status", "UNKNOWN")
            if stat == "OK":
                self._add("Security", "DPI/SNI", "TLS OK", "Handshake OK", "OK", "OK")
            else:
                self._add("Security", "DPI/SNI", stat, "Handshake OK", "ISSUE", "XX")

        # Filtering
        cens = results.get("censorship")
        if cens and isinstance(cens, dict):
            for dt in cens.get("domain_tests", []):
                m_ = dt.get("matches")
                tag = "OK" if m_ is True else ("MISMATCH" if m_ is False else "AMBIGUOUS")
                sym = "OK" if m_ is True else ("XX" if m_ is False else "--")
                self._add("Filtering", f"Domain: {dt['domain']}",
                          dt.get("interpreted", dt.get("status", "?")),
                          f"expected {dt.get('expected', '?')}", tag, sym)

            sv = cens.get("sni_variants", {})
            if sv and "error" not in sv:
                for name, v in sv.items():
                    stat = v.get("status", "?")
                    sym = "OK" if stat == "OK" else "!!"
                    self._add("Filtering", f"SNI: {name}", stat,
                              "OK" if name == "normal" else "?", stat, sym)

            dc = cens.get("dns_comparison", {})
            if dc.get("status"):
                stat = dc["status"]
                if stat in ("DNS_INTERCEPTION", "MISMATCH", "ALL_FAILED"):
                    sym = "XX"
                elif stat == "CONSISTENT":
                    sym = "OK"
                else:
                    sym = "!!"
                self._add("Filtering", "DNS Resolvers", stat, "CONSISTENT", stat, sym)

            bp = cens.get("blockpage", {})
            for h_, d_ in bp.items():
                stat = d_.get("status", "?")
                if stat in ("STUB_PAGE", "REDIRECTED"):
                    self._add("Filtering", f"Blockpage: {h_}", stat, "OK", stat, "XX")
                elif stat == "OK":
                    self._add("Filtering", f"Blockpage: {h_}", "OK", "OK", "OK", "OK")
                elif stat == "HTTP_BLOCKED":
                    self._add("Filtering", f"Blockpage: {h_}", stat, "OK", stat, "XX")
                elif stat == "HTTP_BLOCKED_AND_HTTPS_FAILED":
                    self._add("Filtering", f"Blockpage: {h_}", stat, "OK", stat, "XX")

            verdict = cens.get("verdict", "UNKNOWN")
            conf = cens.get("confidence", "LOW")
            if verdict == "NO_FILTERING_DETECTED":
                self._add("Filtering", "Overall Verdict", verdict, "No filtering", "OK", "OK")
            elif verdict == "INCONCLUSIVE":
                self._add("Filtering", "Overall Verdict", verdict, "No filtering", "INFO", "--")
            else:
                sym = "!!" if conf == "MEDIUM" else "XX"
                self._add("Filtering", "Overall Verdict", f"{verdict} ({conf})",
                          "No filtering", verdict, sym)
            for sig in cens.get("signals", []):
                self._add("Filtering", "Signal", sig[:60], "-", "DETECTED", "!!")

        # TLS Fragmentation
        frag = results.get("tls_frag")
        if frag and isinstance(frag, dict):
            concl = frag.get("conclusion", "UNKNOWN")
            if concl == "FRAGMENTATION_BYPASS_WORKS":
                self._add("Filtering", "TLS Fragmentation", "BYPASS WORKS",
                          "DPI not fragment-aware", "BYPASS", "OK")
            elif concl == "DPI_REASSEMBLES_FRAGMENTS":
                self._add("Filtering", "TLS Fragmentation", "DPI reassembles",
                          "no bypass", "BLOCKED", "XX")
            elif concl == "NO_BYPASS_NEEDED":
                self._add("Filtering", "TLS Fragmentation", "no bypass needed",
                          "target accessible", "INFO", "--")
            else:
                self._add("Filtering", "TLS Fragmentation", concl, "-", "INFO", "--")
            for target, data in frag.get("by_target", {}).items():
                whole = data.get("whole", {}).get("status", "?")
                frag_ok = sum(1 for rr in data.get("fragmented", {}).values()
                              if rr.get("status") == "OK")
                total_frag = len(data.get("fragmented", {}))
                self._add("Filtering", f"Frag: {target}",
                          f"whole={whole}, frag={frag_ok}/{total_frag}", "-", "INFO", "--")

        # CDN
        cdn = results.get("cdn") or {}
        if cdn and isinstance(cdn, dict):
            pr = cdn.get("cdn_provider", {}).get("provider", "Unknown")
            if pr and pr != "Unknown":
                self._add("CDN", "Provider", pr, "Detected", "OK", "OK")
            edge = cdn.get("edge_node", {}).get("edge", "?")
            if edge and edge != "?":
                self._add("CDN", "Edge Node", str(edge), "Detected", "OK", "OK")

        # IPv6
        ipv6 = results.get("ipv6")
        if ipv6 and isinstance(ipv6, dict):
            addrs = ipv6.get("system_addresses", [])
            gc = sum(1 for a in addrs if a.get("is_global"))
            ula_c = sum(1 for a in addrs if a.get("is_ula"))
            if addrs:
                summary = f"{len(addrs)} ({gc} global, {ula_c} ULA)"
                self._add("IPv6", "System Addresses", summary,
                          ">= 1 global", "OK" if gc > 0 else "WARNING",
                          "OK" if gc > 0 else "!!")
            else:
                self._add("IPv6", "System Addresses", "0", ">= 1", "NONE", "XX")
            aaaa = ipv6.get("aaaa_resolution", [])
            self._add("IPv6", "AAAA Records",
                      f"{len(aaaa)} ({', '.join(aaaa[:2]) or 'none'})",
                      ">= 1", "OK" if aaaa else "NONE", "OK" if aaaa else "XX")
            for label, t in ipv6.get("tcp6_tests", {}).items():
                st2 = t.get("status", "?")
                sym = "OK" if st2 == "OPEN" else ("XX" if st2 in ("TIMEOUT", "NO_ROUTE") else "--")
                self._add("IPv6", f"TCP6: {label}", st2, "OPEN",
                          "OK" if st2 == "OPEN" else "NONE", sym)
            vv = ipv6.get("verdict", "?")
            if vv == "FULL":
                self._add("IPv6", "Overall Verdict", vv, "IPv6 works", "OK", "OK")
            elif vv == "NO_IPV6":
                self._add("IPv6", "Overall Verdict", vv, "optional", "INFO", "--")
            elif vv in ("LOCAL_ONLY", "PRIVATE_ONLY"):
                self._add("IPv6", "Overall Verdict", vv, "global", "WARNING", "!!")
            elif vv == "AAAA_NO_ROUTE":
                self._add("IPv6", "Overall Verdict", vv, "IPv6 works", "WARNING", "!!")
            else:
                self._add("IPv6", "Overall Verdict", vv, "IPv6 works", "PARTIAL", "!!")

        # HTTP/3
        quic = results.get("http3")
        if quic and isinstance(quic, dict):
            alt = quic.get("alt_svc", {}).get("verdict", "?")
            self._add("HTTP/3", "Alt-Svc Header", alt, "ADVERTISED",
                      "OK" if alt == "ADVERTISED" else "INFO",
                      "OK" if alt == "ADVERTISED" else "--")
            udp = quic.get("udp_probe", {}).get("status", "?")
            self._add("HTTP/3", "UDP/443 Probe", udp, "RESPONSE",
                      "OK" if udp == "RESPONSE" else "INFO",
                      "OK" if udp == "RESPONSE" else "--")
            vq = quic.get("verdict", "?")
            if vq == "SUPPORTED":
                self._add("HTTP/3", "Overall Verdict", vq, "supported", "OK", "OK")
            else:
                self._add("HTTP/3", "Overall Verdict", vq, "supported", "INFO", "--")

        # Route
        tr = results.get("traceroute") or {}
        if tr and isinstance(tr, dict):
            sm = tr.get("summary", {})
            if sm.get("total_hops"):
                self._add("Route", "Traceroute Hops", str(sm["total_hops"]), "5-25", "INFO", "--")
            if sm.get("total_rtt_ms"):
                self._add("Route", "Route Total RTT",
                          f"{sm['total_rtt_ms']:.1f} ms", "< 300", "INFO", "--")
            if sm.get("missing_hops"):
                self._add("Route", "Missing Hops", str(sm["missing_hops"]), "[]", "INFO", "--")

        return self

    def render(self):
        if not self.rows:
            return "No data for comparison."
        headers = ["Category", "Metric", "Measured", "Standard", "Status"]
        for r in self.rows:
            r["status_str"] = f"[{r['sym']}] {r['status']}"
        widths = [len(h) for h in headers]
        for r in self.rows:
            widths[0] = max(widths[0], len(r["category"]))
            widths[1] = max(widths[1], len(r["metric"]))
            widths[2] = max(widths[2], len(r["measured"]))
            widths[3] = max(widths[3], len(r["standard"]))
            widths[4] = max(widths[4], len(r["status_str"]))
        sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
        out = [sep, "|" + "|".join(f" {h.center(w)} " for h, w in zip(headers, widths)) + "|", sep]
        for r in self.rows:
            out.append("|" + "|".join([
                f" {r['category'].ljust(widths[0])} ",
                f" {r['metric'].ljust(widths[1])} ",
                f" {r['measured'].ljust(widths[2])} ",
                f" {r['standard'].ljust(widths[3])} ",
                f" {r['status_str'].ljust(widths[4])} ",
            ]) + "|")
        out.append(sep)
        out.append("Legend: [OK]=good  [!!]=warning  [XX]=critical  [--]=info")
        return "\n".join(out)


# ============================================================
# Diagnostic Runner
# ============================================================
class DiagnosticRunner:
    def __init__(self, host, domain, url, cdn_host):
        self.host = host
        self.domain = domain
        self.url = url
        self.cdn_host = cdn_host
        self.hostname = urlparse(url).hostname or domain

    def run(self, enabled, overall_cb=None, current_cb=None, on_result_cb=None):
        results = {}
        total = len(enabled)

        def inner_cb(frac, msg=""):
            if current_cb:
                try:
                    current_cb(frac * 100, msg)
                except Exception:
                    pass

        for idx, name in enumerate(enabled, 1):
            if overall_cb:
                try:
                    overall_cb(idx - 1, total, name, "starting")
                except Exception:
                    pass
            try:
                r = self._run_one(name, progress_cb=inner_cb)
                if r is not None:
                    results[name] = r
            except Exception as e:
                print(f"\n[TEST ERROR {name}: {type(e).__name__}: {e}]")
                results[name] = {"error": str(e)}
            if overall_cb:
                try:
                    overall_cb(idx, total, name, "done")
                except Exception:
                    pass
            if on_result_cb:
                try:
                    on_result_cb(dict(results))
                except Exception:
                    pass
        return results

    def _run_one(self, name, progress_cb):
        cb = progress_cb
        if name == "ping":       return PingModule().execute(host=self.host, progress_cb=cb)
        if name == "dns":        return DNSModule().execute(domain=self.domain, progress_cb=cb)
        if name == "http":       return HTTPHealthModule().execute(url=self.url, progress_cb=cb)
        if name == "ssl":        return SSLModule().execute(hostname=self.hostname, progress_cb=cb)
        if name == "public_ip":  return PublicIPModule().execute(progress_cb=cb)
        if name == "traceroute": return TracerouteModule(probes=2, max_hops=20).execute(target=self.host, progress_cb=cb)
        if name == "mtu":        return MTUModule().execute(target=self.host, progress_cb=cb)
        if name == "speedtest":  return SpeedtestModule().execute(progress_cb=cb)
        if name == "dpi_sni":    return DPISNIModule().execute(hostname=self.hostname, progress_cb=cb)
        if name == "bandwidth":  return BandwidthMonitor(interval=2).sample(progress_cb=cb)
        if name == "censorship": return CensorshipDetectionModule().run(progress_cb=cb)
        if name == "cdn":        return CDNConnectivityModule().run(hostname=self.cdn_host, progress_cb=cb)
        if name == "tls_frag":   return TLSFragmentationModule().test(progress_cb=cb)
        if name == "ipv6":       return IPv6Module().test(domain=self.domain, progress_cb=cb)
        if name == "http3":      return QUICModule().test(hostname=self.hostname, progress_cb=cb)
        return None


# ============================================================
# Stdout Redirect (for GUI)
# ============================================================
class RedirectText:
    def __init__(self, text_widget, root):
        self.tw = text_widget
        self.root = root
        self.buf = ""

    def write(self, s):
        if not s:
            return
        self.buf += s
        if "\n" in self.buf:
            lines = self.buf.split("\n")
            for line in lines[:-1]:
                self._schedule(line + "\n")
            self.buf = lines[-1]

    def _schedule(self, text):
        try:
            self.root.after(0, lambda t=text: self._append(t))
        except Exception:
            pass

    def _append(self, text):
        try:
            self.tw.insert(tk.END, text)
            self.tw.see(tk.END)
        except Exception:
            pass

    def flush(self):
        if self.buf:
            self._schedule(self.buf)
            self.buf = ""


# ============================================================
# GUI
# ============================================================
class NetDiagGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"NetDiag v{__version__} - Network & Censorship Diagnostic")
        self.root.minsize(1150, 800)
        try:
            self.root.state("zoomed")
        except Exception:
            try:
                self.root.attributes("-zoomed", True)
            except Exception:
                self.root.geometry("1400x1000")

        self.running = False
        self.test_vars = {
            "ping": tk.BooleanVar(value=True),
            "dns": tk.BooleanVar(value=True),
            "http": tk.BooleanVar(value=True),
            "ssl": tk.BooleanVar(value=True),
            "public_ip": tk.BooleanVar(value=True),
            "traceroute": tk.BooleanVar(value=True),
            "mtu": tk.BooleanVar(value=True),
            "speedtest": tk.BooleanVar(value=False),
            "dpi_sni": tk.BooleanVar(value=True),
            "bandwidth": tk.BooleanVar(value=True),
            "censorship": tk.BooleanVar(value=True),
            "cdn": tk.BooleanVar(value=True),
            "tls_frag": tk.BooleanVar(value=False),
            "ipv6": tk.BooleanVar(value=True),
            "http3": tk.BooleanVar(value=True),
        }
        self.host_var = tk.StringVar(value="8.8.8.8")
        self.domain_var = tk.StringVar(value="google.com")
        self.url_var = tk.StringVar(value="https://www.google.com")
        self.cdn_host_var = tk.StringVar(value="www.cloudflare.com")
        self.save_file_var = tk.BooleanVar(value=False)
        self.save_path_var = tk.StringVar(value="netdiag_output.txt")
        self.render_trace_var = tk.BooleanVar(value=True)
        self._build()
        self._redirect()

    def _build(self):
        top = ttk.LabelFrame(self.root, text="Target Settings", padding=10)
        top.pack(fill=tk.X, padx=10, pady=5)
        r1 = ttk.Frame(top)
        r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="Host:", width=10).pack(side=tk.LEFT)
        ttk.Entry(r1, textvariable=self.host_var, width=18).pack(side=tk.LEFT, padx=5)
        ttk.Label(r1, text="Domain:", width=10).pack(side=tk.LEFT, padx=(15, 0))
        ttk.Entry(r1, textvariable=self.domain_var, width=22).pack(side=tk.LEFT, padx=5)
        ttk.Label(r1, text="URL:", width=6).pack(side=tk.LEFT, padx=(15, 0))
        ttk.Entry(r1, textvariable=self.url_var, width=36).pack(side=tk.LEFT, padx=5)
        r2 = ttk.Frame(top)
        r2.pack(fill=tk.X, pady=2)
        ttk.Label(r2, text="CDN Host:", width=10).pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.cdn_host_var, width=28).pack(side=tk.LEFT, padx=5)

        tf = ttk.LabelFrame(self.root, text="Tests to Run", padding=10)
        tf.pack(fill=tk.X, padx=10, pady=5)
        labels = {
            "ping": "Ping", "dns": "DNS", "http": "HTTP Health",
            "ssl": "SSL Certificate", "public_ip": "Public IP",
            "traceroute": "Traceroute (slow)", "mtu": "MTU Discovery",
            "speedtest": "Speedtest (very slow)", "dpi_sni": "DPI / SNI",
            "bandwidth": "Bandwidth", "censorship": "Censorship Detection",
            "cdn": "CDN Connectivity", "tls_frag": "TLS Fragmentation (bypass test)",
            "ipv6": "IPv6 Test", "http3": "HTTP/3 (QUIC)",
        }
        r, c = 0, 0
        for k, v in self.test_vars.items():
            ttk.Checkbutton(tf, text=labels[k], variable=v).grid(
                row=r, column=c, sticky=tk.W, padx=15, pady=3)
            c += 1
            if c >= 3:
                c = 0
                r += 1

        opt = ttk.LabelFrame(self.root, text="Options", padding=10)
        opt.pack(fill=tk.X, padx=10, pady=5)
        o1 = ttk.Frame(opt)
        o1.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(o1, text="Save to file:",
                        variable=self.save_file_var).pack(side=tk.LEFT, padx=5)
        ttk.Entry(o1, textvariable=self.save_path_var, width=45).pack(side=tk.LEFT, padx=5)
        ttk.Button(o1, text="Browse...", command=self._browse).pack(side=tk.LEFT, padx=5)
        ttk.Label(o1, text="(.txt + .csv)", foreground="gray").pack(side=tk.LEFT, padx=5)
        o2 = ttk.Frame(opt)
        o2.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(o2, text="Render traceroute visualization",
                        variable=self.render_trace_var).pack(side=tk.LEFT, padx=5)

        bf = ttk.Frame(self.root)
        bf.pack(fill=tk.X, padx=10, pady=5)
        self.run_btn = ttk.Button(bf, text="\u25B6 Run Diagnostics",
                                  command=self._on_run, width=20)
        self.run_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Clear All", command=self._clear, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Copy Terminal", command=self._copy_term, width=14).pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Save Terminal As...", command=self._save_term, width=18).pack(side=tk.LEFT, padx=5)

        pf = ttk.LabelFrame(self.root, text="Progress", padding=10)
        pf.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(pf, text="Overall:", width=14).grid(row=0, column=0, sticky=tk.W, padx=5, pady=3)
        self.overall_bar = ttk.Progressbar(pf, mode="determinate", maximum=100)
        self.overall_bar.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=3)
        self.overall_lbl = ttk.Label(pf, text="0 / 0 (0%)", width=24)
        self.overall_lbl.grid(row=0, column=2, padx=5, sticky=tk.W)
        ttk.Label(pf, text="Current:", width=14).grid(row=1, column=0, sticky=tk.W, padx=5, pady=3)
        self.current_bar = ttk.Progressbar(pf, mode="determinate", maximum=100)
        self.current_bar.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=3)
        self.current_lbl = ttk.Label(pf, text="Ready", width=24)
        self.current_lbl.grid(row=1, column=2, padx=5, sticky=tk.W)
        pf.columnconfigure(1, weight=1)

        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        tf2 = ttk.LabelFrame(paned, text="Results Table (live)", padding=5)
        hd = ttk.Frame(tf2)
        hd.pack(fill=tk.X, pady=(0, 3))
        ttk.Label(hd, text="Live Results", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.row_count = ttk.Label(hd, text="(0 rows)", foreground="gray")
        self.row_count.pack(side=tk.LEFT, padx=8)
        ttk.Button(hd, text="Copy Table", command=self._copy_table).pack(side=tk.RIGHT, padx=3)
        ttk.Button(hd, text="Export CSV", command=self._export_csv).pack(side=tk.RIGHT, padx=3)
        ttk.Button(hd, text="Clear Table", command=self._clear_table).pack(side=tk.RIGHT, padx=3)

        cols = ("category", "metric", "measured", "standard", "status")
        self.tree = ttk.Treeview(tf2, columns=cols, show="headings", height=8)
        for col, h, w in [("category", "Category", 100), ("metric", "Metric", 200),
                          ("measured", "Measured", 240), ("standard", "Standard", 260),
                          ("status", "Status", 200)]:
            self.tree.heading(col, text=h)
            self.tree.column(col, width=w, anchor=tk.W, stretch=True)
        self.tree.tag_configure("ok", background="#d4edda", foreground="#155724")
        self.tree.tag_configure("warning", background="#fff3cd", foreground="#856404")
        self.tree.tag_configure("critical", background="#f8d7da", foreground="#721c24")
        self.tree.tag_configure("info", background="#e2e3e5", foreground="#383d41")
        scroll = ttk.Scrollbar(tf2, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<Control-c>", lambda e: self._copy_table())
        paned.add(tf2, weight=1)

        tf3 = ttk.LabelFrame(paned, text="Terminal Output (selectable / copyable)", padding=5)
        self.terminal = scrolledtext.ScrolledText(
            tf3, wrap=tk.WORD, font=("Consolas", 9),
            bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        self.terminal.pack(fill=tk.BOTH, expand=True)
        paned.add(tf3, weight=1)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN,
                  anchor=tk.W).pack(fill=tk.X, side=tk.BOTTOM)

    def _redirect(self):
        self.redir = RedirectText(self.terminal, self.root)
        sys.stdout = self.redir
        sys.stderr = self.redir

    def _browse(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if p:
            self.save_path_var.set(p)

    def _clear(self):
        self.terminal.delete("1.0", tk.END)
        # FIX: also reset the pending stdout buffer, otherwise leftovers
        # from the previous run could appear in the cleared terminal.
        if getattr(self, "redir", None) is not None:
            self.redir.buf = ""
        self._clear_table()

    def _copy_term(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.terminal.get("1.0", tk.END))
        self.status_var.set("Terminal copied")

    def _save_term(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not p:
            return
        try:
            Path(p).write_text(self.terminal.get("1.0", tk.END), encoding="utf-8")
            self.status_var.set(f"Saved to {p}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def _tag(self, sym):
        return {"OK": "ok", "!!": "warning", "XX": "critical"}.get(sym, "info")

    def _update_table(self, results):
        try:
            for it in self.tree.get_children():
                self.tree.delete(it)
            comp = StandardsComparator().compare_all(results)
            for row in comp.rows:
                tag = self._tag(row["sym"])
                status = f"[{row['sym']}] {row['status']}"
                self.tree.insert("", tk.END, values=(
                    row["category"], row["metric"], row["measured"],
                    row["standard"], status), tags=(tag,))
            self.row_count.config(text=f"({len(self.tree.get_children())} rows)")
        except Exception as e:
            print(f"[Table update error: {e}]")

    def _clear_table(self):
        for it in self.tree.get_children():
            self.tree.delete(it)
        self.row_count.config(text="(0 rows)")

    def _copy_table(self):
        lines = ["\t".join(["Category", "Metric", "Measured", "Standard", "Status"])]
        for it in self.tree.get_children():
            v = self.tree.item(it)["values"]
            lines.append("\t".join(str(x) for x in v))
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status_var.set(f"Table copied ({len(lines) - 1} rows)")

    def _export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv",
                                         filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Category", "Metric", "Measured", "Standard", "Status"])
                for it in self.tree.get_children():
                    w.writerow(self.tree.item(it)["values"])
            self.status_var.set(f"CSV: {p}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _save_all(self, results, elapsed, cfg):
        path = Path(cfg["save_path"])
        try:
            text = self.terminal.get("1.0", tk.END)
            header = (f"# NetDiag v{__version__} - {datetime.now().isoformat()}\n"
                      f"# Host={cfg['host']} Domain={cfg['domain']}\n"
                      f"# URL={cfg['url']} CDN={cfg['cdn_host']}\n"
                      f"# Duration={elapsed:.1f}s\n\n")
            path.write_text(header + text, encoding="utf-8")
            csv_path = path.with_suffix(".csv")
            comp = StandardsComparator().compare_all(results)
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Category", "Metric", "Measured", "Standard", "Status"])
                for r in comp.rows:
                    w.writerow([r["category"], r["metric"], r["measured"],
                                r["standard"], r["status"]])
            self.status_var.set(f"Saved: {path} + {csv_path}")
            print(f"\n[Saved: {path}]")
            print(f"[Saved: {csv_path}]")
        except Exception as e:
            self.status_var.set(f"Save failed: {e}")
            print(f"\n[Save failed: {e}]")

    def _set_overall(self, pct, completed, total, msg=""):
        self.overall_bar["value"] = pct
        self.overall_lbl.config(text=f"{completed} / {total} ({pct:.0f}%)")
        if msg:
            self.status_var.set(msg)

    def _set_current(self, pct, msg=""):
        self.current_bar["value"] = pct
        self.current_lbl.config(text=(msg[:30] if msg else f"{pct:.0f}%"))

    def _on_run(self):
        if self.running:
            return
        enabled = [k for k, v in self.test_vars.items() if v.get()]
        if not enabled:
            messagebox.showwarning("No tests", "Please enable at least one test.")
            return
        self.running = True
        self.run_btn.config(state=tk.DISABLED)
        self._clear()
        self.status_var.set(f"Running {len(enabled)} test(s)...")
        self.overall_lbl.config(text=f"0 / {len(enabled)} (0%)")
        self.overall_bar["value"] = 0
        self.current_bar["value"] = 0
        self.current_lbl.config(text="Starting...")
        # FIX (thread-safety): snapshot ALL Tkinter variables here, in the
        # main thread. The old code read host_var/domain_var/save_file_var/
        # render_trace_var/... from the worker thread, which is not
        # thread-safe in Tkinter and could crash or misbehave.
        cfg = {
            "host": self.host_var.get(),
            "domain": self.domain_var.get(),
            "url": self.url_var.get(),
            "cdn_host": self.cdn_host_var.get(),
            "save_to_file": bool(self.save_file_var.get()),
            "save_path": self.save_path_var.get(),
            "render_trace": bool(self.render_trace_var.get()),
        }
        threading.Thread(target=self._run_async, args=(enabled, cfg),
                         daemon=True).start()

    def _run_async(self, enabled, cfg):
        start = time.time()
        total = len(enabled)

        def overall_cb(completed, total_n, name, phase):
            pct = (completed / total_n * 100) if total_n else 0
            action = "Running" if phase == "starting" else "Done"
            msg = f"{action}: {name}"
            try:
                self.root.after(0, lambda p=pct, c=completed, t=total_n, m=msg:
                                self._set_overall(p, c, t, m))
                if phase == "starting":
                    self.root.after(0, lambda: self.current_bar.configure(value=0))
                    self.root.after(0, lambda: self.current_lbl.configure(text=""))
            except Exception:
                pass

        def current_cb(pct, msg):
            try:
                self.root.after(0, lambda p=pct, m=msg: self._set_current(p, m))
            except Exception:
                pass

        def on_result(results):
            try:
                self.root.after(0, lambda r=dict(results): self._update_table(r))
            except Exception:
                pass

        runner = DiagnosticRunner(
            host=cfg["host"],
            domain=cfg["domain"],
            url=cfg["url"],
            cdn_host=cfg["cdn_host"],
        )

        try:
            results = runner.run(enabled, overall_cb=overall_cb,
                                 current_cb=current_cb, on_result_cb=on_result)
        except Exception as e:
            print(f"\n[FATAL: {type(e).__name__}: {e}]")
            results = {}

        try:
            if "traceroute" in results and cfg["render_trace"] and results["traceroute"]:
                print("\n" + TracerouteRenderer.render(results["traceroute"]))
            if "ipv6" in results and results["ipv6"]:
                print("\n" + IPv6Renderer.render(results["ipv6"]))
            print("\n" + "=" * 72)
            print("RESULTS vs STANDARDS")
            print("=" * 72)
            print(StandardsComparator().compare_all(results).render())
            print("\n" + "=" * 72)
            print("RAW JSON")
            print("=" * 72)
            print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
            elapsed = time.time() - start
            print(f"\n=== DONE in {elapsed:.1f}s ===")
            if cfg["save_to_file"]:
                try:
                    self.root.after(0, lambda r=dict(results), e=elapsed:
                                    self._save_all(r, e, cfg))
                except Exception:
                    pass
            self.root.after(0, lambda: self._set_current(100, "Done"))
            self.root.after(0, lambda: self._set_overall(
                100, total, total, f"All {total} tests done in {elapsed:.1f}s"))
        except Exception as e:
            print(f"\n[FATAL: {type(e).__name__}: {e}]")
        finally:
            self.running = False
            try:
                self.root.after(0, lambda: self.run_btn.config(state=tk.NORMAL))
            except Exception:
                pass


# ============================================================
# CLI
# ============================================================
def run_cli(args):
    if args.only_censorship:
        enabled = ["censorship"]
    else:
        enabled = ["ping", "dns", "http", "ssl", "public_ip", "mtu",
                   "dpi_sni", "bandwidth"]
        if not (args.quick or args.skip_traceroute):
            enabled.append("traceroute")
        if not (args.quick or args.skip_speedtest):
            enabled.append("speedtest")
        if not args.no_censorship:
            enabled.append("censorship")
        if not args.no_cdn:
            enabled.append("cdn")
        if args.tls_frag:
            enabled.append("tls_frag")
        if not args.no_ipv6:
            enabled.append("ipv6")
        if not args.no_http3:
            enabled.append("http3")

    runner = DiagnosticRunner(
        host=args.host, domain=args.domain, url=args.url, cdn_host=args.cdn_host,
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print(f"NetDiag v{__version__} CLI")
        print(f"Host={args.host} Domain={args.domain} URL={args.url}")
        print(f"Tests: {', '.join(enabled)}\n")
        results = runner.run(enabled)
        if results.get("traceroute"):
            print("\n" + TracerouteRenderer.render(results["traceroute"]))
        if results.get("ipv6"):
            print("\n" + IPv6Renderer.render(results["ipv6"]))
        print("\n" + "=" * 72)
        print("RESULTS vs STANDARDS")
        print("=" * 72)
        print(StandardsComparator().compare_all(results).render())
        print("\n" + "=" * 72)
        print("RAW JSON")
        print("=" * 72)
        print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    output = buf.getvalue()
    print(output)
    if args.output:
        try:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"\n[Saved to {args.output}]")
        except Exception as e:
            print(f"\n[Save failed: {e}]", file=sys.stderr)
            return 1
    return 0


# ============================================================
# Selftest
# ============================================================
def run_selftest():
    print(f"NetDiag v{__version__} Self-Test")
    print("=" * 50)
    required = {"ping3": "ping3", "dns.resolver": "dnspython",
                "requests": "requests", "urllib3": "urllib3",
                "psutil": "psutil", "speedtest": "speedtest-cli",
                "icmplib": "icmplib"}
    optional = {"scapy": "scapy", "OpenSSL": "pyopenssl",
                "tkinter": "tkinter (bundled)"}
    ok = True
    print("Required:")
    for mod, pkg in required.items():
        try:
            __import__(mod)
            print(f"  [OK]   {mod}")
        except ImportError:
            print(f"  [FAIL] {mod}  (pip install {pkg})")
            ok = False
    print("\nOptional:")
    for mod, pkg in optional.items():
        try:
            __import__(mod)
            print(f"  [OK]   {mod}")
        except ImportError:
            print(f"  [----] {mod}  (optional: pip install {pkg})")
    print("\nInfo:")
    print("  IPv6 test: uses stdlib socket + psutil (no extra deps)")
    print("  HTTP/3 test: uses stdlib socket + requests (no extra deps)")
    print("  TLS frag: uses stdlib ssl.MemoryBIO (no extra deps)")
    print()
    if ok:
        print("All required dependencies present.")
        print(f"You can run: python {Path(sys.argv[0]).name}")
    else:
        print("Some required dependencies are missing.")
        print("Install with: pip install " + " ".join(required.values()))
    return 0 if ok else 1


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description=f"NetDiag v{__version__} - Network & Censorship Diagnostic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netdiag.py                        GUI mode
  python netdiag.py --cli                  CLI mode
  python netdiag.py --cli --quick          Fast CLI (skip slow tests)
  python netdiag.py --cli --tls-frag       Include TLS fragmentation test
  python netdiag.py --cli --only-censorship
  python netdiag.py --cli --no-ipv6 --no-http3
  python netdiag.py --selftest             Verify installation
        """)
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--version", action="version", version=f"NetDiag {__version__}")
    parser.add_argument("--selftest", action="store_true", help="Verify installation")
    parser.add_argument("--host", default="8.8.8.8", help="Ping/traceroute/MTU target")
    parser.add_argument("--domain", default="google.com", help="Domain for DNS/IPv6")
    parser.add_argument("--url", default="https://www.google.com", help="URL for HTTP/SSL")
    parser.add_argument("--cdn-host", default="www.cloudflare.com", help="CDN hostname")
    parser.add_argument("--skip-speedtest", action="store_true")
    parser.add_argument("--skip-traceroute", action="store_true")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--no-censorship", action="store_true")
    parser.add_argument("--no-cdn", action="store_true")
    parser.add_argument("--no-ipv6", action="store_true")
    parser.add_argument("--no-http3", action="store_true")
    parser.add_argument("--only-censorship", action="store_true")
    parser.add_argument("--tls-frag", action="store_true",
                        help="Include TLS fragmentation bypass test")
    parser.add_argument("--output", metavar="FILE", help="Save CLI output")
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()
    if args.cli:
        return run_cli(args)
    if not HAS_TK:
        print("tkinter not available. Install or use --cli.")
        return 1
    root = tk.Tk()
    NetDiagGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)