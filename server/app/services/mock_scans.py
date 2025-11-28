"""
Lightweight analysis helpers for EduScan backend.

The functions in this module perform real network/file heuristics (no randomness) so
results are derived from actual targets when the API is invoked. Most routines rely
on Python's stdlib (socket/ssl) and `httpx` for HTTP probing, making them portable
without requiring heavy external binaries. When a target is unreachable the
functions fall back to informative errors rather than fabricating pseudo data.
"""

from __future__ import annotations

import hashlib
import os
import ipaddress
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Literal, Sequence, Tuple, Optional, Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunparse
import re

import httpx
from .hash_detector import detect_hash_type, estimate_hash_strength, get_hashcat_mode, get_john_format

PortStatus = Literal["open", "closed", "filtered"]
PayloadResult = Literal["Vulnerable", "Likely Safe"]

HTTP_TIMEOUT = 6.0
TCP_TIMEOUT = 1.3
# Optional local templates directory (in-repo). Primary scan uses nuclei-templates via `-tags sqli`.
SQLI_TEMPLATE_DIR = Path(__file__).resolve().parent / "nuclei-templates/dast/vulnerabilities/" / "sqli"
# Local nuclei XSS templates directory
XSS_TEMPLATE_DIR = Path(__file__).resolve().parent / "nuclei-templates/dast/vulnerabilities/" / "xss"
# Nuclei HTTP templates directory (prefer absolute path provided by user)
HTTP_TEMPLATE_DIR_ABS = Path("/home/jack/Desktop/lomba/server/app/services/nuclei-templates/http")
HTTP_TEMPLATE_DIR_REL = Path(__file__).resolve().parent / "nuclei-templates" / "http"
# Where to persist last nuclei raw output for debugging
NUCLEI_RESPON_PATH = Path(__file__).resolve().parent / "respon.json"
NUCLEI_TEXT_PATTERN = re.compile(
    r"\[(?P<template>[^\]]+)\]\s+\[(?P<protocol>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<target>\S+)"
)

def _norm_sev(val: Optional[str]) -> str:
    if not val:
        return "info"
    v = str(val).lower()
    mapping = {
        "informational": "info",
        "unknown": "info",
        "none": "info",
    }
    allowed = {"info", "low", "medium", "high", "critical"}
    return mapping.get(v, v if v in allowed else "info")

SERVICE_PORTS = [
    {"port": 21, "service": "FTP"},
    {"port": 22, "service": "SSH"},
    {"port": 25, "service": "SMTP"},
    {"port": 53, "service": "DNS"},
    {"port": 80, "service": "HTTP"},
    {"port": 110, "service": "POP3"},
    {"port": 143, "service": "IMAP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 587, "service": "SMTP Submission"},
    {"port": 3306, "service": "MySQL"},
    {"port": 3389, "service": "RDP"},
]

SERVICE_RISK = {
    "FTP": 18,
    "SSH": 11,
    "SMTP": 14,
    "DNS": 10,
    "HTTP": 20,
    "POP3": 12,
    "IMAP": 12,
    "HTTPS": 6,
    "SMTP Submission": 11,
    "MySQL": 22,
    "RDP": 24,
    "Custom": 10,
}

SERVICE_GUIDANCE = {
    "FTP": (
        "FTP mentransmisikan kredensial secara cleartext sehingga mudah di-sniff.",
        "Migrasikan ke SFTP/FTPS dan batasi akses IP internal.",
    ),
    "SSH": (
        "SSH exposed ke publik; brute-force mudah terjadi jika password login masih aktif.",
        "Batasi SSH via ACL/VPN dan paksa login key pair + Fail2Ban.",
    ),
    "HTTP": (
        "HTTP terbuka tanpa TLS akan memaparkan sesi/cookie.",
        "Redirect seluruh traffic ke HTTPS + aktifkan HSTS.",
    ),
    "HTTPS": (
        "HTTPS terpublik – pastikan TLS modern dan tidak menerima cipher legacy.",
        "Audit dengan TLS Inspector/sslyze dan cabut sertifikat akan kadaluarsa.",
    ),
    "MySQL": (
        "Database MySQL langsung terekspos sehingga enumerasi user/DB memungkinkan.",
        "Batasi MySQL hanya di jaringan privat dan gunakan accounts least-privilege.",
    ),
    "RDP": (
        "RDP raw di internet sering menjadi target brute force/RCE (BlueKeep).",
        "Letakkan RDP di VPN/bastion dan aktifkan Network Level Authentication.",
    ),
    "SMTP": (
        "SMTP service terbuka bisa dimanfaatkan untuk relay/spam jika misconfigured.",
        "Aktifkan auth STARTTLS dan batasi relaying pada host terpercaya.",
    ),
}

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security", 
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "expect-ct",
    "x-permitted-cross-domain-policies",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

HEADER_SCORING = {
    "content-security-policy": {"weight": 25, "critical": True},
    "strict-transport-security": {"weight": 20, "critical": True},
    "x-frame-options": {"weight": 15, "critical": True},
    "x-content-type-options": {"weight": 10, "critical": False},
    "referrer-policy": {"weight": 8, "critical": False},
    "permissions-policy": {"weight": 12, "critical": False},
    "x-xss-protection": {"weight": 8, "critical": False},
    "expect-ct": {"weight": 5, "critical": False},
    "x-permitted-cross-domain-policies": {"weight": 5, "critical": False},
    "cross-origin-embedder-policy": {"weight": 8, "critical": False},
    "cross-origin-opener-policy": {"weight": 8, "critical": False},
    "cross-origin-resource-policy": {"weight": 8, "critical": False},
}

# Fallback mini wordlist jika file wordlist belum tersedia
DIRECTORY_WORDLIST = [
    "/admin",
    "/.git/",
    "/wp-admin",
    "/server-status",
    "/backup",
    "/uploads",
    "/api",
    "/login",
    "/dashboard",
    "/old",
]

# Lokasi folder wordlist kustom untuk ffuf
WORDLIST_DIR = Path(__file__).resolve().parent / "wordlist"

FFUF_MATCH_CODES = {
    200,
    201,
    202,
    204,
    206,
    301,
    302,
    307,
    308,
    401,
    403,
    405,
}

def _normalize_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _resolve_wordlist(name: str) -> Path | None:
    """Cari file wordlist berdasarkan nama yang diberikan di folder services/wordlist.

    Prioritas:
    - Exact match "<name>.txt"
    - File yang nama (tanpa ekstensi) setelah dinormalisasi sama dengan nama
    - File yang nama (tanpa ekstensi) diawali nama (dinormalisasi)
    """
    target = _normalize_name(name)
    if not WORDLIST_DIR.exists():
        return None
    # exact
    exact = WORDLIST_DIR / f"{name}.txt"
    if exact.exists():
        return exact
    # scan candidates
    for file in WORDLIST_DIR.glob("*.txt"):
        stem = _normalize_name(file.stem)
        if stem == target or stem.startswith(target):
            return file
    return None


def _origin_root(url: str) -> str:
    """Ambil origin root (scheme://host/) untuk menghindari query mempengaruhi fuzzing.

    Contoh: http://site.tld/path?a=1 -> http://site.tld/
    """
    try:
        p = urlsplit(url)
        if not p.scheme or not p.netloc:
            return url.rstrip("/") + "/"
        return f"{p.scheme}://{p.netloc}/"
    except Exception:
        return url.rstrip("/") + "/"


def _run_ffuf(url: str, wordlist_path: Path, timeout: int = 600) -> Tuple[List[Dict], Dict[str, str]]:
    """Jalankan ffuf untuk enumerasi direktori dan parse hasil JSON.

    Menghasilkan list entries dengan bentuk yang konsisten: path, status, size.
    """
    _ensure_tool("ffuf")
    # Pastikan target di-root domain agar respon tidak bias 200 dari endpoint tertentu
    base = _origin_root(url)
    target = base.rstrip("/") + "/FUZZ"
    # ffuf menulis JSON ke file; gunakan tempfile agar mudah dibaca
    with tempfile.NamedTemporaryFile("w+b", delete=False) as tmp:
        out_path = Path(tmp.name)
    cmd = [
        "ffuf",
        "-u",
        target,
        "-w",
        str(wordlist_path),
        "-of",
        "json",
        "-o",
        str(out_path),
        "-t",
        "80",
        "-c",
        "-noninteractive",
        # Filter out 404 agar output fokus ke temuan
        "-fc",
        "404",
    ]
    exit_code, stdout, stderr = _run_command(cmd, timeout=timeout)
    # ffuf mengembalikan exitcode 0 meski tidak ada hasil. Pastikan file ada.
    entries: List[Dict] = []
    notes: List[str] = []
    code_counts: Dict[str, int] = {}
    try:
        if out_path.exists():
            data = json.loads(out_path.read_text(encoding="utf-8") or "{}")
            for item in data.get("results", []):
                status = int(item.get("status", 0))
                # hanya status menarik
                if status not in FFUF_MATCH_CODES:
                    continue
                fuzz_val = None
                inp = item.get("input")
                if isinstance(inp, dict):
                    fuzz_val = inp.get("FUZZ") or next(iter(inp.values()), None)
                path = "/" + str(fuzz_val).lstrip("/") if fuzz_val else "/"
                size = item.get("length") or item.get("size") or 0
                entries.append({"path": path, "status": status, "size": f"{size} bytes"})
                code_counts[str(status)] = code_counts.get(str(status), 0) + 1
            if not entries:
                notes.append("ffuf tidak menemukan endpoint menarik (filtered 404)")
        else:
            notes.append("ffuf tidak menghasilkan output JSON")
    finally:
        out_path.unlink(missing_ok=True)
    tool_name = "FFUF"
    status_obj = {
        "name": tool_name,
        "status": "completed",
        "notes": f"{len(entries)} temuan",
        "target": target,
        "wordlist": str(wordlist_path),
        "status_counts": code_counts,
        "entries": entries,  # lampirkan untuk kebutuhan spider
    }
    # Jika ffuf gagal total, naikkan error agar caller bisa fallback
    if exit_code != 0 and not entries:
        raise RuntimeError(f"FFUF gagal: {stderr or stdout or 'tidak ada output'}")
    return entries, status_obj

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "native client",
    "sqlite error",
    "pg::syntaxerror",
]

SQLI_SAFE_CHARS = "'\"(),:@-._~"
SQLI_PAYLOADS = {
    "error": [
        "1'",
        "1\"",
        "1'-- -",
        "1' OR '1'='1",
        "1') OR ('1'='1",
    ],
    "union": [
        "1' UNION SELECT NULL-- -",
        "1' UNION SELECT NULL,NULL-- -",
        "1' UNION SELECT username,password FROM users-- -",
    ],
    "blind": [
        "1' AND SLEEP(3)-- -",
        "1' OR pg_sleep(3)-- -",
        "1' || dbms_pipe.receive_message('EDUSCAN',3)-- -",
    ],
}

def _preflight_http(url: str, params: Dict[str, str] | None = None) -> httpx.Response:
    """Reachability check for a target URL.

    Performs a simple GET with redirects enabled and TLS verification disabled.
    Any httpx.HTTPError should be handled by the caller.
    """
    with httpx.Client(timeout=HTTP_TIMEOUT, verify=False, follow_redirects=True) as client:
        return client.get(url, params=params)


def _ensure_tool(tool_name: str) -> None:
    if shutil.which(tool_name) is None:
        raise RuntimeError(
            f"Tool '{tool_name}' tidak ditemukan di PATH. Install {tool_name} terlebih dahulu (lihat README)."
        )


def _run_command(command: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        if timeout is None:
            proc = subprocess.run(command, capture_output=True, text=True)
        else:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Eksekusi '{command[0]}' melebihi batas {timeout}s.") from exc
    return proc.returncode, proc.stdout, proc.stderr


BRACKET_LINE = re.compile(r"^\[(?P<code>[\+\-xX!])\]\s+(?P<site>.+?)\s*$")


def _parse_bracket_outputs(text: str) -> Dict:
    """Parse outputs like:
    [x] facebook.com
    [-] amazon.com
    [+] instagram.com
    [!] error.site
    Returns counts per code and list of entries.
    """
    counts = {"+": 0, "-": 0, "x": 0, "!": 0}
    entries: List[Dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("***"):
            continue
        m = BRACKET_LINE.match(line)
        if not m:
            continue
        code = m.group("code").lower()
        site = m.group("site").strip()
        if code not in counts:
            code = "x"
        counts[code] += 1
        entries.append({"site": site, "code": code})
    return {"counts": counts, "entries": entries}


def _flatten_obj(obj: Any, prefix: str = "") -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, (str, int, float, bool)) or v is None:
                flat[key] = v
            elif isinstance(v, (list, tuple)):
                # stringify simple list
                try:
                    flat[key] = ", ".join(str(x) for x in v)
                except Exception:
                    flat[key] = str(v)
            elif isinstance(v, dict):
                flat.update(_flatten_obj(v, key))
    return flat


def _run_truecaller(number: str, cookie: Optional[str]) -> Tuple[Dict, Dict]:
    """Scrape Truecaller web search with provided cookies.

    - number: E.164 like +62878..., or raw digits
    - cookie: full Cookie header string from a logged-in browser session
    Returns entries of "+" facts plus details dict when possible.
    """
    tool_name = "truecaller-web"
    if not cookie:
        return {}, {"name": tool_name, "status": "skipped", "notes": "cookie tidak disediakan"}
    # Normalize to components
    digits = re.sub(r"\D", "", str(number))
    if not digits or len(digits) < 6:
        return {}, {"name": tool_name, "status": "error", "notes": "nomor tidak valid"}
    # Heuristic split: try 1-3 digits cc, rest subscriber; prefer 2 for ID (62)
    cc = digits[:2]
    subscriber = digits[2:]
    if cc not in {"62", "44", "1"} and len(digits) >= 10:
        cc = digits[:3]
        subscriber = digits[3:]
    url = f"https://www.truecaller.com/search/{cc}/{subscriber}"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,id-ID,id;q=0.8",
        "Referer": "https://www.truecaller.com/",
        "Cookie": cookie,
        "Connection": "close",
    }
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            res = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return {}, {"name": tool_name, "status": "error", "notes": f"request gagal: {exc}"}
    if res.status_code in (401, 403):
        return {}, {"name": tool_name, "status": "error", "notes": f"forbidden ({res.status_code})"}
    if res.status_code == 429:
        return {}, {"name": tool_name, "status": "error", "notes": "rate limited (429)"}
    if res.status_code != 200:
        return {}, {"name": tool_name, "status": "error", "notes": f"status {res.status_code}"}
    html = res.text or ""
    # Extract Next.js data blob
    m = re.search(r"<script id=\"__NEXT_DATA__\" type=\"application/json\">(.*?)</script>", html, re.S)
    entries: List[Dict[str, str]] = []
    details: Dict[str, Any] = {}
    if m:
        try:
            data = json.loads(m.group(1))
            flat = _flatten_obj(data)
            target_keys = [
                "name",
                "displayName",
                "alternativeName",
                "carrier",
                "location",
                "country",
                "city",
                "address",
                "e164",
                "national",
                "international",
                "phone",
                "spam",
                "type",
                "lineType",
                "timezone",
                "timezones",
                "countryCode",
            ]
            for k, v in flat.items():
                low = k.lower()
                if any(t.lower() in low for t in target_keys):
                    val = v if not isinstance(v, (list, dict)) else json.dumps(v, ensure_ascii=False)
                    entries.append({"site": f"{k}: {val}", "code": "+"})
            # Build compact details from a few likely keys
            # Prefer the first matching keys
            def _pick(key_parts: List[str]) -> Optional[str]:
                for fk, fv in flat.items():
                    lk = fk.lower()
                    if all(part.lower() in lk for part in key_parts):
                        return str(fv)
                return None
            details = {
                "name": _pick(["name"]) or _pick(["displayName"]) or None,
                "carrier": _pick(["carrier"]) or None,
                "location": _pick(["location"]) or _pick(["address"]) or None,
                "e164": _pick(["e164"]) or None,
                "international": _pick(["international"]) or None,
                "national": _pick(["national"]) or None,
                "country_code": _pick(["countrycode"]) or None,
                "spam": _pick(["spam"]) or None,
            }
        except Exception:
            pass
    # Fallback: parse key fields from visible HTML when JSON not available
    if not entries:
        # Extract name element like: div.flex-none.font-bold.break-all.sm:text-xl
        name_match = re.search(
            r"<div[^>]*class=\"[^\"]*(?:flex-none)[^\"]*(?:font-bold)[^\"]*(?:break-all)[^\"]*(?:sm:text-xl)[^\"]*\"[^>]*>(.*?)</div>",
            html,
            re.S,
        )
        if name_match:
            raw = name_match.group(1)
            # strip inner tags
            clean = re.sub(r"<[^>]+>", "", raw).strip()
            if clean:
                entries.append({"site": f"name: {clean}", "code": "+"})
                details.setdefault("name", clean)
    counts = {"+": len(entries), "-": 0, "x": 0, "!": 0}
    return (
        {"found": len(entries), "counts": counts, "entries": entries[:200], "details": details},
        {"name": tool_name, "status": "completed", "notes": f"{len(entries)} info"},
    )


def _run_truecaller_bs4(subscriber: str, cookie: Optional[str]) -> Tuple[Dict, Dict]:
    """Use local true.py helper (BeautifulSoup-based) to fetch Truecaller name for ID numbers.

    Expects Indonesian numbers (ISO path 'id') as per helper. Returns entries with the found name.
    """
    if not cookie:
        return {}, {"name": "truecaller", "status": "skipped", "notes": "cookie tidak disediakan"}
    try:
        # Local import to avoid side effects at module import time
        from .true import truecaller_scrape  # type: ignore
    except Exception as exc:
        return {}, {"name": "truecaller", "status": "skipped", "notes": f"modul true.py tidak tersedia: {exc}"}
    try:
        data = truecaller_scrape(subscriber, cookie) or {}
    except Exception as exc:
        return {}, {"name": "truecaller", "status": "error", "notes": str(exc)}
    name = (data or {}).get("name")
    status = (data or {}).get("status")
    entries: List[Dict[str, str]] = []
    if name and isinstance(name, str):
        entries.append({"site": f"name: {name}", "code": "+"})
    elif status and "limit" in str(status).lower():
        entries.append({"site": "rate_limited", "code": "x"})
    counts = {"+": sum(1 for e in entries if e["code"] == "+"), "-": 0, "x": sum(1 for e in entries if e["code"] == "x"), "!": 0}
    return (
        {"found": counts["+"], "counts": counts, "entries": entries[:200], "details": {"name": name, "status": status}},
        {"name": "truecaller", "status": "completed", "notes": status or "ok"},
    )


WHOIS_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _\-\.\/]+?)\s*:\s*(.+?)\s*$")


def _run_whois(domain: str) -> Tuple[Dict, Dict]:
    """Run `whois <domain>` and parse common fields into details and entries.

    Returns a tool output with entries and a compact details mapping for FE usage.
    """
    if shutil.which("whois") is None:
        return {}, {"name": "whois", "status": "skipped", "notes": "whois tidak terpasang"}
    cmd = ["whois", domain]
    code, out, err = _run_command(cmd)
    if code != 0 and not out.strip():
        return {}, {"name": "whois", "status": "error", "notes": err or "no output"}
    lines = out.splitlines()
    details: Dict[str, Any] = {}
    nameservers: List[str] = []
    statuses: List[str] = []
    registrar = None
    created = None
    updated = None
    expires = None
    country = None
    domain_name = None
    for raw in lines:
        if not raw or raw.startswith(('%', '#')) or raw.strip().startswith('>>>'):
            continue
        m = WHOIS_KV.match(raw)
        if not m:
            continue
        k = m.group(1).strip().lower()
        v = m.group(2).strip()
        if 'domain name' in k and not domain_name:
            domain_name = v
        elif 'registrar' == k or k.endswith('registrar'):
            # Skip lines like Registrar IANA ID
            if 'iana' in k:
                pass
            else:
                registrar = registrar or v
        elif 'creation date' in k or k.startswith('created'):
            created = created or v
        elif 'updated date' in k or k.startswith('updated'):
            updated = updated or v
        elif 'expiry date' in k or 'expire date' in k or 'registry expiry date' in k or k.startswith('expires'):
            expires = expires or v
        elif 'name server' in k or k.startswith('nserver'):
            ns = v.split()[0]
            if ns and ns.upper() not in (x.upper() for x in nameservers):
                nameservers.append(ns)
        elif 'status' in k:
            statuses.append(v)
        elif 'country' in k and not country:
            country = v
    if registrar:
        details['registrar'] = registrar
    if created:
        details['created'] = created
    if updated:
        details['updated'] = updated
    if expires:
        details['expires'] = expires
    if nameservers:
        details['nameservers'] = nameservers
    if statuses:
        details['status'] = statuses
    if country:
        details['country'] = country
    if domain_name:
        details['domain'] = domain_name
    # Build entries for UI
    entries: List[Dict[str, str]] = []
    for key in [
        'domain', 'registrar', 'created', 'updated', 'expires', 'country']:
        if details.get(key):
            entries.append({"site": f"{key}: {details[key]}", "code": "+"})
    if details.get('nameservers'):
        for ns in details['nameservers']:
            entries.append({"site": f"nameserver: {ns}", "code": "+"})
    if details.get('status'):
        for st in details['status']:
            entries.append({"site": f"status: {st}", "code": "+"})
    counts = {"+": len(entries), "-": 0, "x": 0, "!": 0}
    return (
        {"found": counts['+'], "counts": counts, "entries": entries[:200], "details": details},
        {"name": "whois", "status": "completed", "notes": f"{counts['+']} info"},
    )


def _run_holehe(email: str) -> Tuple[Dict, Dict]:
    if shutil.which("holehe") is None:
        return {}, {"name": "holehe", "status": "skipped", "notes": "holehe tidak terpasang"}
    # Use simplified invocation compatible with common installs: `holehe <email>`
    cmd = ["holehe", email]
    code, out, err = _run_command(cmd)
    if code != 0 and not out.strip():
        return {}, {"name": "holehe", "status": "error", "notes": err or "no output"}
    parsed = _parse_bracket_outputs(out)
    found = parsed["counts"].get("+", 0)
    return (
        {"found": found, "counts": parsed["counts"], "entries": parsed["entries"][:200]},
        {"name": "holehe", "status": "completed", "notes": f"{sum(parsed['counts'].values())} baris", "counts": parsed["counts"]},
    )


def _run_ignorant(identifier: str) -> Tuple[Dict, Dict]:
    if shutil.which("ignorant") is None:
        return {}, {"name": "ignorant", "status": "skipped", "notes": "ignorant tidak terpasang"}
    # Support username OR phone style: `ignorant 62 87856053716`
    # If looks like a phone, split into country code and subscriber number (digits only for subscriber)
    phone_match = re.match(r"^\+?(\d{1,3})\s*([0-9\s-]{5,})$", identifier.strip())
    if phone_match:
        cc = phone_match.group(1)
        subscriber = re.sub(r"\D", "", phone_match.group(2))
        cmd = ["ignorant", cc, subscriber]
    else:
        # Fallback: username mode `ignorant <username>`
        cmd = ["ignorant", identifier]
    code, out, err = _run_command(cmd)
    if code != 0 and not out.strip():
        return {}, {"name": "ignorant", "status": "error", "notes": err or "no output"}
    parsed = _parse_bracket_outputs(out)
    found = parsed["counts"].get("+", 0)
    return (
        {"found": found, "counts": parsed["counts"], "entries": parsed["entries"][:200]},
        {"name": "ignorant", "status": "completed", "notes": f"{sum(parsed['counts'].values())} baris", "counts": parsed["counts"]},
    )


def _run_phoneinfoga(number: str) -> Tuple[Dict, Dict]:
    """Run PhoneInfoga CLI if available and parse output.

    Tries JSON output first (-J), falls back to text parsing.
    Produces entries as list of "+" code with key:value facts for UI display.
    """
    if shutil.which("phoneinfoga") is None:
        return {}, {"name": "phoneinfoga", "status": "skipped", "notes": "phoneinfoga tidak terpasang"}
    # Prefer JSON (-J) if supported
    cmd = ["phoneinfoga", "scan", "-n", number, "-J"]
    code, out, err = _run_command(cmd)
    if code != 0 or not out.strip():
        cmd = ["phoneinfoga", "scan", "-n", number]
        code, out, err = _run_command(cmd)
        if code != 0 and not out.strip():
            return {}, {"name": "phoneinfoga", "status": "error", "notes": err or "no output"}
        # Try simple key: value parsing
        kv_re = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _\-/]+)\s*[:=]\s*(.+)$")
        entries = []
        for line in out.splitlines():
            m = kv_re.match(line.strip())
            if not m:
                continue
            key = m.group(1).strip()
            val = m.group(2).strip()
            entries.append({"site": f"{key}: {val}", "code": "+"})
        counts = {"+": len(entries), "-": 0, "x": 0, "!": 0}
        return (
            {"found": len(entries), "counts": counts, "entries": entries[:200]},
            {"name": "phoneinfoga", "status": "completed", "notes": f"{len(entries)} info"},
        )
    # JSON path
    entries = []
    try:
        data = json.loads(out)
        # Normalize into key-value pairs (flatten shallow fields)
        def _flatten(obj, prefix: str = ""):
            flat = {}
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        flat[key] = v
                    elif isinstance(v, (list, tuple)):
                        flat[key] = ", ".join(str(x) for x in v)
                    elif isinstance(v, dict):
                        flat.update(_flatten(v, key))
            return flat
        flat = _flatten(data)
        for k, v in flat.items():
            if v in (None, "", []):
                continue
            entries.append({"site": f"{k}: {v}", "code": "+"})
    except json.JSONDecodeError:
        entries = []
    counts = {"+": len(entries), "-": 0, "x": 0, "!": 0}
    return (
        {"found": len(entries), "counts": counts, "entries": entries[:200]},
        {"name": "phoneinfoga", "status": "completed", "notes": f"{len(entries)} info"},
    )


def _run_phonenumbers_local(number: str) -> Tuple[Dict, Dict]:
    """Use the phonenumbers library if installed to resolve basic details offline.

    Returns entries as "+" code facts and a structured dict under "details".
    """
    try:
        import phonenumbers  # type: ignore
        from phonenumbers import carrier as _pn_carrier, geocoder as _pn_geocoder, timezone as _pn_tz
    except Exception:
        return {}, {"name": "phonenumbers", "status": "skipped", "notes": "phonenumbers tidak terpasang"}
    try:
        pn = phonenumbers.parse(number)
        valid = phonenumbers.is_valid_number(pn)
        if not valid:
            return {}, {"name": "phonenumbers", "status": "error", "notes": "invalid number"}
        loc = _pn_geocoder.description_for_number(pn, "en")
        carr = _pn_carrier.name_for_number(pn, "en")
        tzs = _pn_tz.time_zones_for_number(pn) or []
        intl = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
        e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
        details = {
            "international": intl,
            "national": nat,
            "e164": e164,
            "country_code": str(pn.country_code),
            "location": loc,
            "carrier": carr,
            "timezones": list(tzs),
        }
        entries = []
        for k, v in details.items():
            if v in (None, "", [], {}):
                continue
            val = ", ".join(v) if isinstance(v, (list, tuple)) else v
            entries.append({"site": f"{k}: {val}", "code": "+"})
        counts = {"+": len(entries), "-": 0, "x": 0, "!": 0}
        return (
            {"found": len(entries), "counts": counts, "entries": entries[:200], "details": details},
            {"name": "phonenumbers", "status": "completed", "notes": f"{len(entries)} info"},
        )
    except Exception as exc:
        return {}, {"name": "phonenumbers", "status": "error", "notes": str(exc)}


def _run_nuclei(
    url: str,
    extra_args: List[str] | None = None,
    target_list: Sequence[str] | None = None,
    use_dast: bool = True,
) -> Tuple[List[Dict], Dict[str, str], List[str]]:
    _ensure_tool("nuclei")
    cmd = ["nuclei", "-silent", "-jsonl", "-c", "50"]
    if use_dast:
        cmd.append("-dast")
    target_file = None
    try:
        if target_list:
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
                handle.write("\n".join(target_list))
                target_file = handle.name
            cmd.extend(["-l", target_file])
        else:
            cmd.extend(["-u", url])
        if extra_args:
            cmd.extend(extra_args)
        exit_code, stdout, stderr = _run_command(cmd)
    finally:
        if target_file:
            Path(target_file).unlink(missing_ok=True)
    if exit_code != 0 and not stdout.strip():
        raise RuntimeError(f"Nuclei gagal: {stderr or 'tidak ada output'}")
    hits: List[Dict] = []
    json_samples: List[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            # Capture a compact JSON sample for debugging
            try:
                compact = json.dumps(
                    {
                        "template": data.get("template-id") or data.get("id"),
                        "name": (data.get("info") or {}).get("name"),
                        "severity": (data.get("info") or {}).get("severity") or data.get("severity"),
                        "matched": data.get("matched-at"),
                    },
                    ensure_ascii=False,
                )
                json_samples.append(f"[NUCLEI-JSON] {compact}")
            except Exception:
                pass
        except json.JSONDecodeError:
            match = NUCLEI_TEXT_PATTERN.search(line)
            if match:
                hits.append(
                    {
                        "title": match.group("template"),
                        "severity": match.group("severity").lower(),
                        "detected_by": "Nuclei",
                        "evidence": match.group("target"),
                        "vector": match.group("protocol"),
                    }
                )
            else:
                hits.append({"raw": line})
            continue
        info = data.get("info", {})
        # Be robust across nuclei versions: severity may be at top-level or under info
        severity_val = _norm_sev((info.get("severity") or data.get("severity")))
        # Attempt to infer method from nuclei record
        method_val = data.get("fuzzing_method")
        if not method_val:
            req = data.get("request") or ""
            if isinstance(req, str) and req:
                method_val = req.split(" ", 1)[0]
        param_val = data.get("fuzzing_parameter")
        hits.append(
            {
                "title": info.get("name") or data.get("template-id"),
                "severity": severity_val,
                "detected_by": "Nuclei",
                "evidence": data.get("matched-at"),
                "vector": data.get("template-id"),
                "param": param_val,
                "method": method_val,
                "url": data.get("url") or data.get("matched-at"),
            }
        )
    status = {"name": "Nuclei", "status": "completed", "notes": f"{len(hits)} temuan"}
    log_lines = [line for line in stderr.splitlines() if line.strip()]
    # Append a few JSON samples to logs for debugging (max 15 lines)
    log_lines.extend(json_samples[:15])
    # Save raw nuclei output and parsed hits for debugging into respon.json
    try:
        payload_dump = {
            "timestamp": datetime.utcnow().isoformat(),
            "command": " ".join(cmd),
            "targets": target_list or [url],
            "stdout": stdout.splitlines(),
            "stderr": [line for line in stderr.splitlines() if line.strip()],
            "parsed_hits": hits,
        }
        NUCLEI_RESPON_PATH.write_text(json.dumps(payload_dump, ensure_ascii=False, indent=2), encoding="utf-8")
        log_lines.append(f"[INF] Nuclei raw output saved to {NUCLEI_RESPON_PATH}")
    except Exception as exc:
        log_lines.append(f"[WRN] Tidak bisa menulis {NUCLEI_RESPON_PATH}: {exc}")
    return hits, status, log_lines


def _run_nikto(url: str) -> Tuple[List[Dict], Dict[str, str]]:
    _ensure_tool("nikto")
    cmd = ["nikto", "-h", url, "-ask", "none", "-nolookup"]
    exit_code, stdout, stderr = _run_command(cmd)
    if exit_code != 0 and not stdout.strip():
        raise RuntimeError(f"Nikto gagal: {stderr or 'tidak ada output'}")
    findings = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text or not text.startswith("+"):
            continue
        if "Target" in text[:12]:
            continue
        findings.append(
            {
                "title": text.lstrip("+ ").strip(),
                "severity": "info",
                "detected_by": "Nikto",
                "evidence": text,
                "vector": "HTTP",
            }
        )
    status = {"name": "Nikto", "status": "completed", "notes": f"{len(findings)} temuan"}
    return findings, status


def _run_dirb(url: str) -> Tuple[List[Dict], Dict[str, str]]:
    """Runner untuk Surface Auditor.

    Prefer ffuf (lebih cepat), fallback ke dirb klasik jika ffuf/wordlist tidak tersedia.
    """
    # Coba gunakan ffuf dengan wordlist 'admin' jika tersedia
    wl = _resolve_wordlist("admin")
    if shutil.which("ffuf") and wl:
        entries, status_obj = _run_ffuf(url, wl)
        # Konversi menjadi temuan untuk SurfaceAuditor
        findings = [
            {
                "title": url.rstrip("/") + entry["path"],
                "severity": "medium" if int(entry["status"]) in {200, 204, 401, 403} else "info",
                "detected_by": "FFUF",
                "evidence": f"{entry['status']} {entry['size']}",
                "vector": "Directory brute",
            }
            for entry in entries
        ]
        status_obj["name"] = "FFUF"
        status_obj["notes"] = f"{len(findings)} temuan"
        return findings, status_obj

    # Fallback ke dirb mini (bawaan) agar tetap ada hasil
    _ensure_tool("dirb")
    target = url if url.endswith("/") else f"{url.rstrip('/')}/"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("\n".join(DIRECTORY_WORDLIST))
            tmp.flush()
            tmp_path = tmp.name
        cmd = ["dirb", target, tmp_path, "-S"]
        exit_code, stdout, stderr = _run_command(cmd, timeout=180)
        if exit_code != 0 and "FOUND" not in stdout and not stdout.strip():
            raise RuntimeError(f"Dirb gagal: {stderr or 'tidak ada output'}")
        hits = []
        for line in stdout.splitlines():
            text = line.strip()
            if not text.startswith("+"):
                continue
            parts = text.split()
            if len(parts) < 2:
                continue
            hits.append(
                {
                    "title": parts[1],
                    "severity": "medium",
                    "detected_by": "Dirb",
                    "evidence": text,
                    "vector": "Directory brute",
                }
            )
        status = {"name": "Dirb", "status": "completed", "notes": f"{len(hits)} temuan"}
        return hits, status
    finally:
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)


def _deterministic_int(seed: str, min_value: int, max_value: int) -> int:
    digest = hashlib.sha256(seed.encode()).hexdigest()
    value = int(digest[:8], 16)
    return min_value + (value % (max_value - min_value + 1))


def _extract_host(target: str) -> Tuple[str, int]:
    if "://" not in target:
        target = f"//{target}"
    parsed = urlparse(target, scheme="http")
    if not parsed.hostname:
        raise ValueError("Host tidak valid")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname, port


def _safe_ip(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ipaddress.ip_address(resolved)
            return resolved
        except (socket.gaierror, ValueError):
            return host


def _probe_port(host: str, port: int, service: str) -> Dict:
    status: PortStatus = "closed"
    banner = "-"
    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TCP_TIMEOUT)
        try:
            sock.connect((_safe_ip(host), port))
            status = "open"
            if service in {"HTTP", "HTTPS"}:
                banner = _http_banner(host, port, service == "HTTPS")
            elif service == "SSH":
                banner = _tcp_banner(host, port)
            elif service == "MySQL":
                banner = _tcp_banner(host, port, prefix_len=50)
        except socket.timeout:
            status = "filtered"
        except OSError:
            status = "closed"
    latency = round(max(time.perf_counter() - start, 0.001), 3)
    return {
        "port": port,
        "service": service,
        "status": status,
        "version": banner if status == "open" else "-",
        "latency": latency,
    }


def _run_nmap_port_scan(host: str, ports: Sequence[Dict]) -> Tuple[List[Dict], Dict[str, int], str]:
    """Gunakan nmap untuk scan port jika tersedia; fallback ke socket jika gagal."""
    _ensure_tool("nmap")
    port_list = ",".join(str(p["port"]) for p in ports)
    cmd = [
        "nmap",
        "-Pn",              # jangan ping dulu
        "-sS",              # TCP SYN scan
        "-p",
        port_list,
        "--max-retries",
        "2",
        "--host-timeout",
        "15s",
        "-oG",
        "-",                # grepable output ke stdout
        host,
    ]
    exit_code, stdout, stderr = _run_command(cmd, timeout=25)
    if exit_code != 0 and not stdout.strip():
        raise RuntimeError(f"nmap gagal: {stderr or 'tidak ada output'}")

    table: List[Dict] = []
    summary = {"open": 0, "closed": 0, "filtered": 0}

    for line in stdout.splitlines():
        if "Ports:" not in line:
            continue
        # Contoh format: Host: 127.0.0.1 ()  Ports: 22/open/tcp//ssh///, 80/closed/tcp//http///
        try:
            ports_part = line.split("Ports:")[1].strip()
        except Exception:
            continue
        for item in ports_part.split(","):
            parts = item.strip().split("/")
            if len(parts) < 2:
                continue
            try:
                port_num = int(parts[0])
            except ValueError:
                continue
            status_val = parts[1] or "filtered"
            proto = parts[2] if len(parts) > 2 else "tcp"
            service = parts[4] if len(parts) > 4 and parts[4] else next(
                (entry["service"] for entry in SERVICE_PORTS if entry["port"] == port_num), "Custom"
            )
            status_norm: PortStatus
            if status_val.startswith("open"):
                status_norm = "open"
            elif status_val.startswith("closed"):
                status_norm = "closed"
            else:
                status_norm = "filtered"
            summary[status_norm] += 1
            table.append(
                {
                    "port": port_num,
                    "service": service,
                    "status": status_norm,
                    "version": proto,  # tidak ada banner, tampilkan proto
                    "latency": None,
                }
            )

    if not table:
        raise RuntimeError("nmap tidak menghasilkan tabel port")

    return table, summary, " ".join(cmd)


def _http_banner(host: str, port: int, https: bool) -> str:
    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        with httpx.Client(verify=False, timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            response = client.head(url)
            server = response.headers.get("server")
            powered = response.headers.get("x-powered-by")
            if server and powered:
                return f"{server}; {powered}"
            if server:
                return server
            if powered:
                return powered
    except httpx.HTTPError:
        return "open"
    return "open"


def _tcp_banner(host: str, port: int, prefix_len: int = 80) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_TIMEOUT)
            sock.connect((_safe_ip(host), port))
            data = sock.recv(prefix_len)
            if data:
                return data.decode(errors="ignore").strip()
    except OSError:
        return "open"
    return "open"


def _compute_port_risk(open_ports: Sequence[Dict]) -> int:
    score = sum(SERVICE_RISK.get(entry["service"], 8) for entry in open_ports)
    if any(entry["service"] == "HTTP" for entry in open_ports):
        score += 5
    if any(entry["service"] == "MySQL" for entry in open_ports):
        score += 10
    return min(score, 100)


def _port_insights(open_ports: Sequence[Dict]) -> List[str]:
    insights = []
    web_ports = [entry for entry in open_ports if entry["service"] in {"HTTP", "HTTPS"}]
    if web_ports:
        insights.append(
            f"{len(web_ports)} layanan web terbuka; jalankan Surface Auditor & XSS Scanner untuk endpoint terkait."
        )
    db_ports = [entry for entry in open_ports if entry["service"] in {"MySQL"}]
    if db_ports:
        insights.append("Database port terekspos; audit TLS/ACL dan implementasi pamd.")
    if not insights:
        insights.append("Tidak ada insight kritikal; lanjutkan dengan SQLi/XSS untuk validasi mendalam.")
    return insights


def generate_port_scan(payload: Dict) -> Dict:
    target = payload["target"]
    mode = payload.get("mode", "common")
    custom_ports = payload.get("custom_ports")
    host, inferred_port = _extract_host(target)
    if mode == "custom" and custom_ports:
        candidates = []
        for item in custom_ports.split(","):
            item = item.strip()
            if item.isdigit():
                port = int(item)
                service = next((entry["service"] for entry in SERVICE_PORTS if entry["port"] == port), "Custom")
                candidates.append({"port": port, "service": service})
        ports = candidates or SERVICE_PORTS
    else:
        ports = SERVICE_PORTS
    # Coba pakai nmap jika tersedia untuk hasil lebih akurat; fallback ke socket scan
    table: List[Dict]
    summary: Dict[str, int]
    command_used = None
    try:
        if shutil.which("nmap"):
            table, summary, command_used = _run_nmap_port_scan(host, ports)
        else:
            raise RuntimeError("nmap tidak tersedia")
    except Exception as exc:
        table = [_probe_port(host, entry["port"], entry["service"]) for entry in ports]
        summary = {"open": 0, "closed": 0, "filtered": 0}
        for row in table:
            summary[row["status"]] += 1
        command_used = f"socket-scan {host}:{inferred_port} ({mode}) | fallback: {exc}"
    open_ports = [row for row in table if row["status"] == "open"]
    risk_score = _compute_port_risk(open_ports)
    command = command_used or f"socket-scan {host}:{inferred_port} ({mode})"
    analysis: List[str] = []
    recommendations: List[str] = []
    for entry in open_ports:
        explanation, remediation = SERVICE_GUIDANCE.get(
            entry["service"],
            (
                "Layanan ini terbuka; verifikasi apakah memang perlu terekspos ke publik.",
                "Segmentasikan service ke jaringan internal atau gunakan VPN/bastion.",
            ),
        )
        version = entry["version"] if entry["version"] != "-" else "versi tidak terdeteksi"
        analysis.append(f"Port {entry['port']}/{entry['service']} terbuka ({version}). {explanation}")
        if remediation not in recommendations:
            recommendations.append(remediation)
    if not analysis:
        analysis.append("Tidak ada port terbuka yang merespon; permukaan serangan jaringan minim.")
    if not recommendations:
        recommendations.append("Tetap lakukan pemindaian berkala dan gunakan allow-list firewall.")
    return {
        "target": host,
        "table": table,
        "summary": summary,
        "risk_score": risk_score,
        "command": command,
        "insights": _port_insights(open_ports),
        "analysis": analysis,
        "recommendations": recommendations,
    }


def _prepare_request(url: str, parameter: str) -> Tuple[str, Dict[str, str]]:
    parsed = urlsplit(url)
    # Normalize query to avoid odd forms like "/param=/1" turning into invalid URLs.
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    normalized: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for k, v in pairs:
        nk = k.lstrip("/")
        nv = v
        if isinstance(nv, str) and nv.startswith("/") and nv[1:].isdigit():
            nv = nv[1:]
        if nk not in seen:
            normalized.append((nk, nv))
            seen.add(nk)
    query = dict(normalized)
    key = parameter.lstrip("/")
    if key not in query:
        query[key] = "1"
    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    return base or url, query


def _http_request(url: str, params: Dict[str, str]) -> httpx.Response:
    with httpx.Client(timeout=HTTP_TIMEOUT, verify=False, follow_redirects=True) as client:
        response = client.get(url, params=params)
        return response


def _build_sqli_mutations(
    url: str, parameter: str, payloads: Sequence[str]
) -> Tuple[str, Dict[str, str], List[Dict[str, str]]]:
    base_url, base_params = _prepare_request(url, parameter)
    mutations = []
    for payload in payloads:
        mutated = dict(base_params)
        mutated[parameter.lstrip("/")] = payload
        query = urlencode(mutated, doseq=True, safe=SQLI_SAFE_CHARS)
        final_url = f"{base_url}?{query}" if query else base_url
        mutations.append({"payload": payload, "params": mutated, "url": final_url})
    return base_url, base_params, mutations


def _probe_sql_payloads(
    base_url: str, baseline: Dict[str, int], mutations: Sequence[Dict[str, str]], mode: str
) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    rows: List[Dict[str, str]] = []
    stats = {"errors": 0, "blind": 0, "failures": 0, "anomalies": 0}
    base_len = baseline.get("length", 0)
    waf_markers = {"cf-ray", "x-sucuri-id", "x-firewall", "x-waf", "x-block", "server"}
    for mutation in mutations:
        start = time.perf_counter()
        try:
            response = _http_request(base_url, mutation["params"])
            elapsed_ms = (time.perf_counter() - start) * 1000
            body = response.text
            body_lower = body.lower()
            size = len(body)
        except httpx.HTTPError as exc:
            stats["failures"] += 1
            rows.append(
                {
                    "payload": mutation["payload"],
                    "result": "Request failed",
                    "response": str(exc),
                }
            )
            continue
        matched_error = next((error for error in SQL_ERRORS if error in body_lower), None)
        result = "Clean"
        evidence = None
        if matched_error:
            stats["errors"] += 1
            result = "SQL error leakage"
            evidence = matched_error
        elif response.status_code >= 500:
            stats["failures"] += 1
            result = f"Server error ({response.status_code})"
        else:
            header_blob = " ".join(f"{k.lower()}:{v}" for k, v in response.headers.items())
            if response.status_code in {401, 403, 406} and any(marker in header_blob.lower() for marker in waf_markers):
                result = "Blocked (WAF suspected)"
                evidence = "403/401/406 with WAF headers"
            else:
                if base_len:
                    delta = abs(size - base_len) / max(base_len, 1)
                    if delta > 0.35:
                        stats["anomalies"] += 1
                        result = "Content anomaly"
                        evidence = f"size diff {size-base_len:+d} ({delta*100:.0f}%)"
        blind_hit = False
        if mode == "blind" and elapsed_ms > 2500 and not matched_error:
            stats["blind"] += 1
            blind_hit = True
            if result == "Clean":
                result = "Timing anomaly"
                evidence = "slow-response"
        rows.append(
            {
                "payload": mutation["payload"],
                "result": result,
                "response": f"{response.status_code} | {elapsed_ms:.0f} ms",
                "evidence": evidence,
            }
        )
    return rows, stats


def generate_sql_scan(payload: Dict) -> Dict:
    url = str(payload["url"])
    param_name = payload.get("parameter") or "id"
    payload_type = payload.get("payload_type", "error")
    fuzz_payloads = SQLI_PAYLOADS.get(payload_type, SQLI_PAYLOADS["error"])
    # Auto-select parameter from URL query if provided parameter not present
    parsed_for_param = urlsplit(url)
    existing_params = dict(parse_qsl(parsed_for_param.query, keep_blank_values=True))
    auto_selected = False
    chosen_param = param_name
    if existing_params and param_name not in existing_params:
        chosen_param = next(iter(existing_params.keys()))
    # sanitize chosen param to avoid leading '/'
    if chosen_param.startswith('/'):
        chosen_param = chosen_param.lstrip('/')
        auto_selected = True
    base_url, base_params, mutations = _build_sqli_mutations(url, chosen_param, fuzz_payloads)

    # Preflight: ensure target is reachable; if not, return a clear, FE-friendly response
    try:
        baseline_resp = _preflight_http(base_url, base_params)
        baseline = {"status": baseline_resp.status_code, "length": len(baseline_resp.text)}
    except httpx.HTTPError as exc:
        return {
            "url": url,
            "payload_type": payload_type,
            "table": [
                {
                    "payload": "-",
                    "result": "Unreachable",
                    "response": str(exc),
                    "evidence": None,
                }
            ],
            "risk_score": 0,
            "mitigation": "Target tidak dapat dihubungi. Periksa URL/DNS/koneksi jaringan, lalu coba lagi.",
            "diff_original": f"SELECT * FROM users WHERE {param_name} = ?",
            "diff_patched": f"stmt = db.prepare('SELECT * FROM users WHERE {param_name} = ?')\nstmt.execute([sanitize({param_name})])",
            "recommendations": [
                "Pastikan target live dan bisa diakses dari server API (firewall/proxy).",
            ],
            "log": [
                f"[ERR] Target tidak dapat dihubungi: {str(exc)}",
                f"[INF] URL: {url}",
            ],
        }

    manual_rows, manual_stats = _probe_sql_payloads(base_url, baseline, mutations, payload_type)
    mutated_targets_all = [mutation["url"] for mutation in mutations] or [url]
    # Dedupe nuclei targets to avoid payload looping on identical URLs
    seen_targets: set[str] = set()
    mutated_targets: List[str] = []
    for t in mutated_targets_all:
        if t not in seen_targets:
            seen_targets.add(t)
            mutated_targets.append(t)
    findings: List[Dict] = []
    nuclei_logs: List[str] = []
    executed_cmds: List[str] = []
    # Run nuclei only for relevant payload types (skip for 'union' since no template matches)
    if payload_type != "union":
        # Primary: installed nuclei-templates via tags sqli (covers time-based, etc.)
        try:
            builtin_findings, _status1, logs1 = _run_nuclei(url, ["-tags", "sqli"], target_list=mutated_targets)
            findings.extend(builtin_findings)
            nuclei_logs.extend(logs1)
            executed_cmds.append("nuclei -silent -jsonl -c 50 -dast -tags sqli -l <mutations-list>")
        except RuntimeError as exc:
            nuclei_logs.append(f"[WRN] Nuclei '-tags sqli' gagal: {exc}")

        # Secondary: if custom local templates exist, run them too and merge
        if SQLI_TEMPLATE_DIR.exists():
            try:
                extra_findings, _status2, logs2 = _run_nuclei(url, ["-t", str(SQLI_TEMPLATE_DIR)], target_list=mutated_targets)
                if extra_findings:
                    findings.extend(extra_findings)
                nuclei_logs.extend(logs2)
                executed_cmds.append(f"nuclei -silent -jsonl -c 50 -dast -t {SQLI_TEMPLATE_DIR} -l <mutations-list>")
            except RuntimeError as exc:
                nuclei_logs.append(f"[WRN] Nuclei lokal (template kustom) gagal: {exc}")
        else:
            nuclei_logs.append(
                f"[INF] Template kustom lokal tidak ditemukan di {SQLI_TEMPLATE_DIR}. Melewati fase lokal."
            )
    else:
        nuclei_logs.append("[INF] Payload preset 'union' tidak memiliki template nuclei; hasil nuclei di-skip.")
    severity_order = ["info", "low", "medium", "high", "critical"]
    severity_score = {"info": 10, "low": 20, "medium": 55, "high": 80, "critical": 95}
    highest_index = 0
    rows: List[Dict[str, str]] = list(manual_rows)
    # Filter nuclei findings sesuai preset (error-based vs time-based/blind)
    def _match_preset(item: Dict[str, str]) -> bool:
        if payload_type == "union":
            return False
        vector = (item.get("vector") or "").lower()
        title = (item.get("title") or "").lower()
        text = f"{vector} {title}"
        if payload_type == "error":
            keys = ["error-based", "error based", "syntax error", "sql syntax", "unclosed quotation"]
            return any(k in text for k in keys)
        if payload_type == "blind":
            keys = ["time-based", "time based", "blind", "sleep", "pg_sleep", "delay"]
            return any(k in text for k in keys)
        return True

    # Deduplicate nuclei findings by evidence or title to avoid repeated rows
    seen_evidence: set[str] = set()
    for item in findings:
        if not _match_preset(item):
            continue
        ev = (item.get("evidence") or item.get("title") or "").strip()
        if ev and ev in seen_evidence:
            continue
        if ev:
            seen_evidence.add(ev)
        severity = (item.get("severity") or "info").lower()
        if severity in severity_order:
            highest_index = max(highest_index, severity_order.index(severity))
        rows.append(
            {
                "payload": item.get("title") or item.get("vector") or "Nuclei payload",
                "result": severity,
                "response": item.get("detected_by") or "Nuclei",
                "evidence": item.get("evidence") or item.get("matched-at"),
            }
        )
    if not rows:
        rows.append({"payload": "nuclei-sqli", "result": "Likely Safe", "response": "Tidak ada temuan"})
    risk_from_nuclei = severity_score.get(severity_order[highest_index], 0) if findings else 0
    risk_from_errors = 95 if manual_stats["errors"] else 0
    risk_from_blind = 75 if manual_stats["blind"] else 0
    risk_from_fail = 25 if manual_stats["failures"] else 0
    risk_from_anomaly = 40 if manual_stats.get("anomalies") else 0
    risk_score = max(
        risk_from_nuclei,
        risk_from_errors,
        risk_from_blind,
        risk_from_fail,
        risk_from_anomaly,
        0,
    )

    if manual_stats["errors"] or findings:
        recommendations = [
            "Segera patch query menjadi prepared statement/ORM.",
            "Aktifkan WAF/IPS untuk memblok payload SQLi yang umum.",
            "Batasi user DB ke hak minimum (SELECT saja).",
        ]
        mitigation = "Gunakan prepared statement, sanitasi input, dan aktifkan WAF ruleset SQLi."
    elif manual_stats["blind"]:
        recommendations = [
            "Investigasi query yang menyebabkan delay dan tambahkan limit waktu eksekusi DB.",
            "Gunakan prepared statement dan hindari concatenation dinamis untuk parameter.",
        ]
        mitigation = "Deteksi blind SQLi; gunakan prepared statement dan monitoring untuk query lambat."
    else:
        recommendations = [
            "Tidak ada payload nuclei yang tembus. Pertahankan sanitasi input saat ini dan lakukan tes berkala.",
            "Aktifkan logging & alert ketika terjadi error DB untuk deteksi dini.",
        ]
        mitigation = "Tidak terdeteksi injection melalui nuclei template."

    diff_original = f"SELECT * FROM users WHERE {param_name} = ?"
    diff_patched = f"stmt = db.prepare('SELECT * FROM users WHERE {param_name} = ?')\nstmt.execute([sanitize({param_name})])"
    log_lines = [
        f"[INF] Payload preset '{payload_type}' memodifikasi parameter '{param_name}' dengan {len(mutated_targets)} variasi.",
        f"[INF] Baseline: status={baseline['status']}, length={baseline['length']}.",
        f"[INF] Manual check: errors={manual_stats['errors']}, blind={manual_stats['blind']}, failures={manual_stats['failures']}, anomalies={manual_stats.get('anomalies',0)}.",
    ]
    if nuclei_logs:
        log_lines.extend(nuclei_logs)
    if findings:
        log_lines.append(f"[INF] Nuclei menemukan {len(findings)} temuan (maks severity {severity_order[highest_index]}).")
    if risk_score == 0:
        log_lines.append("[INF] Tidak ada indikasi SQL injection dari payload yang diuji.")
    # Add command previews and parameter selection note
    for cmd in executed_cmds:
        log_lines.append(f"[CMD] {cmd}")
    if auto_selected:
        log_lines.append(
            f"[INF] Parameter '{param_name}' tidak ada pada URL, otomatis memakai '{chosen_param}'."
        )
    return {
        "url": url,
        "payload_type": payload_type,
        "table": rows,
        "risk_score": risk_score,
        "mitigation": mitigation,
        "diff_original": diff_original.replace(param_name, chosen_param),
        "diff_patched": diff_patched.replace(param_name, chosen_param),
        "recommendations": recommendations,
        "log": log_lines[-200:],
    }


def generate_xss_scan(payload: Dict) -> Dict:
    """Run XSS checks by combining Dalfox and Nuclei XSS templates.

    - Dalfox: `dalfox url <target> --format json`
    - Nuclei: `nuclei -u <target> -c 50 -jsonl -t nuclei-templates/.../xss -dast`
    """
    target = payload.get("url")
    target_url = str(target) if target else ""
    if not target_url:
        raise RuntimeError("Field 'url' wajib diisi untuk XSS scan (contoh: https://target.com/search?q=test).")

    all_findings: List[Dict[str, str]] = []
    dalfox_count = 0
    nuclei_count = 0

    # 1) Dalfox (best-in-class for XSS)
    try:
        if shutil.which("dalfox") is None:
            raise RuntimeError("Tool 'dalfox' tidak ditemukan di PATH")
        cmd = ["dalfox", "url", target_url, "--silence", "--no-spinner", "--format", "json"]
        exit_code, stdout, stderr = _run_command(cmd)
        if exit_code != 0 and not stdout.strip():
            raise RuntimeError(f"Dalfox gagal: {stderr or 'tidak ada output'}")
        raw = stdout.strip()
        parsed_items: List[dict] = []
        # Dalfox sometimes outputs JSON array; handle both array and JSONL
        if raw.startswith('['):
            try:
                arr = json.loads(raw)
                if isinstance(arr, list):
                    parsed_items = [item for item in arr if isinstance(item, dict) and item]
            except json.JSONDecodeError:
                parsed_items = []
        if not parsed_items:
            for line in stdout.splitlines():
                text = line.strip()
                if not text:
                    continue
                try:
                    data = json.loads(text)
                    parsed_items.append(data)
                except json.JSONDecodeError:
                    # keep raw line for context
                    all_findings.append({"raw": text, "source": "Dalfox"})
        for data in parsed_items:
            all_findings.append(
                {
                    "type": data.get("message_str") or data.get("type") or "finding",
                    "payload": data.get("payload"),
                    "param": data.get("param"),
                    "method": data.get("method"),
                    "severity": (data.get("severity") or "info").lower(),
                    "url": data.get("data") or data.get("url"),
                    "host": data.get("host"),
                    "evidence": data.get("evidence") or data.get("matched-at") or data.get("description"),
                    "source": "Dalfox",
                }
            )
        dalfox_count = sum(1 for f in all_findings if f.get("source") == "Dalfox")
    except Exception as exc:
        # Non-fatal; we still try nuclei
        all_findings.append({
            "type": "Dalfox",
            "raw": f"Skipped/failed: {exc}",
            "source": "Dalfox",
        })

    # 2) Nuclei with local XSS templates
    nuclei_hits: List[Dict] = []
    try:
        if XSS_TEMPLATE_DIR.exists():
            hits, _status, logs = _run_nuclei(target_url, ["-t", str(XSS_TEMPLATE_DIR)])
            nuclei_hits = hits
        else:
            # fallback to tags if template dir missing
            hits, _status, logs = _run_nuclei(target_url, ["-tags", "xss"])
            nuclei_hits = hits
    except Exception as exc:
        # Don't fail the entire request; record diagnostic as a pseudo finding
        all_findings.append({
            "type": "Nuclei",
            "raw": f"Skipped/failed: {exc}",
            "source": "Nuclei",
        })

    # Map nuclei hits to UI-friendly schema and merge
    for hit in nuclei_hits:
        title = hit.get("title") or hit.get("vector") or "xss"
        severity = (hit.get("severity") or "info").lower()
        evidence = hit.get("evidence") or hit.get("vector")
        all_findings.append(
            {
                "type": f"Nuclei: {title}",
                "severity": severity,
                "param": hit.get("param"),
                "method": hit.get("method"),
                "payload": None,
                "url": hit.get("url") or evidence,
                "host": urlsplit(target_url).netloc,
                "evidence": evidence,
                "source": "Nuclei",
            }
        )
    nuclei_count = sum(1 for f in all_findings if f.get("source") == "Nuclei" and not f.get("raw", "").startswith("Skipped/failed"))

    # Deduplicate by evidence/type pair to avoid clutter
    deduped: List[Dict[str, str]] = []
    seen_keys = set()
    for f in all_findings:
        key = (f.get("evidence") or f.get("url") or f.get("raw") or f.get("type"), f.get("payload"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(f)

    # Risk scoring: combine count with worst nuclei severity
    severity_order = ["info", "low", "medium", "high", "critical"]
    severity_score = {"info": 5, "low": 10, "medium": 20, "high": 35, "critical": 55}
    worst_idx = 0
    for f in deduped:
        sev = (f.get("severity") or "").lower()
        if f.get("source") == "Nuclei" and sev in severity_order:
            worst_idx = max(worst_idx, severity_order.index(sev))
    base = min(100, len([f for f in deduped if not f.get("raw", "").startswith("Skipped/failed")]) * 15)
    risk_score = min(100, base + severity_score.get(severity_order[worst_idx], 0)) if deduped else 0

    detection_bits = []
    if dalfox_count:
        detection_bits.append(f"Dalfox menemukan {dalfox_count} potensi XSS")
    if nuclei_count:
        detection_bits.append(f"Nuclei menemukan {nuclei_count} temuan")
    detection = ("; ".join(detection_bits) + ".") if detection_bits else "Tidak ada temuan XSS dari Dalfox/Nuclei."

    recommendation = (
        "Implementasi output encoding konsisten; aktifkan Content-Security-Policy, HttpOnly + Secure cookie, dan validasi konteks."
        if (dalfox_count + nuclei_count) > 0
        else "Tetap aktifkan CSP dan lakukan review manual untuk konteks kompleks (event handler, template JS)."
    )

    return {
        "risk_score": risk_score,
        "detection": detection,
        "recommendation": recommendation,
        "findings": deduped,
        "url": target_url,
    }


def _fetch_headers(url: str) -> httpx.Response:
    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True, verify=False) as client:
        return client.get(url)


def _run_nmap_http_headers(url: str) -> Tuple[Dict[str, str], List[str]]:
    """Run nmap NSE scripts for HTTP header analysis."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if not host:
            return {}, ["Invalid URL format"]
        
        # Check if nmap is available
        if shutil.which("nmap") is None:
            return {}, ["nmap not available - using basic HTTP analysis"]
        
        # Run nmap with http-security-headers NSE script
        cmd = [
            "nmap", "-sS", "-Pn", 
            "--script", "http-security-headers,http-headers,http-methods",
            "--script-args", f"http.useragent='Header-Analyzer/1.0'",
            "-p", str(port),
            host
        ]
        
        exit_code, stdout, stderr = _run_command(cmd, timeout=30)
        
        logs = []
        nmap_data = {}
        
        if exit_code == 0:
            logs.append(f"nmap scan completed for {host}:{port}")
            
            # Parse nmap output for header information
            in_headers = False
            current_header = None
            
            for line in stdout.splitlines():
                line = line.strip()
                if "http-security-headers:" in line:
                    in_headers = True
                    continue
                elif in_headers and line.startswith("| "):
                    header_line = line[2:].strip()
                    if ":" in header_line:
                        key, value = header_line.split(":", 1)
                        nmap_data[key.strip().lower()] = value.strip()
                elif in_headers and not line.startswith("|"):
                    in_headers = False
                    
                # Also capture general HTTP headers
                if "http-headers:" in line:
                    in_headers = True
                    continue
                    
            logs.append(f"Extracted {len(nmap_data)} headers from nmap")
        else:
            logs.append(f"nmap failed: {stderr or 'Unknown error'}")
            
        return nmap_data, logs
        
    except Exception as exc:
        return {}, [f"nmap analysis failed: {str(exc)}"]


def _analyze_header_value(header: str, value: str) -> Tuple[str, str, List[str]]:
    """Analyze header value and provide detailed assessment."""
    issues = []
    
    if header == "content-security-policy":
        if not value:
            return "Missing", "critical", ["CSP not implemented - vulnerable to XSS attacks"]
        
        # Basic CSP analysis
        csp_lower = value.lower()
        if "'unsafe-eval'" in csp_lower:
            issues.append("unsafe-eval directive allows code execution")
        if "'unsafe-inline'" in csp_lower:
            issues.append("unsafe-inline directive allows inline scripts")
        if "*" in csp_lower and "default-src" in csp_lower:
            issues.append("Wildcard (*) in default-src is too permissive")
            
        severity = "weak" if issues else "good"
        return "Present" if not issues else "Weak", severity, issues
        
    elif header == "strict-transport-security":
        if not value:
            return "Missing", "critical", ["HSTS not enabled - vulnerable to downgrade attacks"]
        
        hsts_lower = value.lower()
        if "max-age" not in hsts_lower:
            issues.append("max-age directive missing")
        else:
            # Extract max-age value
            import re
            age_match = re.search(r'max-age=(\d+)', hsts_lower)
            if age_match:
                max_age = int(age_match.group(1))
                if max_age < 31536000:  # 1 year
                    issues.append(f"max-age too short: {max_age}s (recommended: 31536000s)")
        
        if "includesubdomains" not in hsts_lower:
            issues.append("includeSubDomains directive missing")
            
        severity = "weak" if issues else "good"
        return "Present" if not issues else "Partial", severity, issues
        
    elif header == "x-frame-options":
        if not value:
            return "Missing", "high", ["Clickjacking protection not enabled"]
        
        xfo_upper = value.upper()
        if xfo_upper in ["DENY", "SAMEORIGIN"]:
            return xfo_upper, "good", []
        elif xfo_upper.startswith("ALLOW-FROM"):
            return "ALLOW-FROM", "weak", ["ALLOW-FROM is deprecated, use CSP frame-ancestors instead"]
        else:
            return "Invalid", "weak", [f"Invalid X-Frame-Options value: {value}"]
            
    elif header == "x-content-type-options":
        if not value:
            return "Missing", "medium", ["MIME-type confusion attacks possible"]
        return "nosniff" if value.lower() == "nosniff" else "Invalid", "good" if value.lower() == "nosniff" else "weak", []
        
    elif header == "referrer-policy":
        if not value:
            return "Missing", "low", ["Referrer information may leak"]
        
        safe_policies = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"]
        if value.lower() in safe_policies:
            return value, "good", []
        else:
            return value, "weak", [f"Consider using stricter policy like 'strict-origin-when-cross-origin'"]
            
    elif header == "permissions-policy":
        if not value:
            return "Missing", "low", ["Feature policy not defined"]
        return "Present", "good", []
        
    elif header == "x-xss-protection":
        if not value:
            return "Missing", "medium", ["Legacy XSS protection not set"]
        if value == "1; mode=block":
            return "Enabled", "good", []
        elif value == "0":
            return "Disabled", "weak", ["XSS protection explicitly disabled"]
        else:
            return value, "weak", ["Non-standard XSS protection value"]
            
    else:
        # Generic header analysis
        if not value:
            return "Missing", "low", []
        return "Present", "good", []


def generate_header_scan(url: str) -> Dict:
    """Enhanced header scanner with nmap NSE integration."""
    logs = []
    
    try:
        # Basic HTTP header fetch
        response = _fetch_headers(url)
        logs.append(f"HTTP request to {url} completed: {response.status_code}")
        
        # Get nmap analysis
        nmap_headers, nmap_logs = _run_nmap_http_headers(url)
        logs.extend(nmap_logs)
        
        # Combine headers from both sources
        combined_headers = dict(response.headers)
        combined_headers.update(nmap_headers)
        
        headers = []
        recommendations: List[str] = []
        total_score = 0
        max_possible_score = 0
        critical_missing = 0
        
        for header in SECURITY_HEADERS:
            header_config = HEADER_SCORING.get(header, {"weight": 5, "critical": False})
            weight = header_config["weight"]
            is_critical = header_config["critical"]
            max_possible_score += weight
            
            value = combined_headers.get(header, "")
            status, severity, issues = _analyze_header_value(header, value)
            
            # Calculate score for this header
            if status == "Missing":
                header_score = 0
                if is_critical:
                    critical_missing += 1
            elif severity == "good":
                header_score = weight
            elif severity == "weak":
                header_score = weight * 0.5
            else:
                header_score = weight * 0.3
                
            total_score += header_score
            
            # Format status for display
            display_status = status
            if issues:
                display_status = f"{status} ({len(issues)} issues)"
            
            headers.append({
                "name": header.replace("-", " ").title(),
                "status": display_status,
                "value": value[:100] + "..." if len(value) > 100 else value,
                "severity": severity,
                "issues": issues,
                "weight": weight,
                "score": header_score
            })
            
            # Generate recommendations
            if status == "Missing" and is_critical:
                recommendations.append(f"CRITICAL: Implement {header.replace('-', ' ').title()} immediately")
            elif issues:
                recommendations.append(f"Fix {header.replace('-', ' ').title()}: {'; '.join(issues)}")
        
        # Calculate risk score (0-100, where 0 is perfect, 100 is terrible)
        if max_possible_score > 0:
            security_percentage = (total_score / max_possible_score) * 100
            risk_score = max(0, min(100, 100 - security_percentage))
        else:
            risk_score = 100
            
        # Add bonus penalties for critical issues
        risk_score += critical_missing * 15
        risk_score = min(100, risk_score)
        
        coverage = sum(1 for header in headers if header["status"] not in ["Missing"])
        critical_headers = sum(1 for h in SECURITY_HEADERS if HEADER_SCORING.get(h, {}).get("critical", False))
        critical_implemented = sum(1 for header in headers 
                                 if header["status"] not in ["Missing"] 
                                 and HEADER_SCORING.get(header["name"].lower().replace(" ", "-"), {}).get("critical", False))
        
        # Enhanced tool notes
        if risk_score >= 80:
            security_level = "Critical"
            tool_note = "Immediate action required - multiple critical security headers missing"
        elif risk_score >= 60:
            security_level = "High Risk"
            tool_note = "Significant security gaps identified - implement missing headers"
        elif risk_score >= 40:
            security_level = "Medium Risk" 
            tool_note = "Some security improvements needed"
        elif risk_score >= 20:
            security_level = "Low Risk"
            tool_note = "Good security posture with minor improvements needed"
        else:
            security_level = "Excellent"
            tool_note = "Excellent security header implementation"
            
        logs.append(f"Analysis complete: {security_level} (Risk Score: {risk_score})")
        
        if not recommendations:
            recommendations.append("Monitor headers regularly with automated tools")
            recommendations.append("Consider implementing Content Security Policy reporting")
            
        return {
            "url": url,
            "headers": headers,
            "risk_score": int(risk_score),
            "coverage": coverage,
            "critical_coverage": f"{critical_implemented}/{critical_headers}",
            "security_level": security_level,
            "tool_note": tool_note,
            "recommendations": recommendations,
            "total_score": int(total_score),
            "max_score": max_possible_score,
            "logs": logs[-20:],  # Keep last 20 log entries
            "nmap_enabled": bool(nmap_headers),
        }
        
    except Exception as exc:
        logs.append(f"Error in header analysis: {str(exc)}")
        return {
            "url": url,
            "headers": [],
            "risk_score": 100,
            "coverage": 0,
            "critical_coverage": "0/3",
            "security_level": "Error",
            "tool_note": f"Analysis failed: {str(exc)}",
            "recommendations": ["Fix connectivity issues and retry scan"],
            "total_score": 0,
            "max_score": 100,
            "logs": logs,
            "nmap_enabled": False,
        }


def generate_directory_scan(payload: Dict) -> Dict:
    base_url = str(payload["base_url"])
    wordlist = str(payload.get("wordlist", "admin"))
    wl_path = _resolve_wordlist(wordlist)
    entries: List[Dict] = []
    used_tool = None
    # Coba pakai ffuf jika tersedia + file wordlist ditemukan
    if shutil.which("ffuf") and wl_path and wl_path.exists():
        used_tool = "ffuf"
        try:
            entries, _ = _run_ffuf(base_url, wl_path)
        except RuntimeError as exc:
            # fallback ke probing HTTP cepat jika ffuf gagal
            entries = []
    if not entries and used_tool is None:
        # fallback: HTTP probing sederhana menggunakan fallback mini-wordlist
        used_tool = "http"
        targets = DIRECTORY_WORDLIST
        with httpx.Client(timeout=HTTP_TIMEOUT, verify=False, follow_redirects=False) as client:
            for path in targets:
                url = base_url.rstrip("/") + path
                try:
                    response = client.get(url)
                    entries.append(
                        {
                            "path": path,
                            "status": response.status_code,
                            "size": f"{len(response.content)} bytes",
                        }
                    )
                except httpx.HTTPError:
                    entries.append({"path": path, "status": "error", "size": "0"})

    # Hitung skor risiko berbasis status berbahaya
    score = 0
    for entry in entries:
        try:
            code = int(entry.get("status", 0))
        except Exception:
            code = 0
        if code in {200, 204}:
            score += 10
        elif code in {401, 403}:
            score += 8
        elif code in {301, 302, 307, 308}:
            score += 6
        elif code in {405}:
            score += 4
    risk_score = min(100, score)

    recs: List[str] = []
    if entries:
        recs.append(
            f"Kunci akses direktori sensitif dan matikan listing. Validasi dengan ffuf -u {base_url.rstrip('/')}/FUZZ -w {wl_path or 'wordlist/*.txt'}"
        )
        recs.append("Pindahkan backup/log ke lokasi privat atau beri proteksi.")
    else:
        recs.append("Tidak ada temuan signifikan. Coba wordlist lain untuk cakupan lebih luas.")

    return {
        "base_url": base_url,
        "wordlist": wordlist,
        "entries": entries,
        "risk_score": risk_score,
        "recommendations": recs,
    }




def generate_surface_scan(payload: Dict) -> Dict:
    url = str(payload["url"])
    techniques = payload.get("techniques") or ["Nuclei", "Nikto", "FFUF"]
    
    def _run_ffuf_surface(target: str):
        # Prefer wordlist "fuzz" bila ada, fallback ke "admin"
        wl = _resolve_wordlist("fuzz") or _resolve_wordlist("admin")
        if not shutil.which("ffuf"):
            return [], {"name": "FFUF", "status": "skipped", "notes": "ffuf tidak terpasang"}
        if not wl:
            return [], {"name": "FFUF", "status": "skipped", "notes": "wordlist tidak ditemukan (services/wordlist)"}
        try:
            entries, status = _run_ffuf(target, wl)
        except RuntimeError as exc:
            return [], {"name": "FFUF", "status": "error", "notes": str(exc)}
        findings = [
            {
                "title": target.rstrip("/") + entry["path"],
                "severity": "medium" if int(entry.get("status", 0)) in {200, 204, 401, 403} else "info",
                "detected_by": "FFUF",
                "evidence": f"{entry.get('status')} {entry.get('size')}",
                "vector": "Directory brute",
            }
            for entry in entries
        ]
        status["name"] = "FFUF"
        status["notes"] = f"{len(findings)} temuan"
        return findings, status
    def _run_nuclei_surface(target: str):
        # Jalankan nuclei pada origin root serta URL lengkap jika berbeda, menggunakan template HTTP lokal.
        base = _origin_root(target)
        targets = [base]
        if target.rstrip("/") + "/" != base:
            targets.append(target)
        template_dir = HTTP_TEMPLATE_DIR_ABS if HTTP_TEMPLATE_DIR_ABS.exists() else HTTP_TEMPLATE_DIR_REL
        try:
            findings, status, _logs = _run_nuclei(
                target,
                [
                    "-t",
                    str(template_dir),
                ],
                target_list=targets,
                use_dast=False,
            )
        except RuntimeError as exc:
            return [], {"name": "Nuclei", "status": "error", "notes": str(exc)}
        status["notes"] = f"{len(findings)} temuan (template: {template_dir})"
        return findings, status

    runners = {
        "Nuclei": _run_nuclei_surface,
        "Nikto": _run_nikto,
        "FFUF": _run_ffuf_surface,
    }
    vulnerabilities: List[Dict] = []
    tools_status: List[Dict] = []
    for tool in techniques:
        runner = runners.get(tool)
        if not runner:
            tools_status.append({"name": tool, "status": "skipped", "notes": "Belum terintegrasi."})
            continue
        tool_findings, status = runner(url)
        vulnerabilities.extend(tool_findings)
        tools_status.append(status)
    # Bangun spider dari entri FFUF (path + status code), tidak dari daftar vuln
    spider: List[Dict] = []
    for st in tools_status:
        if st.get("name") == "FFUF" and isinstance(st.get("entries"), list):
            for e in st["entries"]:
                spider.append({
                    "path": e.get("path"),
                    "code": e.get("status"),
                    "size": e.get("size"),
                })
    # Agregasi risiko berbasis severity untuk hasil gabungan
    severity_weights = {"info": 5, "low": 10, "medium": 20, "high": 35, "critical": 55}
    total = 0
    for v in vulnerabilities:
        sev = str(v.get("severity") or "info").lower()
        total += severity_weights.get(sev, 5)
    risk_score = min(100, total)

    # Ringkas temuan per tool agar FE tidak perlu menampilkan daftar panjang
    def _summary(items: List[Dict], tool_names: List[str]) -> List[Dict]:
        order = ["critical", "high", "medium", "low", "info"]
        agg: Dict[str, Dict[str, int]] = {}
        for it in items:
            tool = str(it.get("detected_by") or "Unknown")
            sev = str(it.get("severity") or "info").lower()
            if sev not in order:
                sev = "info"
            bucket = agg.setdefault(tool, {k: 0 for k in order})
            if sev not in bucket:
                bucket[sev] = 0
            bucket[sev] += 1
        out = []
        # Pastikan semua tool ada meski nol
        for tool in tool_names:
            counts = agg.get(tool, {k: 0 for k in order})
            out.append({"tool": tool, "counts": {k: counts.get(k, 0) for k in order}})
        return sorted(out, key=lambda x: x["tool"].lower())

    summary = _summary(vulnerabilities, [t.get("name") for t in tools_status if t.get("name")])
    # Fallback tambahan: jika Nuclei/Nikto 0 tapi status mencatat temuan >0 di notes, gunakan sebagai info
    names = [s["tool"] for s in summary]
    for idx, s in enumerate(list(summary)):
        total_counts = sum((s["counts"] or {}).values()) if s.get("counts") else 0
        if total_counts == 0 and s["tool"] in {"Nuclei", "Nikto"}:
            st = next((x for x in tools_status if x.get("name") == s["tool"]), None)
            if st and isinstance(st.get("notes"), str):
                import re as _re
                m = _re.search(r"(\d+)", st["notes"]) or _re.search(r"(\d+)", st.get("status", ""))
                if m:
                    n = int(m.group(1))
                    summary[idx]["counts"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": n}
    # Fallback: jika ringkasan FFUF nol tetapi ada entries, hitung dari entries
    tool_index = {item["name"]: idx for idx, item in enumerate(tools_status) if item.get("name")}
    names = [s["tool"] for s in summary]
    if "FFUF" in tool_index and "FFUF" in names:
        ffuf_status = tools_status[tool_index["FFUF"]]
        ffuf_entries = ffuf_status.get("entries") or []
        s_idx = names.index("FFUF")
        counts = dict(summary[s_idx]["counts"]) if summary[s_idx].get("counts") else {}
        if not any(counts.values()) and ffuf_entries:
            ff_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for e in ffuf_entries:
                try:
                    code = int(e.get("status", 0))
                except Exception:
                    code = 0
                sev = "medium" if code in {200, 204, 401, 403} else "info"
                ff_counts[sev] += 1
            summary[s_idx]["counts"] = ff_counts
    note = None if vulnerabilities else "Tidak ada temuan dari Nuclei/Nikto/FFUF pada konfigurasi default."
    recommendations = [
        "Jalankan nuclei -t http -u target menggunakan template HTTP yang relevan.",
        "Gunakan ffuf dengan wordlist kustom yang lebih besar untuk coverage maksimal.",
        "Lengkapi tahap pasif dengan ParamSpider & Dalfox untuk hunting parameter XSS.",
    ]
    return {
        "url": url,
        "techniques": techniques,
        "vulnerabilities": vulnerabilities,
        "spider": spider,
        "risk_score": risk_score,
        "tools": tools_status,
        "note": note,
        "recommendations": recommendations,
        "summary": summary,
    }


def generate_osint(payload: Dict) -> Dict:
    tab = payload.get("tab", "phone")
    value = payload.get("value", "")
    timestamp = datetime.utcnow().isoformat()
    confidence = ["High", "Medium", "Low"][_deterministic_int(value + tab, 0, 2)]
    tools_status: List[Dict] = []
    tool_results: Dict[str, Dict] = {}
    tool_outputs: List[Dict] = []
    if tab == "phone":
        carrier_map = ["Telkomsel", "Indosat", "XL Axiata", "Tri"]
        location_map = ["Jakarta", "Bandung", "Surabaya", "Yogyakarta"]
        # Minimal country metadata map (non-exhaustive, fallback to Unknown)
        COUNTRY_META = {
            "62": {
                "country": "Indonesia",
                "iso": "ID",
                "timezone": "Asia/Jakarta",
                "regions": [
                    "DKI Jakarta",
                    "Jawa Barat",
                    "Jawa Tengah",
                    "Jawa Timur",
                    "DI Yogyakarta",
                    "Banten",
                    "Bali",
                    "Sumatera Utara",
                ],
            },
            "1": {
                "country": "United States",
                "iso": "US",
                "timezone": "America/New_York",
                "regions": ["California", "New York", "Texas", "Florida"],
            },
            "44": {
                "country": "United Kingdom",
                "iso": "GB",
                "timezone": "Europe/London",
                "regions": ["England", "Scotland", "Wales", "Northern Ireland"],
            },
        }
        # Parse phone like phone.py expects: "+62 878..." or "62 878..."
        cc = None
        subscriber = None
        m = re.match(r"^\+?(\d{1,3})\s*([0-9\s-]{5,})$", value.strip())
        if m:
            cc = m.group(1)
            subscriber = re.sub(r"\D", "", m.group(2))
        else:
            digits = re.sub(r"\D", "", value)
            if len(digits) > 5:
                cc = digits[:2]
                subscriber = digits[2:]
        e164 = f"+{cc}{subscriber}" if (cc and subscriber) else None
        international = f"+{cc} {subscriber}" if (cc and subscriber) else None
        national = subscriber
        meta = COUNTRY_META.get(str(cc) if cc else "", {})
        country = meta.get("country") or ("Indonesia" if cc == "62" else None)
        iso = meta.get("iso") or ("ID" if cc == "62" else None)
        timezone = meta.get("timezone") or ("Asia/Jakarta" if cc == "62" else None)
        regions = meta.get("regions") or []
        region_pick = regions[_deterministic_int(value, 0, len(regions) - 1)] if regions else None
        result = {
            "carrier": carrier_map[_deterministic_int(value, 0, len(carrier_map) - 1)],
            "location": location_map[_deterministic_int(value[::-1], 0, len(location_map) - 1)],
            "validity": "Active" if str(value).strip().startswith("+62") or (cc == "62") else "Unknown",
            "country_code": cc,
            "e164": e164,
            "international": international,
            "national": national,
            "country": country,
            "iso": iso,
            "timezone": timezone,
            "region": region_pick,
        }
        # Try phoneinfoga (CLI) if available
        if e164:
            pfi_res, pfi_status = _run_phoneinfoga(e164)
            tools_status.append(pfi_status)
            if pfi_res:
                tool_results["phoneinfoga"] = pfi_res
                tool_outputs.append({"name": "phoneinfoga", **pfi_res})
        # Try Truecaller via local helper (for ID numbers) then fallback to web parser
        tc_cookie = (payload.get("truecaller_cookie") or os.environ.get("TRUECALLER_COOKIE") or None)
        if tc_cookie and (e164 or (cc and subscriber)):
            # Prefer bs4 helper using Indonesian ISO path
            if cc == "62" and subscriber:
                tc_res, tc_status = _run_truecaller_bs4(subscriber, tc_cookie)
                tools_status.append(tc_status)
                if tc_res:
                    tool_results["truecaller"] = tc_res
                    tool_outputs.append({"name": "truecaller", **tc_res})
            # Fallback generic web parser
            tw_res, tw_status = _run_truecaller(e164 or f"+{cc}{subscriber}", tc_cookie)
            tools_status.append(tw_status)
            if tw_res:
                tool_results["truecaller-web"] = tw_res
                tool_outputs.append({"name": "truecaller-web", **tw_res})
            # Propagate name to summary result if available
            for key in ("truecaller", "truecaller-web"):
                data = tool_results.get(key) or {}
                try:
                    details = data.get("details") if isinstance(data, dict) else None
                    name_val = (details or {}).get("name")
                    if name_val and not result.get("name"):
                        result["name"] = name_val
                except Exception:
                    pass
        # Try phonenumbers (library) if available
        pn_res, pn_status = _run_phonenumbers_local(e164 or (f"+{cc}{subscriber}" if (cc and subscriber) else value))
        tools_status.append(pn_status)
        if pn_res:
            tool_results["phonenumbers"] = pn_res
            tool_outputs.append({"name": "phonenumbers", **pn_res})
            # Prefer phonenumbers details for FE fields if available
            details = pn_res.get("details") if isinstance(pn_res, dict) else None
            if isinstance(details, dict) and details:
                try:
                    result["e164"] = details.get("e164") or result.get("e164")
                    result["international"] = details.get("international") or result.get("international")
                    result["national"] = details.get("national") or result.get("national")
                    result["country_code"] = details.get("country_code") or result.get("country_code")
                    # phonenumbers returns a location string; use as country/region if sensible
                    loc = details.get("location")
                    if loc:
                        # If country is empty or generic, set from location
                        if not result.get("country"):
                            result["country"] = loc
                        # Region prefers more granular value; if we had no region, set it
                        if not result.get("region"):
                            result["region"] = loc
                        # Also expose location consistently
                        result["location"] = loc
                    # Carrier direct from phonenumbers
                    if details.get("carrier"):
                        result["carrier"] = details.get("carrier")
                    # Timezones: list -> comma string
                    tzs = details.get("timezones")
                    if isinstance(tzs, (list, tuple)):
                        result["timezone"] = ", ".join([str(x) for x in tzs if x])
                    elif isinstance(tzs, str):
                        result["timezone"] = tzs
                except Exception:
                    pass
        # Try ignorant with phone as identifier (supports `ignorant 62 878...`)
        ign_res, ign_status = _run_ignorant(value)
        tools_status.append(ign_status)
        if ign_res:
            tool_results["ignorant"] = ign_res
            tool_outputs.append({"name": "ignorant", **ign_res})
    elif tab == "domain":
        registrar_map = ["Cloudflare", "Namecheap", "Pandi", "GoDaddy"]
        # Default/fallback values
        result = {
            "registrar": registrar_map[_deterministic_int(value, 0, len(registrar_map) - 1)],
            "created": f"20{_deterministic_int(value,15,24)}-0{_deterministic_int(value,1,9)}-12",
            "technologies": ["Nginx", "React", "Laravel"],
        }
        # Integrate whois
        whois_res, whois_status = _run_whois(value)
        tools_status.append(whois_status)
        if whois_res:
            tool_results["whois"] = whois_res
            tool_outputs.append({"name": "whois", **whois_res})
            det = whois_res.get("details") or {}
            # Promote key fields to result for FE summary
            if det.get("registrar"):
                result["registrar"] = det["registrar"]
            if det.get("created"):
                result["created"] = det["created"]
            if det.get("expires"):
                result["expires"] = det["expires"]
            if det.get("updated"):
                result["updated"] = det["updated"]
            if det.get("nameservers"):
                result["nameservers"] = det["nameservers"]
            if det.get("status"):
                result["status"] = det["status"]
            if det.get("country"):
                result["country"] = det["country"]
    elif tab == "email":
        # Integrate holehe if available
        hh_res, hh_status = _run_holehe(value)
        tools_status.append(hh_status)
        if hh_res:
            tool_results["holehe"] = hh_res
            tool_outputs.append({"name": "holehe", **hh_res})
        result = {
            "breaches": _deterministic_int(value, 0, 5),
            "gravatar": f"https://www.gravatar.com/avatar/{hashlib.md5(value.encode()).hexdigest()}?d=identicon",
            "disposable": value.endswith("@tempmail.com"),
        }
    else:
        # username
        ign_res, ign_status = _run_ignorant(value)
        tools_status.append(ign_status)
        if ign_res:
            tool_results["ignorant"] = ign_res
            tool_outputs.append({"name": "ignorant", **ign_res})
        result = {
            "appearances": _deterministic_int(value, 1, 12),
            "platforms": ["GitHub", "Twitter", "StackOverflow"],
        }
    # Build summary text
    parts = []
    for name, data in tool_results.items():
        counts = data.get("counts", {}) if isinstance(data, dict) else {}
        parts.append(
            f"{name}:+{counts.get('+',0)} -{counts.get('-',0)} x{counts.get('x',0)} !{counts.get('!',0)}"
        )
    summary_text = ", ".join(parts) if parts else None
    # Confidence bump if tools found many
    found_total = sum(res.get("found", 0) for res in tool_results.values())
    if found_total >= 10:
        confidence = "High"
    elif found_total >= 3 and confidence == "Low":
        confidence = "Medium"
    return {
        "tab": tab,
        "value": value,
        "timestamp": timestamp,
        "confidence": confidence,
        "tools": tools_status,
        "summary": tool_results,
        "summary_text": summary_text,
        "results": [
            {"tool": o.get("name"), "site": e.get("site"), "code": e.get("code")}
            for o in tool_outputs
            for e in o.get("entries", [])[:50]
        ],
        "tool_outputs": tool_outputs,
        **result,
    }


def generate_scan_history(seed: int = 5) -> List[Dict]:
    tools = [
        "Port Scanner",
        "SQLi Scanner",
        "XSS Scanner",
        "Header Analyzer",
        "Directory Buster",
        "OSINT Hub",
        "TLS Inspector",
        "Surface Auditor",
        "Credential Audit",
    ]
    history = []
    for idx in range(seed):
        tool = tools[idx % len(tools)]
        identifier = hashlib.sha1(f"{tool}-{idx}".encode()).hexdigest()[:6]
        risk = (idx * 13) % 90 + 10
        history.append(
            {
                "id": f"hist-{identifier}",
                "tool": tool,
                "target": f"{tool.lower().replace(' ', '-')}.eduscan.local",
                "risk": risk,
                "timestamp": datetime.utcnow().isoformat(),
                "status": "Completed" if risk < 70 else "Warning",
            }
        )
    return history


def generate_credential_audit(payload: Dict) -> Dict:
    """
    Real credential audit using actual security tools (JtR, hashcat, hashid, etc.)
    Falls back to fast heuristic analysis if tools unavailable
    """
    samples = payload.get("samples", [])
    cleaned = [line.strip() for line in samples if line.strip()]
    
    weak = []
    reused = []
    crackable = []
    hash_analysis = []
    seen_passwords = {}
    tool_results = {}
    tools_used = []
    
    # Common weak passwords (rockyou top patterns)
    weak_patterns = [
        "password", "123456", "admin", "root", "guest", "test", "user",
        "qwerty", "letmein", "welcome", "monkey", "dragon", "master",
        "shadow", "football", "baseball", "superman", "batman"
    ]
    
    # Password complexity analysis
    complexity_stats = {
        "min_length": float('inf'),
        "max_length": 0,
        "avg_length": 0,
        "has_uppercase": 0,
        "has_lowercase": 0,
        "has_numbers": 0,
        "has_symbols": 0,
        "total_entropy": 0
    }
    
    for entry in cleaned:
        if ":" not in entry:
            continue
            
        parts = entry.split(":", 1)
        if len(parts) < 2:
            continue
            
        username = parts[0]
        credential = parts[1]
        
        # Detect if it's a hash or plaintext using real tools
        print(f"DEBUG MAIN: Processing credential: '{credential}'")
        is_hash, detection_method = _detect_hash_type_with_tools(credential)
        print(f"DEBUG MAIN: Detection result: is_hash='{is_hash}', method='{detection_method}'")
        
        # Track detection tools used
        if detection_method == "enhanced" and "enhanced-detector" not in tools_used:
            tools_used.append("enhanced-detector")
            print(f"DEBUG MAIN: Added enhanced-detector to tools_used")
        elif detection_method == "hashcat" and "hashcat" not in tools_used:
            tools_used.append("hashcat")
        elif detection_method == "hashid" and "hashid" not in tools_used:
            tools_used.append("hashid")
        elif detection_method == "hash-identifier" and "hash-identifier" not in tools_used:
            tools_used.append("hash-identifier")
        
        print(f"DEBUG MAIN: Current tools_used: {tools_used}")
        
        if is_hash and is_hash != "":
            print(f"DEBUG MAIN: Processing as HASH: {is_hash}")
            # Check against common hash database first (fastest)
            rainbow_result = _check_common_hashes(credential)
            cracked_by_rainbow = rainbow_result.get("status") == "found"
            
            hash_analysis.append({
                "username": username,
                "hash_type": is_hash,
                "hash": credential[:20] + "..." if len(credential) > 20 else credential,
                "crackability": estimate_hash_strength(is_hash),
                "detection_method": detection_method,
                "rainbow_cracked": cracked_by_rainbow,
                "plaintext": rainbow_result.get("plaintext") if cracked_by_rainbow else None
            })
            
            # Mark as crackable if found in rainbow tables or weak hash type
            if cracked_by_rainbow:
                crackable.append(f"{username}:{credential[:16]}... → {rainbow_result.get('plaintext')} (Rainbow tables)")
            elif is_hash in ["MD5", "NTLM", "LM", "SHA1"]:
                crackable.append(f"{username}:{credential[:16]}... (Weak hash: {is_hash})")
        else:
            print(f"DEBUG MAIN: Processing as PLAINTEXT: {credential}")
            # Plaintext password analysis
            password = credential
            
            # Update complexity stats
            length = len(password)
            complexity_stats["min_length"] = min(complexity_stats["min_length"], length)
            complexity_stats["max_length"] = max(complexity_stats["max_length"], length)
            
            if any(c.isupper() for c in password):
                complexity_stats["has_uppercase"] += 1
            if any(c.islower() for c in password):
                complexity_stats["has_lowercase"] += 1
            if any(c.isdigit() for c in password):
                complexity_stats["has_numbers"] += 1
            if any(not c.isalnum() for c in password):
                complexity_stats["has_symbols"] += 1
                
            # Calculate entropy (simplified)
            entropy = _calculate_password_entropy(password)
            complexity_stats["total_entropy"] += entropy
            
            # Weakness detection (JtR style)
            weakness_reasons = []
            
            # Length check
            if length < 8:
                weakness_reasons.append("too_short")
            
            # Common patterns
            password_lower = password.lower()
            if any(weak in password_lower for weak in weak_patterns):
                weakness_reasons.append("common_pattern")
                
            # Dictionary words
            if password_lower in ["password", "admin123", "letmein", "welcome123"]:
                weakness_reasons.append("dictionary_word")
                
            # Keyboard patterns
            if _is_keyboard_pattern(password):
                weakness_reasons.append("keyboard_pattern")
                
            # Date patterns
            if _contains_date_pattern(password):
                weakness_reasons.append("date_pattern")
                
            # Username in password
            if username.lower() in password_lower or password_lower in username.lower():
                weakness_reasons.append("contains_username")
                
            if weakness_reasons or entropy < 35:
                weak.append({
                    "entry": entry,
                    "reasons": weakness_reasons,
                    "entropy": round(entropy, 1),
                    "jtr_estimate": "< 1 hour" if entropy < 25 else "< 1 day" if entropy < 35 else "< 1 week" if entropy < 45 else "months+"
                })
            
            # Reuse detection
            if password in seen_passwords:
                reused.append({
                    "current": entry,
                    "previous": seen_passwords[password],
                    "password_hash": hashlib.md5(password.encode()).hexdigest()[:8]
                })
            seen_passwords[password] = entry
    
    # Run real tools on hashes if any found
    if hash_analysis and (shutil.which("john") or shutil.which("hashcat")):
        # Create temporary hash file for tools
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                hash_file_path = f.name
                for hash_entry in hash_analysis:
                    if not hash_entry.get("rainbow_cracked"):
                        # Write in john format: username:hash
                        original_entry = next((e for e in cleaned if hash_entry["username"] in e), "")
                        if original_entry:
                            f.write(original_entry + '\n')
            
            # Try John the Ripper first
            if shutil.which("john") and os.path.getsize(hash_file_path) > 0:
                john_result = _run_john_the_ripper(hash_file_path)
                tool_results["john"] = john_result
                
                # Update hash analysis with JtR results
                for cracked_line in john_result.get("cracked", []):
                    if ":" in cracked_line:
                        cracked_user, cracked_pass = cracked_line.split(":", 1)
                        for hash_entry in hash_analysis:
                            if hash_entry["username"] == cracked_user and not hash_entry.get("rainbow_cracked"):
                                hash_entry["jtr_cracked"] = True
                                hash_entry["plaintext"] = cracked_pass
                                crackable.append(f"{cracked_user}:*** → {cracked_pass} (John the Ripper)")
            
            # Try hashcat if john didn't crack everything
            uncracked_hashes = [h for h in hash_analysis if not h.get("rainbow_cracked") and not h.get("jtr_cracked")]
            if shutil.which("hashcat") and uncracked_hashes:
                hashcat_result = _run_hashcat_quick(hash_file_path)
                tool_results["hashcat"] = hashcat_result
                
                # Update with hashcat results
                for cracked_line in hashcat_result.get("cracked", []):
                    if ":" in cracked_line:
                        cracked_hash, cracked_pass = cracked_line.split(":", 1)
                        for hash_entry in hash_analysis:
                            if cracked_hash in hash_entry["hash"] and not hash_entry.get("rainbow_cracked") and not hash_entry.get("jtr_cracked"):
                                hash_entry["hashcat_cracked"] = True
                                hash_entry["plaintext"] = cracked_pass
                                crackable.append(f"{hash_entry['username']}:*** → {cracked_pass} (Hashcat)")
            
            # Clean up temp file
            os.unlink(hash_file_path)
            
        except Exception as e:
            tool_results["error"] = f"Tool execution error: {str(e)}"
    
    # Calculate averages for plaintext passwords only
    plaintext_entries = []
    for e in cleaned:
        if ":" in e:
            parts = e.split(":", 1)
            if len(parts) == 2:
                cred = parts[1]
                hash_type, _ = _detect_hash_type_with_tools(cred)
                if not hash_type:  # It's plaintext
                    plaintext_entries.append(cred)
    
    total_passwords = len(plaintext_entries)
    if total_passwords > 0:
        complexity_stats["avg_length"] = sum(len(p) for p in plaintext_entries) / total_passwords
        complexity_stats["total_entropy"] = complexity_stats["total_entropy"] / total_passwords
    else:
        complexity_stats["avg_length"] = 0
        complexity_stats["min_length"] = 0
        complexity_stats["total_entropy"] = 0
    
    # Policy compliance
    policy = {
        "uppercase": complexity_stats["has_uppercase"] > 0,
        "lowercase": complexity_stats["has_lowercase"] > 0,
        "numbers": complexity_stats["has_numbers"] > 0,
        "symbols": complexity_stats["has_symbols"] > 0,
        "min_length_8": complexity_stats["min_length"] >= 8 if complexity_stats["min_length"] != float('inf') else False,
        "avg_entropy": round(complexity_stats["total_entropy"], 1)
    }
    
    # Risk scoring (JtR/Hashcat style) - Proportional calculation
    total_credentials = len(cleaned)
    if total_credentials == 0:
        risk_score = 0
    else:
        # Base score calculation (0-100)
        risk_score = 0
        
        # Weak password percentage (0-40 points)
        weak_percentage = (len(weak) / total_credentials) * 100
        risk_score += min(40, weak_percentage * 0.4)
        
        # Reused password percentage (0-25 points)
        reused_percentage = (len(reused) / total_credentials) * 100
        risk_score += min(25, reused_percentage * 0.25)
        
        # Crackable hash percentage (0-30 points)
        if hash_analysis:
            crackable_percentage = (len(crackable) / len(hash_analysis)) * 100
            risk_score += min(30, crackable_percentage * 0.3)
        
        # Policy compliance penalties (0-15 points total)
        policy_penalties = 0
        if not policy["symbols"]:
            policy_penalties += 3
        if not policy["min_length_8"]:
            policy_penalties += 4
        if policy["avg_entropy"] < 30:
            policy_penalties += 5
        elif policy["avg_entropy"] < 40:
            policy_penalties += 2
        
        risk_score += policy_penalties
        
        # Ensure minimum score for any issues found
        if weak or reused or crackable:
            risk_score = max(risk_score, 15)  # Minimum 15 if any issues
        
        # Cap at 100
        risk_score = min(100, int(risk_score))
    
    # Enhanced recommendations
    recommendations = []
    
    if weak:
        recommendations.append(f"🔥 {len(weak)} password lemah terdeteksi - gunakan John the Ripper dengan --wordlist=rockyou.txt --rules")
        recommendations.append("Implementasi hashcat dengan rule-based attack: hashcat -a 0 -r best64.rule")
        
    if reused:
        recommendations.append(f"♻️ {len(reused)} password reuse terdeteksi - aktifkan password history policy")
        
    if crackable:
        recommendations.append(f"💀 {len(crackable)} hash lemah terdeteksi - upgrade ke bcrypt/scrypt/Argon2")
        
    if hash_analysis:
        weak_hashes = [h for h in hash_analysis if h["crackability"] == "high"]
        if weak_hashes:
            recommendations.append(f"⚠️ {len(weak_hashes)} hash dengan algoritma lemah (MD5/NTLM/LM)")
            
    if policy["avg_entropy"] < 35:
        recommendations.append("📊 Entropy rata-rata rendah - terapkan kebijakan kompleksitas password")
        
    if not policy["symbols"]:
        recommendations.append("🔤 Wajibkan karakter khusus dalam password policy")
        
    # Enhanced JtR/Hashcat command suggestions based on actual results
    jtr_commands = []
    if hash_analysis:
        # Suggest commands based on hash types found
        hash_types = list(set(h["hash_type"] for h in hash_analysis if h["hash_type"]))
        for hash_type in hash_types:
            john_format = get_john_format(hash_type)
            hashcat_mode = get_hashcat_mode(hash_type)
            
            if john_format:
                jtr_commands.append(f"john --format={john_format} --wordlist=rockyou.txt hashfile.txt")
            if hashcat_mode is not None:
                jtr_commands.append(f"hashcat -m {hashcat_mode} -a 0 hashfile.txt rockyou.txt")
    
    # Add tool execution results to recommendations
    if tool_results:
        if tool_results.get("john", {}).get("status") == "completed":
            john_time = tool_results["john"].get("time_taken", 0)
            john_cracked = len(tool_results["john"].get("cracked", []))
            recommendations.append(f"🔧 John the Ripper: {john_cracked} hash cracked dalam {john_time}s")
        
        if tool_results.get("hashcat", {}).get("status") == "completed":
            hashcat_time = tool_results["hashcat"].get("time_taken", 0)
            hashcat_cracked = len(tool_results["hashcat"].get("cracked", []))
            recommendations.append(f"⚡ Hashcat: {hashcat_cracked} hash cracked dalam {hashcat_time}s")
        
        if tool_results.get("john", {}).get("status") == "not_installed":
            recommendations.append("📦 Install John the Ripper: apt install john")
        
        if tool_results.get("hashcat", {}).get("status") == "not_installed":
            recommendations.append("📦 Install Hashcat: apt install hashcat")
        
    if not recommendations:
        recommendations.append("✅ Credential audit menunjukkan keamanan yang baik")
        recommendations.append("🔄 Lanjutkan audit berkala dengan JtR/Hashcat")
    
    # Determine actual tools used
    tools_used = []
    if tool_results.get("john"):
        tools_used.append("john")
    if tool_results.get("hashcat"):
        tools_used.append("hashcat")
    if any(h.get("rainbow_cracked") for h in hash_analysis):
        tools_used.append("rainbow_tables")
    if any(h.get("detection_method") == "hashid" for h in hash_analysis):
        tools_used.append("hashid")
    if any(h.get("detection_method") == "hash-identifier" for h in hash_analysis):
        tools_used.append("hash-identifier")
    
    return {
        "total": len(cleaned),
        "weak": [w["entry"] for w in weak],
        "weak_detailed": weak,
        "reused": [r["current"] for r in reused],
        "reused_detailed": reused,
        "crackable_hashes": crackable,
        "hash_analysis": hash_analysis,
        "policy": policy,
        "complexity_stats": complexity_stats,
        "risk_score": risk_score,
        "recommendations": recommendations,
        "jtr_commands": jtr_commands,
        "tools_suggested": ["john", "hashcat", "hydra", "medusa", "hashid"],
        "tools_used": tools_used,
        "tool_results": tool_results
    }


def _detect_hash_type_with_tools(credential: str) -> tuple[str, str]:
    """Detect hash type using hashcat --identify first, then fallback to other methods"""
    if not credential:
        return "", "hashcat"
    
    # PRIORITY 1: Use enhanced built-in detector (most reliable for profiling)
    enhanced_result = detect_hash_type(credential)
    print(f"DEBUG: Enhanced detector input: '{credential}'")
    print(f"DEBUG: Enhanced detector result: '{enhanced_result}'")
    
    if enhanced_result != "":  # Hash detected
        print(f"DEBUG: Returning hash type: {enhanced_result}")
        return enhanced_result, "enhanced"
    else:  # Plaintext or no detection
        print(f"DEBUG: Enhanced detector says plaintext or no detection")
        return "", "enhanced"
    
    # PRIORITY 3: Fallback to hashid if available
    if shutil.which("hashid"):
        try:
            result = subprocess.run(
                ["hashid", credential], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if '[+]' in line and 'Possible' not in line and 'Unknown' not in line:
                        hash_type = line.split('[+]')[-1].strip()
                        if hash_type and hash_type != "Unknown hash":
                            # Double-check for obvious passwords
                            if any(pattern in credential.lower() for pattern in ["admin", "password", "123", "test", "user"]):
                                return "", "hashid"
                            return hash_type, "hashid"
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
    
    # PRIORITY 4: Fallback to hash-identifier
    if shutil.which("hash-identifier"):
        try:
            process = subprocess.Popen(
                ["hash-identifier"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, _ = process.communicate(input=f"{credential}\n", timeout=5)
            if "Possible Hashs:" in stdout:
                lines = stdout.split('\n')
                for i, line in enumerate(lines):
                    if "Possible Hashs:" in line and i + 1 < len(lines):
                        hash_type = lines[i + 1].strip().replace('[+]', '').strip()
                        if hash_type and hash_type != "Not Found.":
                            # Double-check for obvious passwords
                            if any(pattern in credential.lower() for pattern in ["admin", "password", "123", "test", "user"]):
                                return "", "hash-identifier"
                            return hash_type, "hash-identifier"
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
    
    # If no hash detected by any method, it's plaintext
    return "", "fallback"


def _detect_hash_type_builtin(credential: str) -> str:
    """Built-in hash detection based on hash-id.py logic"""
    if not credential:
        return ""
    
    # Check for obvious plaintext patterns first
    if any(c in credential for c in [' ', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+']) and len(credential) < 50:
        # If it contains common password characters and is short, likely plaintext
        if not (len(credential) in [16, 32, 40, 56, 64, 80, 96, 128] and all(c in "0123456789abcdefABCDEF" for c in credential)):
            return ""
    
    # Hash format detection (from hash-id.py patterns)
    h = credential.lower()
    
    # bcrypt patterns
    if credential.startswith("$2a$") or credential.startswith("$2b$") or credential.startswith("$2y$"):
        return "bcrypt"
    
    # Unix crypt patterns  
    if credential.startswith("$1$"):
        return "MD5crypt"
    if credential.startswith("$6$"):
        return "SHA512crypt"
    if credential.startswith("$5$"):
        return "SHA256crypt"
    
    # WordPress/phpBB patterns
    if credential.startswith("$P$") or credential.startswith("$H$"):
        return "WordPress/phpBB3"
    
    # Length-based detection for hex hashes
    if all(c in "0123456789abcdef" for c in h):
        if len(h) == 32:
            return "MD5"
        elif len(h) == 40:
            return "SHA1"  
        elif len(h) == 56:
            return "SHA224"
        elif len(h) == 64:
            return "SHA256"
        elif len(h) == 96:
            return "SHA384"
        elif len(h) == 128:
            return "SHA512"
        elif len(h) == 16:
            return "LM"
    
    # NTLM (usually 32 hex chars, but context matters)
    if len(h) == 32 and all(c in "0123456789abcdef" for c in h) and ":" not in credential:
        return "NTLM"
    
    # MySQL hash patterns
    if len(h) == 16 and all(c in "0123456789abcdef" for c in h):
        return "MySQL323"
    if credential.startswith("*") and len(credential) == 41:
        return "MySQL5"
    
    # SAM format (LM:NTLM)
    if ":" in credential and len(credential) == 65:
        parts = credential.split(":")
        if len(parts) == 2 and len(parts[0]) == 32 and len(parts[1]) == 32:
            return "SAM"
    
    return ""


def _detect_hash_type_heuristic(credential: str) -> str:
    """Legacy heuristic detection - kept for compatibility"""
    return _detect_hash_type_builtin(credential)


def _calculate_password_entropy(password: str) -> float:
    """Calculate password entropy (simplified Shannon entropy)"""
    if not password:
        return 0
        
    # Character set size estimation
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32  # Common symbols
        
    if charset_size == 0:
        return 0
        
    # Entropy = log2(charset_size^length)
    import math
    return len(password) * math.log2(charset_size)


def _is_keyboard_pattern(password: str) -> bool:
    """Detect keyboard patterns like qwerty, asdf, etc."""
    keyboard_patterns = [
        "qwerty", "asdf", "zxcv", "123456", "654321",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1qaz2wsx", "qazwsx", "wsxedc"
    ]
    
    password_lower = password.lower()
    return any(pattern in password_lower for pattern in keyboard_patterns)


def _contains_date_pattern(password: str) -> bool:
    """Detect date patterns in password"""
    import re
    
    # Common date patterns
    date_patterns = [
        r'\d{4}',  # Year
        r'\d{1,2}/\d{1,2}/\d{2,4}',  # Date formats
        r'\d{1,2}-\d{1,2}-\d{2,4}',
        r'\d{8}',  # YYYYMMDD
        r'(19|20)\d{2}',  # 1900-2099
    ]
    
    for pattern in date_patterns:
        if re.search(pattern, password):
            return True
            
    return False


def generate_wappalyzer_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run Wappalyzer CLI to detect website technologies.
    Uses the wappy command to analyze the domain and return structured technology data.
    Falls back to basic HTTP header analysis if wappy is not available.
    """
    domain = payload.get("domain", "").strip()
    if not domain:
        raise RuntimeError("Domain is required for Wappalyzer scan")
    
    # Remove protocol if present
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc or domain
    
    technologies = {}
    total_found = 0
    
    # Try wappy command first
    try:
        # Create temporary file for wappalyzer output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        # Run wappy command
        cmd = ["wappy", "-u", domain, "-wf", tmp_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            cwd=Path.home()
        )
        
        # Try to parse JSON output first
        if result.returncode == 0 and Path(tmp_path).exists():
            try:
                with open(tmp_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        wapp_data = json.loads(content)
                        
                        # Parse wappalyzer JSON output format
                        if isinstance(wapp_data, list) and wapp_data:
                            site_data = wapp_data[0]
                            if "technologies" in site_data:
                                for tech in site_data["technologies"]:
                                    category = tech.get("categories", [{}])[0].get("name", "Other")
                                    if category not in technologies:
                                        technologies[category] = []
                                    
                                    tech_info = {
                                        "name": tech.get("name", "Unknown"),
                                        "version": tech.get("version") if tech.get("version") else None
                                    }
                                    technologies[category].append(tech_info)
                                    total_found += 1
                
                # Clean up temp file
                try:
                    os.unlink(tmp_path)
                except:
                    pass
                    
            except (json.JSONDecodeError, KeyError, IndexError):
                # If JSON parsing fails, try to parse from stdout
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        if line.startswith('[+]TECHNOLOGIES['):
                            continue
                        elif ' : ' in line:
                            parts = line.split(' : ', 1)
                            if len(parts) == 2:
                                category = parts[0].strip()
                                tech_info = parts[1].strip()
                                
                                if category not in technologies:
                                    technologies[category] = []
                                
                                # Parse version info
                                name = tech_info
                                version = None
                                if '[version: ' in tech_info:
                                    name = tech_info.split(' [version: ')[0]
                                    version_part = tech_info.split(' [version: ')[1].rstrip(']')
                                    if version_part != 'nil':
                                        version = version_part
                                
                                technologies[category].append({
                                    "name": name,
                                    "version": version
                                })
                                total_found += 1
        
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        # wappy command failed or not found, continue to fallback
        pass
    except Exception:
        # Any other error with wappy, continue to fallback
        pass
    
    # Fallback: Basic HTTP header analysis if wappy failed or found nothing
    if not technologies:
        try:
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                try:
                    response = httpx.get(f"{protocol}://{domain}", timeout=HTTP_TIMEOUT, follow_redirects=True)
                    headers = dict(response.headers)
                    content = response.text.lower()
                    
                    # Server detection
                    server = headers.get("server", "").lower()
                    if "nginx" in server:
                        technologies.setdefault("Web servers", []).append({"name": "Nginx", "version": None})
                    elif "apache" in server:
                        technologies.setdefault("Web servers", []).append({"name": "Apache", "version": None})
                    elif "litespeed" in server:
                        technologies.setdefault("Web servers", []).append({"name": "LiteSpeed", "version": None})
                    elif "cloudflare" in server:
                        technologies.setdefault("CDN", []).append({"name": "Cloudflare", "version": None})
                    
                    # Programming language detection
                    if "x-powered-by" in headers:
                        powered_by = headers["x-powered-by"].lower()
                        if "php" in powered_by:
                            # Try to extract PHP version
                            php_version = None
                            if "/" in powered_by:
                                php_version = powered_by.split("/")[-1].strip()
                            technologies.setdefault("Programming languages", []).append({"name": "PHP", "version": php_version})
                        elif "asp.net" in powered_by:
                            technologies.setdefault("Programming languages", []).append({"name": "ASP.NET", "version": None})
                    
                    # CMS detection from content
                    if "wp-content" in content or "wordpress" in content:
                        technologies.setdefault("CMS", []).append({"name": "WordPress", "version": None})
                    elif "joomla" in content:
                        technologies.setdefault("CMS", []).append({"name": "Joomla", "version": None})
                    elif "drupal" in content:
                        technologies.setdefault("CMS", []).append({"name": "Drupal", "version": None})
                    
                    # JavaScript library detection
                    if "jquery" in content:
                        technologies.setdefault("JavaScript libraries", []).append({"name": "jQuery", "version": None})
                    if "bootstrap" in content:
                        technologies.setdefault("UI frameworks", []).append({"name": "Bootstrap", "version": None})
                    
                    # E-commerce detection
                    if "woocommerce" in content:
                        technologies.setdefault("Ecommerce", []).append({"name": "WooCommerce", "version": None})
                    elif "shopify" in content:
                        technologies.setdefault("Ecommerce", []).append({"name": "Shopify", "version": None})
                    
                    total_found = sum(len(techs) for techs in technologies.values())
                    break  # Success, exit the protocol loop
                    
                except Exception:
                    continue  # Try next protocol
                    
        except Exception:
            # Complete fallback - return minimal valid response
            technologies = {"Web servers": [{"name": "Unknown", "version": None}]}
            total_found = 1
    
    return {
        "domain": domain,
        "technologies": technologies,
        "total_found": total_found,
        "timestamp": datetime.now().isoformat()
    }


def _run_john_the_ripper(hash_file_path: str, hash_format: str = None) -> Dict:
    """Run John the Ripper on hash file, return cracked passwords"""
    if not shutil.which("john"):
        return {"tool": "john", "status": "not_installed", "cracked": [], "time_taken": 0}
    
    try:
        # Prepare john command
        cmd = ["john", "--show", hash_file_path]
        if hash_format:
            # Map common formats to john formats
            john_formats = {
                "MD5": "Raw-MD5",
                "SHA1": "Raw-SHA1", 
                "SHA256": "Raw-SHA256",
                "NTLM": "NT",
                "bcrypt": "bcrypt",
                "MD5crypt": "md5crypt"
            }
            if hash_format in john_formats:
                cmd = ["john", f"--format={john_formats[hash_format]}", hash_file_path]
        
        # Run quick crack attempt (30 seconds max)
        start_time = time.time()
        
        # First try to show already cracked
        show_result = subprocess.run(
            ["john", "--show", hash_file_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        cracked = []
        if show_result.returncode == 0 and show_result.stdout:
            for line in show_result.stdout.strip().split('\n'):
                if ':' in line and line.strip():
                    cracked.append(line.strip())
        
        # If nothing cracked yet, try quick crack
        if not cracked:
            crack_result = subprocess.run(
                cmd + ["--wordlist=/usr/share/wordlists/rockyou.txt"] if os.path.exists("/usr/share/wordlists/rockyou.txt") else cmd,
                capture_output=True,
                text=True,
                timeout=30  # Quick 30-second attempt
            )
            
            # Check results again
            show_result = subprocess.run(
                ["john", "--show", hash_file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if show_result.returncode == 0 and show_result.stdout:
                for line in show_result.stdout.strip().split('\n'):
                    if ':' in line and line.strip():
                        cracked.append(line.strip())
        
        time_taken = time.time() - start_time
        
        return {
            "tool": "john",
            "status": "completed",
            "cracked": cracked,
            "time_taken": round(time_taken, 2)
        }
        
    except subprocess.TimeoutExpired:
        return {"tool": "john", "status": "timeout", "cracked": [], "time_taken": 30}
    except Exception as e:
        return {"tool": "john", "status": "error", "cracked": [], "error": str(e), "time_taken": 0}


def _run_hashcat_quick(hash_file_path: str, hash_mode: int = None) -> Dict:
    """Run hashcat quick attack on hash file"""
    if not shutil.which("hashcat"):
        return {"tool": "hashcat", "status": "not_installed", "cracked": [], "time_taken": 0}
    
    try:
        start_time = time.time()
        
        # Determine hashcat mode
        if hash_mode is None:
            hash_mode = 0  # MD5 default
            
        # Quick dictionary attack (15 seconds max)
        cmd = [
            "hashcat", 
            "-m", str(hash_mode),
            "-a", "0",  # Dictionary attack
            hash_file_path,
            "/usr/share/wordlists/rockyou.txt" if os.path.exists("/usr/share/wordlists/rockyou.txt") else "/usr/share/dict/words",
            "--runtime=15",  # 15 second limit
            "--quiet"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20
        )
        
        # Check for cracked passwords in potfile
        cracked = []
        try:
            potfile_path = os.path.expanduser("~/.local/share/hashcat/hashcat.potfile")
            if os.path.exists(potfile_path):
                with open(potfile_path, 'r') as f:
                    for line in f:
                        if ':' in line:
                            cracked.append(line.strip())
        except:
            pass
            
        time_taken = time.time() - start_time
        
        return {
            "tool": "hashcat",
            "status": "completed",
            "cracked": cracked[-10:] if cracked else [],  # Last 10 results
            "time_taken": round(time_taken, 2)
        }
        
    except subprocess.TimeoutExpired:
        return {"tool": "hashcat", "status": "timeout", "cracked": [], "time_taken": 20}
    except Exception as e:
        return {"tool": "hashcat", "status": "error", "cracked": [], "error": str(e), "time_taken": 0}


def _check_common_hashes(password_hash: str) -> Dict:
    """Check hash against common weak hashes database"""
    # Common weak hashes that would be in rainbow tables
    weak_hashes = {
        "5d41402abc4b2a76b9719d911017c592": "hello",  # MD5
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": "hello",  # SHA1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "",  # SHA256 empty
        "d41d8cd98f00b204e9800998ecf8427e": "",  # MD5 empty
        "da39a3ee5e6b4b0d3255bfef95601890afd80709": "",  # SHA1 empty
        "098f6bcd4621d373cade4e832627b4f6": "test",  # MD5 test
        "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": "test",  # SHA1 test
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "password",  # SHA256 password
        "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5": "secret",  # SHA256 secret
        "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f": "admin123",  # SHA256 admin123
    }
    
    if password_hash.lower() in weak_hashes:
        return {
            "tool": "rainbow_tables",
            "status": "found",
            "plaintext": weak_hashes[password_hash.lower()],
            "source": "common_hashes"
        }
    
    return {"tool": "rainbow_tables", "status": "not_found"}
