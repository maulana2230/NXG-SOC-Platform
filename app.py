#!/usr/bin/env python3
"""
IP REPUTATION INVESTIGATOR - Web Application
Flask backend wrapping ip_investigator logic
"""

import json
import math
import os
import re
import sys
import time
import threading
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, send_from_directory, make_response, Response, stream_with_context, send_file
from flask_cors import CORS

# ── PDF generation (ReportLab) ────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable, KeepTogether)
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics import renderPDF
    from io import BytesIO
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# ── Path setup ────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# ── Import investigator core ──────────────────────────────────────
sys.path.insert(0, BASE_DIR)

try:
    import requests as req_lib
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Run: pip install requests flask flask-cors")
    sys.exit(1)

# ── Scoring weights (same as original) ───────────────────────────
SC = {
    "abuse_conf_weight":        0.40,
    "abuse_reports_weight":     4,     # per log2(1+reports) step
    "abuse_reports_max":        20,    # cap for report-volume component
    "abuse_distinct_bonus":     5,     # >= abuse_distinct_min unique reporters
    "abuse_distinct_min":       10,
    "abuse_tor_bonus":          10,
    "vt_malicious_per_engine":  4,
    "vt_suspicious_per_engine": 1,
    "otx_pulse_per_hit":        3,
    "otx_malware_bonus":        8,
    "otx_max":                  25,
    "ha_threat_weight":         0.30,
    "ha_malicious_flat":        20,
    "ha_suspicious_flat":       10,
    "gn_malicious_flat":        20,
    "gn_suspicious_flat":       10,
    "ipapi_proxy_score":        5,
    "ipapi_hosting_score":      0,
    "threatfox_ioc_per_hit":    8,
    "threatfox_max":            30,
    # Dampening factor applied to OTX pulse score when the IP is whitelisted
    # shared infrastructure (AbuseIPDB isWhitelisted / OTX validation).
    # Pulse membership on Google/Cloudflare/Fastly IPs is co-occurrence
    # (malware *contacting* the infra), not attribution.
    "wl_otx_dampen":            0.25,
}

# ── Batch parallelism + per-source throttles ──────────────────────
# IPs are investigated in parallel (BATCH_WORKERS at a time). Sources with
# tight free-tier quotas are token-bucket throttled so parallel batches
# don't trigger 429s (which would put keys on 1h failover cooldown):
#   VirusTotal  free tier: 4 req/min  → 15.1s min interval PER KEY
#   ip-api      free tier: 45 req/min → 1.4s min interval (global, IP-based)
BATCH_WORKERS_DEFAULT = 5
BATCH_WORKERS_MAX     = 10

class RateLimiter:
    """Thread-safe min-interval limiter (token bucket, capacity 1)."""
    def __init__(self, min_interval):
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._next_ok = 0.0
    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now  = time.monotonic()
            slot = max(now, self._next_ok)
            self._next_ok = slot + self.min_interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)
    def next_free(self):
        """When (monotonic ts) this limiter's next slot opens. For load balancing."""
        with self._lock:
            return self._next_ok

VT_MIN_INTERVAL    = 15.1   # set to 0 if you have a paid VT key
IPAPI_LIMITER      = RateLimiter(1.4)
_VT_LIMITERS       = {}
_VT_LIMITERS_LOCK  = threading.Lock()

def vt_limiter(key):
    """One limiter per VT key — multiple keys multiply effective throughput."""
    with _VT_LIMITERS_LOCK:
        if key not in _VT_LIMITERS:
            _VT_LIMITERS[key] = RateLimiter(VT_MIN_INTERVAL)
        return _VT_LIMITERS[key]

SESSION = req_lib.Session()
SESSION.mount("https://", HTTPAdapter(
    # 429 intentionally excluded from auto-retry — we want to read the response and
    # fail over to a backup API key immediately rather than burning retries on a
    # key that's already rate-limited.
    max_retries=Retry(total=3, backoff_factor=0.6, status_forcelist=[500, 502, 503, 504])
))

# ── Config ────────────────────────────────────────────────────────
def load_config():
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(data):
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=2)

# ── Multi-key pools + automatic failover ───────────────────────────
# Each source field (e.g. "ABUSEIPDB_KEY") may have a primary key stored
# directly under that field, plus an optional list of backup keys stored
# under "<FIELD>_BACKUPS". When the primary key gets rate-limited, queries
# automatically roll over to the next configured backup key.
# Fields in ROTATE_FIELDS additionally load-balance across ALL keys on
# every request (round-robin by limiter availability) instead of only
# failing over on 429 — required for throttled sources like VT where the
# limiter prevents 429s and would otherwise leave backup keys idle.
BACKUP_SUFFIX = "_BACKUPS"
ROTATE_FIELDS = {"VIRUSTOTAL_KEY"}

_PLACEHOLDER_RE = re.compile(r"^(your_|<|xxx|changeme|placeholder|none$|null$)", re.I)

def _is_real_key(v):
    """Reject empty values and the placeholders shipped in config.example.json
    (e.g. YOUR_ABUSEIPDB_API_KEY) so they are not treated as configured keys."""
    if not isinstance(v, str):
        return False
    v = v.strip()
    if not v or _PLACEHOLDER_RE.match(v) or "your_key_here" in v.lower():
        return False
    return True

def get_key_pool(cfg, field):
    """Return an ordered list of all non-empty API keys configured for a
    source field: primary key first, then backup keys, de-duplicated."""
    pool = []
    primary = cfg.get(field)
    if isinstance(primary, str) and _is_real_key(primary):
        pool.append(primary.strip())
    elif isinstance(primary, list):  # tolerate legacy/odd shapes
        pool.extend(x.strip() for x in primary if _is_real_key(x))
    backups = cfg.get(field + BACKUP_SUFFIX)
    if isinstance(backups, list):
        for b in backups:
            if _is_real_key(b) and b.strip() not in pool:
                pool.append(b.strip())
    return pool

_KEY_STATE_LOCK = threading.Lock()
_KEY_COOLDOWN  = {}   # {(field, key): unix_ts_until_retry}
_KEY_LAST_GOOD = {}   # {field: key}
_KEY_COOLDOWN_SECONDS = 3600  # don't retry a rate-limited key for 1h

_RATE_LIMIT_MARKERS = (
    "rate limit", "quota", "429", "too many requests", "daily limit",
    "limit exceeded", "limit reached",
)

def _looks_rate_limited(result):
    if not isinstance(result, dict):
        return False
    err = (result.get("error") or "").lower()
    return any(m in err for m in _RATE_LIMIT_MARKERS)

def query_with_key_failover(field, cfg, fn):
    """Call fn(key) -> result dict, trying each configured key for `field`
    in turn. Keys that come back rate-limited are put on a cooldown and the
    next key is tried instead. The last key that worked cleanly is preferred
    on subsequent calls. Returns None if no key is configured at all."""
    pool = get_key_pool(cfg, field)
    if not pool:
        return None

    now = time.time()
    with _KEY_STATE_LOCK:
        last_good = _KEY_LAST_GOOD.get(field)
        cooldowns = dict(_KEY_COOLDOWN)

    def sort_key(k):
        in_cooldown = cooldowns.get((field, k), 0) > now
        return (in_cooldown, k != last_good)

    if field in ROTATE_FIELDS:
        # Least-loaded rotation instead of primary-first failover: pick the
        # key whose rate-limit slot frees up soonest, so ALL configured keys
        # share the load (N keys ≈ N× effective request rate). Keys on
        # cooldown (daily quota exhausted) still sort last.
        ordered = sorted(pool, key=lambda k: (cooldowns.get((field, k), 0) > now,
                                              vt_limiter(k).next_free()))
    else:
        ordered = sorted(pool, key=sort_key)

    result = None
    for key in ordered:
        result = fn(key)
        if _looks_rate_limited(result):
            with _KEY_STATE_LOCK:
                _KEY_COOLDOWN[(field, key)] = time.time() + _KEY_COOLDOWN_SECONDS
            continue
        if not result.get("error"):
            with _KEY_STATE_LOCK:
                _KEY_LAST_GOOD[field] = key
        return result

    # Every configured key for this source is currently rate-limited.
    if result is not None and len(pool) > 1:
        base_err = result.get("error") or "Rate limit exceeded"
        result["error"] = "{}  (all {} configured keys rate-limited)".format(base_err, len(pool))
    return result

# ── Validation ────────────────────────────────────────────────────
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def is_cidr(entry):
    """True if entry is a CIDR prefix like 202.130.52.0/24 (not a bare IP)."""
    entry = entry.strip()
    if "/" not in entry:
        return False
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False

# Safety cap on how many host IPs a single scan may expand to. A /20 = 4096
# hosts. Bigger than this and free-tier TI quotas (AbuseIPDB ~1000/day) get
# burned instantly, so we truncate and surface a note to the caller.
MAX_CIDR_HOSTS = 4096

def expand_targets(raw_ips):
    """Expand a mixed list of bare IPs and CIDR prefixes into de-duplicated
    host IPs. Returns (valid_ips, invalid, notes).

    - CIDR (e.g. 202.130.52.0/24) expands to usable hosts (network/broadcast
      excluded for prefixes shorter than /31; /31 and /32 keep all addresses).
    - Expansion is capped at MAX_CIDR_HOSTS per prefix; overflow is truncated
      and reported in notes.
    """
    valid_ips = []
    invalid = []
    notes = []
    seen = set()

    def _add(ip_str):
        if ip_str not in seen:
            seen.add(ip_str)
            valid_ips.append(ip_str)

    for entry in raw_ips:
        entry = (entry or "").strip()
        if not entry:
            continue
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                invalid.append(entry)
                continue
            hosts = list(net) if net.num_addresses <= 2 else list(net.hosts())
            if len(hosts) > MAX_CIDR_HOSTS:
                notes.append("{}: {} hosts, capped to first {}".format(
                    entry, len(hosts), MAX_CIDR_HOSTS))
                hosts = hosts[:MAX_CIDR_HOSTS]
            else:
                notes.append("{}: expanded to {} host(s)".format(entry, len(hosts)))
            for h in hosts:
                _add(str(h))
        elif is_valid_ip(entry):
            _add(entry.strip())
        else:
            invalid.append(entry)

    return valid_ips, invalid, notes

# ── Source queries (same logic as original script) ────────────────
def q_abuse(ip, key):
    r = {"source": "AbuseIPDB", "score": 0, "ioc": [], "error": None}
    if not key:
        r["error"] = "No API key"
        return r
    try:
        resp = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=15,
        )
        if resp.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"
            return r
        if resp.status_code in (401, 403):
            r["error"] = "Invalid API key"
            return r
        d = resp.json().get("data", {})
        conf   = d.get("abuseConfidenceScore", 0)
        total  = d.get("totalReports", 0)
        is_tor = d.get("isTor", False)
        wl     = d.get("isWhitelisted", False)
        r["ioc"].append("Confidence: {}%  |  Reports: {}  |  Country: {}".format(conf, total, d.get("countryCode", "N/A")))
        r["ioc"].append("ISP: {}  |  Usage: {}".format(d.get("isp", "N/A"), d.get("usageType", "N/A")))
        if wl:
            r["score"] = -10
            r["whitelisted"] = True
            r["ioc"].append("WHITELISTED by AbuseIPDB (shared infrastructure) — -10 pts offset applied")
            return r
        r["score"] += conf * SC["abuse_conf_weight"]
        # Report volume as an independent signal — log-scaled so it still
        # contributes when abuseConfidenceScore has decayed to 0%.
        if total > 0:
            rep_score = min(SC["abuse_reports_weight"] * math.log2(1 + total),
                            SC["abuse_reports_max"])
            r["score"] += rep_score
            r["ioc"].append("Report volume: {} reports (+{:.1f} pts)".format(total, rep_score))
        distinct = d.get("numDistinctUsers", 0)
        if distinct >= SC["abuse_distinct_min"]:
            r["score"] += SC["abuse_distinct_bonus"]
            r["ioc"].append("Reported by {} distinct users (+{} pts)".format(
                distinct, SC["abuse_distinct_bonus"]))
        if is_tor:
            r["score"] += SC["abuse_tor_bonus"]
            r["ioc"].append("Tor Exit Node confirmed")
        if conf >= 80:
            r["ioc"].append("CRITICAL: Abuse confidence {}%".format(conf))
        elif conf >= 50:
            r["ioc"].append("Moderate abuse confidence {}%".format(conf))
        if d.get("lastReportedAt"):
            r["ioc"].append("Last reported: {}".format(d["lastReportedAt"][:10]))
    except Exception as e:
        r["error"] = str(e)
    return r

def q_vt(ip, key):
    r = {"source": "VirusTotal", "score": 0, "ioc": [], "error": None}
    if not key:
        r["error"] = "No API key"
        return r
    try:
        vt_limiter(key).wait()
        resp = SESSION.get(
            "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip),
            headers={"x-apikey": key},
            timeout=15,
        )
        if resp.status_code == 404:
            r["ioc"].append("Not found in VT")
            return r
        if resp.status_code == 401:
            r["error"] = "Invalid API key"
            return r
        if resp.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"
            return r
        d = resp.json()
        attrs = d.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        clean = stats.get("harmless", 0)
        total = sum(stats.values()) or 1
        r["score"] += mal * SC["vt_malicious_per_engine"] + sus * SC["vt_suspicious_per_engine"]
        r["ioc"].append("Engines: {} malicious / {} suspicious / {} clean of {}".format(mal, sus, clean, total))
        r["ioc"].append("ASN: {} ({}) | Country: {}".format(
            attrs.get("asn", "N/A"), attrs.get("as_owner", "N/A"), attrs.get("country", "N/A")))
        r["ioc"].append("VT community reputation: {}".format(attrs.get("reputation", 0)))
        if mal > 0:
            eng = attrs.get("last_analysis_results", {})
            bad = [k for k, v in eng.items() if v.get("category") == "malicious"][:5]
            if bad:
                r["ioc"].append("Flagged by: {}".format(", ".join(bad)))
    except Exception as e:
        r["error"] = str(e)
    return r

def q_otx(ip, key):
    r = {"source": "AlienVault OTX", "score": 0, "ioc": [], "error": None}
    if not key:
        r["error"] = "No API key"
        return r
    base = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}".format(ip)
    hdrs = {"X-OTX-API-KEY": key}
    try:
        resp1 = SESSION.get("{}/general".format(base), headers=hdrs, timeout=15)
        if resp1.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"
            return r
        if resp1.status_code in (401, 403):
            r["error"] = "Invalid API key"
            return r
        gen = resp1.json()
        # OTX "validation" entries mark known-good infra (e.g. Google, CDNs).
        for val in gen.get("validation", []):
            if "whitelist" in (str(val.get("source", "")) + str(val.get("name", ""))).lower():
                r["whitelisted"] = True
                r["ioc"].append("OTX verdict: Whitelisted ({})".format(val.get("message") or val.get("name") or "known-good infra"))
                break
        resp2 = SESSION.get("{}/malware".format(base), headers=hdrs, timeout=15)
        if resp2.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"
            return r
        mal = resp2.json()
        pulse_count = gen.get("pulse_info", {}).get("count", 0)
        r["ioc"].append("Pulse hits: {}  |  Country: {}  |  ASN: {}".format(
            pulse_count, gen.get("country_name", "N/A"), gen.get("asn", "N/A")))
        r["score"] += min(pulse_count * SC["otx_pulse_per_hit"], SC["otx_max"])
        pulses = gen.get("pulse_info", {}).get("pulses", [])
        tags = set()
        for p in pulses[:10]:
            tags.update(p.get("tags", []))
        if tags:
            r["ioc"].append("Threat tags: {}".format(", ".join(list(tags)[:6])))
        mal_count = mal.get("count", 0)
        if mal_count > 0:
            r["score"] += SC["otx_malware_bonus"]
            r["ioc"].append("{} malware samples linked to IP".format(mal_count))
        if pulse_count == 0 and mal_count == 0:
            r["ioc"].append("No threat pulses found")
        elif pulse_count > 5:
            r["ioc"].append("HIGH: {} threat intelligence pulses".format(pulse_count))
        elif pulse_count > 0:
            r["ioc"].append("{} threat intelligence pulses".format(pulse_count))
        # OTX's own whitelist verdict overrides its pulse scoring: pulses on
        # whitelisted shared infra are co-occurrence, not attribution.
        if r.get("whitelisted") and r["score"] > 0:
            r["ioc"].append("Pulse score zeroed ({} pts removed) — OTX validation marks this IP as whitelisted infrastructure".format(round(r["score"], 2)))
            r["score"] = 0
    except Exception as e:
        r["error"] = str(e)
    return r

def q_ha(ip, key):
    r = {"source": "Hybrid Analysis", "score": 0, "ioc": [], "error": None}
    if not key:
        r["error"] = "No API key"
        return r
    try:
        resp = SESSION.get(
            "https://www.hybrid-analysis.com/api/v2/search/terms",
            headers={"api-key": key, "User-Agent": "Falcon Sandbox", "accept": "application/json"},
            params={"host": ip},
            timeout=20,
        )
        if resp.status_code == 401:
            r["error"] = "Invalid API key"
            return r
        if resp.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"
            return r
        if not resp.ok:
            r["ioc"].append("No records found in Hybrid Analysis")
            return r
        data    = resp.json()
        results = data.get("result", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        if not results:
            r["ioc"].append("No sandbox reports for this IP")
            return r
        verdicts = [x.get("verdict", "") for x in results if x.get("verdict")]
        scores   = [x.get("threat_score", 0) for x in results if x.get("threat_score")]
        families = set(x.get("vx_family") or x.get("threat_name", "") for x in results
                       if x.get("vx_family") or x.get("threat_name"))
        families.discard("")
        mal_c  = verdicts.count("malicious")
        sus_c  = verdicts.count("suspicious")
        avg_ts = int(sum(scores) / len(scores)) if scores else 0
        r["ioc"].append("Submissions: {}  |  Malicious: {}  |  Suspicious: {}".format(len(results), mal_c, sus_c))
        r["ioc"].append("Avg threat score: {}/100".format(avg_ts))
        if mal_c > 0:
            r["score"] += SC["ha_malicious_flat"]
            r["ioc"].append("{} submissions classified MALICIOUS".format(mal_c))
        elif sus_c > 0:
            r["score"] += SC["ha_suspicious_flat"]
            r["ioc"].append("{} submissions classified SUSPICIOUS".format(sus_c))
        r["score"] += avg_ts * SC["ha_threat_weight"]
        if families:
            r["ioc"].append("Malware families: {}".format(", ".join(list(families)[:5])))
    except Exception as e:
        r["error"] = str(e)
    return r

# Separate session for GreyNoise — no retry on 429 so we can read the response body
GN_SESSION = req_lib.Session()
GN_SESSION.mount("https://", HTTPAdapter(
    max_retries=Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    # 429 intentionally excluded — we want to read the body, not retry blindly
))

def q_greynoise(ip, key):
    r = {"source": "GreyNoise", "score": 0, "ioc": [], "error": None}
    if not key:
        r["error"] = "No API key configured"
        return r
    try:
        resp = GN_SESSION.get(
            "https://api.greynoise.io/v3/community/{}".format(ip),
            headers={"Accept": "application/json", "key": key},
            timeout=15,
        )
        if resp.status_code == 200:
            d = resp.json()
            noise          = d.get("noise", False)
            riot           = d.get("riot", False)
            gn_name        = d.get("name", "")
            last_seen      = d.get("last_seen", "")
            classification = d.get("classification", "")
            r["ioc"].append("Classification: {}".format(classification.upper() if classification else "UNKNOWN"))
            r["ioc"].append("Noise (scanner): {}  |  RIOT (trusted infra): {}".format(noise, riot))
            if gn_name and gn_name.lower() != "unknown":
                r["ioc"].append("Known as: {}".format(gn_name))
            if last_seen:
                r["ioc"].append("Last seen: {}".format(last_seen))
            if classification == "malicious":
                r["score"] += SC["gn_malicious_flat"]
                r["ioc"].append("GreyNoise verdict: MALICIOUS")
            elif classification == "benign":
                r["score"] -= 5
                r["ioc"].append("GreyNoise verdict: Benign — known trusted scanner")
            elif noise and not riot:
                r["score"] += SC["gn_suspicious_flat"]
                r["ioc"].append("GreyNoise verdict: Active internet scanner (unclassified noise)")
            elif riot:
                r["score"] -= 5
                r["ioc"].append("GreyNoise verdict: RIOT — known trusted infrastructure")
            else:
                r["ioc"].append("GreyNoise verdict: Not observed in mass scan traffic")
        elif resp.status_code == 404:
            r["ioc"].append("IP not observed in internet scan traffic")
        elif resp.status_code == 401:
            r["error"] = "Invalid API key"
        elif resp.status_code == 429:
            # Parse rate limit info from response body
            try:
                body = resp.json()
                plan      = body.get("plan", "Community")
                rate_limit = body.get("rate_limit", "")
                plan_url  = body.get("plan_url", "https://greynoise.io/pricing")
                limit_str = " ({} requests)".format(rate_limit) if rate_limit else ""
                r["error"] = "Rate limit reached{} — {} plan. Upgrade at {}".format(
                    limit_str, plan, plan_url)
            except Exception:
                r["error"] = "Rate limit reached — upgrade at https://greynoise.io/pricing"
        else:
            r["error"] = "Unexpected response: HTTP {}".format(resp.status_code)
    except Exception as e:
        err_str = str(e)
        if "429" in err_str or "rate" in err_str.lower():
            r["error"] = "Rate limit reached — upgrade at https://greynoise.io/pricing"
        elif "timeout" in err_str.lower():
            r["error"] = "Request timed out"
        else:
            r["error"] = "Connection error — check network or API key"
    return r

# ── Source 6: ip-api (FREE, no key, 45 req/min) ──────────────────
def q_ipapi(ip):
    r = {"source": "ip-api", "score": 0, "ioc": [], "error": None}
    try:
        IPAPI_LIMITER.wait()
        resp = SESSION.get(
            "http://ip-api.com/json/{}".format(ip),
            params={"fields": "status,message,country,countryCode,isp,org,as,proxy,hosting,query"},
            timeout=10,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                r["ioc"].append("Country: {}  |  ISP: {}".format(d.get("country", "N/A"), d.get("isp", "N/A")))
                r["ioc"].append("Org: {}  |  ASN: {}".format(d.get("org", "N/A"), d.get("as", "N/A")))
                if d.get("proxy"):
                    r["score"] += SC["ipapi_proxy_score"]
                    r["ioc"].append("Detected as: PROXY / VPN / Tor")
                if d.get("hosting"):
                    r["score"] += SC["ipapi_hosting_score"]
                    r["ioc"].append("Detected as: Hosting / Datacenter IP")
                if not d.get("proxy") and not d.get("hosting"):
                    r["ioc"].append("Not flagged as proxy or hosting")
            else:
                r["ioc"].append("Query failed: {}".format(d.get("message", "unknown")))
        elif resp.status_code == 429:
            r["error"] = "Rate limit reached (45 req/min)"
        else:
            r["error"] = "HTTP {}".format(resp.status_code)
    except Exception as e:
        r["error"] = str(e)
    return r

# ── Source 7: ThreatFox / abuse.ch (FREE, optional key) ──────────
def q_threatfox(ip, tf_key=""):
    r = {"source": "ThreatFox", "score": 0, "ioc": [], "error": None}
    try:
        hdrs = {"Accept": "application/json"}
        if tf_key:
            hdrs["Auth-Key"] = tf_key
        resp = SESSION.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip},
            headers=hdrs,
            timeout=15,
        )
        if resp.status_code == 200:
            d = resp.json()
            status = d.get("query_status", "")
            if status == "ok" and d.get("data"):
                iocs = d["data"]
                r["score"] += min(len(iocs) * SC["threatfox_ioc_per_hit"], SC["threatfox_max"])
                malware_types = list(set(
                    x.get("malware_printable", x.get("malware", "Unknown"))
                    for x in iocs if x.get("malware_printable") or x.get("malware")
                ))[:4]
                threat_types = list(set(x.get("threat_type", "") for x in iocs if x.get("threat_type")))[:3]
                r["ioc"].append("{} IOC hit(s) found".format(len(iocs)))
                if malware_types:
                    r["ioc"].append("Malware: {}".format(", ".join(malware_types)))
                if threat_types:
                    r["ioc"].append("Threat type: {}".format(", ".join(threat_types)))
                first = iocs[0]
                r["ioc"].append("Confidence: {}%  |  Last seen: {}".format(
                    first.get("confidence_level", "N/A"), first.get("last_seen", "N/A")))
            elif status == "no_result":
                r["ioc"].append("No IOC records found")
            else:
                r["ioc"].append("Status: {}".format(status))
        else:
            r["error"] = "HTTP {}".format(resp.status_code)
    except Exception as e:
        r["error"] = str(e)
    return r

# ══════════════════════════════════════════════════════════════════
# HASH INVESTIGATION
# ══════════════════════════════════════════════════════════════════

def detect_hash_type(h):
    h = h.strip().lower()
    if re.fullmatch(r'[0-9a-f]{32}',  h): return "MD5"
    if re.fullmatch(r'[0-9a-f]{40}',  h): return "SHA1"
    if re.fullmatch(r'[0-9a-f]{64}',  h): return "SHA256"
    return None

# ── Hash Source 1: VirusTotal ─────────────────────────────────────
def q_vt_hash(h, key):
    r = {"source": "VirusTotal", "score": 0, "ioc": [], "error": None,
         "url": "https://www.virustotal.com/gui/file/{}".format(h)}
    if not key:
        r["error"] = "No API key"
        return r
    try:
        vt_limiter(key).wait()
        resp = SESSION.get(
            "https://www.virustotal.com/api/v3/files/{}".format(h),
            headers={"x-apikey": key},
            timeout=20,
        )
        if resp.status_code == 404:
            r["ioc"].append("Not found in VirusTotal")
            return r
        if resp.status_code == 401:
            r["error"] = "Invalid API key"; return r
        if resp.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"; return r
        d     = resp.json()
        attrs = d.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious",  0)
        sus   = stats.get("suspicious", 0)
        clean = stats.get("harmless",   0)
        total = sum(stats.values()) or 1
        r["score"] += mal * SC["vt_malicious_per_engine"] + sus * SC["vt_suspicious_per_engine"]
        r["ioc"].append("Detections: {}/{} engines  ({} suspicious)".format(mal, total, sus))
        # File metadata
        name  = (attrs.get("meaningful_name") or attrs.get("name") or "Unknown")
        ftype = attrs.get("type_description", attrs.get("magic", "Unknown"))
        fsize = attrs.get("size", 0)
        r["ioc"].append("File: {}  |  Type: {}  |  Size: {} bytes".format(name, ftype, fsize))
        tags  = attrs.get("tags", [])
        if tags: r["ioc"].append("Tags: {}".format(", ".join(tags[:6])))
        rep   = attrs.get("reputation", 0)
        r["ioc"].append("Community reputation: {}".format(rep))
        if mal > 0:
            engines = attrs.get("last_analysis_results", {})
            flagged = [k for k, v in engines.items() if v.get("category") == "malicious"][:6]
            if flagged: r["ioc"].append("Flagged by: {}".format(", ".join(flagged)))
        first_seen = attrs.get("first_submission_date")
        last_seen  = attrs.get("last_analysis_date")
        if first_seen: r["ioc"].append("First seen: {}".format(datetime.fromtimestamp(first_seen, tz=timezone.utc).strftime("%Y-%m-%d")))
        if last_seen:  r["ioc"].append("Last scan:  {}".format(datetime.fromtimestamp(last_seen,  tz=timezone.utc).strftime("%Y-%m-%d")))
        # Store file info for display
        r["file_info"] = {"name": name, "type": ftype, "size": fsize, "detections": mal, "total_engines": total}
    except Exception as e:
        r["error"] = str(e)
    return r

# ── Hash Source 2: MalwareBazaar (abuse.ch) — FREE, no key ───────
def q_malwarebazaar(h):
    r = {"source": "MalwareBazaar", "score": 0, "ioc": [], "error": None,
         "url": "https://bazaar.abuse.ch/browse.php?search={}".format(h)}
    try:
        resp = SESSION.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": h},
            timeout=15,
        )
        if resp.status_code != 200:
            r["error"] = "HTTP {}".format(resp.status_code); return r
        d      = resp.json()
        status = d.get("query_status", "")
        if status == "hash_not_found":
            r["ioc"].append("Not found in MalwareBazaar"); return r
        if status != "ok":
            r["ioc"].append("Status: {}".format(status)); return r
        info = d.get("data", [{}])[0]
        r["score"] += 30  # presence in MalwareBazaar = known malware
        r["ioc"].append("KNOWN MALWARE — confirmed in MalwareBazaar database")
        fname  = info.get("file_name", "Unknown")
        ftype  = info.get("file_type", "Unknown")
        fsize  = info.get("file_size", 0)
        sig    = info.get("signature", info.get("tags", ""))
        origin = info.get("origin_country", "")
        r["ioc"].append("File: {}  |  Type: {}  |  Size: {} bytes".format(fname, ftype, fsize))
        if sig:    r["ioc"].append("Signature/Tags: {}".format(sig if isinstance(sig, str) else ", ".join(sig)))
        if origin: r["ioc"].append("Origin country: {}".format(origin))
        first_seen = info.get("first_seen", "")
        last_seen  = info.get("last_seen",  "")
        if first_seen: r["ioc"].append("First seen: {}".format(first_seen[:10]))
        if last_seen:  r["ioc"].append("Last seen:  {}".format(last_seen[:10]))
        reporter = info.get("reporter", "")
        if reporter: r["ioc"].append("Reported by: {}".format(reporter))
        r["file_info"] = {"name": fname, "type": ftype, "size": fsize, "detections": "N/A", "total_engines": "N/A"}
    except Exception as e:
        r["error"] = str(e)
    return r

# ── Hash Source 3: AlienVault OTX ─────────────────────────────────
def q_otx_hash(h, key):
    r = {"source": "AlienVault OTX", "score": 0, "ioc": [], "error": None,
         "url": "https://otx.alienvault.com/indicator/file/{}".format(h)}
    if not key:
        r["error"] = "No API key"; return r
    # Detect indicator type for OTX URL
    ht = detect_hash_type(h)
    itype = {"MD5": "file", "SHA1": "file", "SHA256": "file"}.get(ht, "file")
    base  = "https://otx.alienvault.com/api/v1/indicators/{}/{}".format(itype, h)
    hdrs  = {"X-OTX-API-KEY": key}
    try:
        resp1 = SESSION.get("{}/general".format(base), headers=hdrs, timeout=15)
        if resp1.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"; return r
        if resp1.status_code in (401, 403):
            r["error"] = "Invalid API key"; return r
        gen = resp1.json()
        resp2 = SESSION.get("{}/analysis".format(base), headers=hdrs, timeout=15)
        if resp2.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"; return r
        ana = resp2.json()
        pulse_count = gen.get("pulse_info", {}).get("count", 0)
        r["ioc"].append("Pulse hits: {}".format(pulse_count))
        r["score"] += min(pulse_count * SC["otx_pulse_per_hit"], SC["otx_max"])
        pulses = gen.get("pulse_info", {}).get("pulses", [])
        tags   = set()
        for p in pulses[:8]:
            tags.update(p.get("tags", []))
        if tags: r["ioc"].append("Threat tags: {}".format(", ".join(list(tags)[:6])))
        if pulse_count > 3: r["ioc"].append("HIGH: {} threat intelligence pulses".format(pulse_count))
        elif pulse_count == 0: r["ioc"].append("No threat pulses found")
        # Analysis section
        mal_result = ana.get("analysis", {}).get("plugins", {})
        if mal_result:
            r["ioc"].append("OTX file analysis available")
    except Exception as e:
        r["error"] = str(e)
    return r

# ── Hash Source 4: Hybrid Analysis ────────────────────────────────
def q_ha_hash(h, key):
    r = {"source": "Hybrid Analysis", "score": 0, "ioc": [], "error": None,
         "url": "https://www.hybrid-analysis.com/sample/{}".format(h)}
    if not key:
        r["error"] = "No API key"; return r
    try:
        resp = SESSION.get(
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            headers={"api-key": key, "User-Agent": "Falcon Sandbox", "accept": "application/json"},
            params={"hash": h},
            timeout=20,
        )
        if resp.status_code == 401:
            r["error"] = "Invalid API key"; return r
        if resp.status_code == 429:
            r["error"] = "Rate limit exceeded (429)"; return r
        if not resp.ok:
            r["ioc"].append("No records found"); return r
        results  = resp.json()
        if not isinstance(results, list): results = results.get("result", [])
        if not results:
            r["ioc"].append("No sandbox reports found"); return r
        verdicts  = [x.get("verdict", "") for x in results if x.get("verdict")]
        scores    = [x.get("threat_score", 0) for x in results if x.get("threat_score")]
        families  = set(x.get("vx_family") or x.get("threat_name", "") for x in results
                        if x.get("vx_family") or x.get("threat_name"))
        families.discard("")
        mal_c  = verdicts.count("malicious")
        sus_c  = verdicts.count("suspicious")
        avg_ts = int(sum(scores) / len(scores)) if scores else 0
        r["ioc"].append("Reports: {}  |  Malicious: {}  |  Suspicious: {}".format(len(results), mal_c, sus_c))
        r["ioc"].append("Avg threat score: {}/100".format(avg_ts))
        if mal_c > 0:
            r["score"] += SC["ha_malicious_flat"]
            r["ioc"].append("{} reports classified MALICIOUS".format(mal_c))
        elif sus_c > 0:
            r["score"] += SC["ha_suspicious_flat"]
        r["score"] += avg_ts * SC["ha_threat_weight"]
        if families: r["ioc"].append("Malware families: {}".format(", ".join(list(families)[:5])))
        # File info from first result
        first = results[0]
        fname = first.get("submit_name") or first.get("target_url", "Unknown")
        ftype = first.get("type_short") or first.get("file_type", "Unknown")
        fsize = first.get("size", 0)
        if fname: r["ioc"].append("File: {}  |  Type: {}".format(fname, ftype))
        r["file_info"] = {"name": fname, "type": ftype, "size": fsize, "detections": mal_c, "total_engines": len(results)}
    except Exception as e:
        r["error"] = str(e)
    return r

# ── Hash scoring weights ──────────────────────────────────────────
HASH_SOURCE_URLS = {
    "VirusTotal":      "https://www.virustotal.com/gui/file/{hash}",
    "MalwareBazaar":   "https://bazaar.abuse.ch/browse.php?search={hash}",
    "AlienVault OTX":  "https://otx.alienvault.com/indicator/file/{hash}",
    "Hybrid Analysis": "https://www.hybrid-analysis.com/sample/{hash}",
}

ALL_HASH_SOURCES = ["virustotal", "malwarebazaar", "otx", "hybrid"]

def calc_hash_verdict(results):
    total = min(sum(max(r.get("score", 0), 0) for r in results), 100)
    if total >= 50: v = "MALICIOUS"
    elif total >= 25: v = "SUSPICIOUS"
    elif total > 0: v = "SUSPICIOUS"
    else: v = "CLEAN"
    return round(total, 1), v

def investigate_hash(h, cfg, active_sources=None):
    if active_sources is None:
        active_sources = ALL_HASH_SOURCES
    h = h.strip().lower()
    ht = detect_hash_type(h)
    tasks = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        if "virustotal" in active_sources and get_key_pool(cfg, "VIRUSTOTAL_KEY"):
            tasks["vt"] = ex.submit(query_with_key_failover, "VIRUSTOTAL_KEY", cfg, lambda k: q_vt_hash(h, k))
        if "malwarebazaar" in active_sources:
            tasks["mb"] = ex.submit(q_malwarebazaar, h)
        if "otx" in active_sources and get_key_pool(cfg, "OTX_KEY"):
            tasks["otx"] = ex.submit(query_with_key_failover, "OTX_KEY", cfg, lambda k: q_otx_hash(h, k))
        if "hybrid" in active_sources and get_key_pool(cfg, "HA_KEY"):
            tasks["ha"] = ex.submit(query_with_key_failover, "HA_KEY", cfg, lambda k: q_ha_hash(h, k))
        results = []
        for k, fut in tasks.items():
            try:
                res = fut.result()
                results.append(res if res is not None else {"source": _TASK_NAMES.get(k, k), "score": 0, "ioc": [], "error": "No API key"})
            except Exception as e:
                results.append({"source": _TASK_NAMES.get(k, k), "score": 0, "ioc": [], "error": str(e)})
    score, v = calc_hash_verdict(results)
    # Aggregate file info from sources
    file_info = {}
    for r in results:
        fi = r.pop("file_info", {})
        if fi and not file_info:
            file_info = fi
    return {
        "hash": h,
        "hash_type": ht or "UNKNOWN",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "score": score,
        "verdict": v,
        "file_info": file_info,
        "sources": [{"source": r["source"], "score": round(r.get("score", 0), 2),
                     "ioc": r.get("ioc", []), "error": r.get("error"),
                     "url": HASH_SOURCE_URLS.get(r["source"], "").format(hash=h)} for r in results],
    }

def calc_verdict(results):
    # Raw sum (not per-source clamp) so negative trust signals — AbuseIPDB
    # whitelist (-10), GreyNoise benign (-5) — actually offset positive
    # scores from noisier sources. Total still floored at 0, capped at 100.
    total = max(min(sum(r.get("score", 0) for r in results), 100), 0)
    total = round(total, 2)  # 2 decimals so total reconciles with displayed per-source pts
    if total >= 70:
        v = "MALICIOUS"
    elif total >= 45:
        v = "HIGH RISK"
    elif total >= 20:
        v = "SUSPICIOUS"
    else:
        v = "CLEAN"
    return total, v

# ══════════════════════════════════════════════════════════════════
# TRAFFIC BEHAVIOR INVESTIGATION
# Profiles an IP's observed behavior in the last analyzed traffic
# capture (NetFlow CSV) and scores it as an additional intel source
# layered on top of the threat-intelligence verdict.
# ══════════════════════════════════════════════════════════════════
_TRAFFIC_CACHE      = {"flows": [], "ts": None, "files": []}
_TRAFFIC_CACHE_LOCK = threading.Lock()

def cache_traffic_flows(flows, files=None):
    with _TRAFFIC_CACHE_LOCK:
        _TRAFFIC_CACHE["flows"] = flows
        _TRAFFIC_CACHE["ts"]    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if files is not None:
            _TRAFFIC_CACHE["files"] = files

def q_behavior(ip):
    """Informational traffic profile from the last analyzed capture:
    the IP's share of total capture traffic and the bandwidth it
    generated. Contributes NO points to the verdict — flow metadata
    alone cannot establish maliciousness."""
    r = {"source": "Traffic Behavior", "score": 0, "ioc": [], "error": None}
    with _TRAFFIC_CACHE_LOCK:
        flows  = _TRAFFIC_CACHE["flows"]
        cap_ts = _TRAFFIC_CACHE["ts"]
    if not flows:
        r["error"] = "No traffic capture loaded — run Traffic Analysis first"
        return r
    mine = [f for f in flows if f["src_ip"] == ip]
    if not mine:
        r["ioc"].append("IP not seen as a source in loaded capture ({} flows analyzed, {})".format(len(flows), cap_ts))
        return r

    total_bytes = sum(f["bytes"] for f in flows) or 1
    my_bytes    = sum(f["bytes"]   for f in mine)
    my_pkts     = sum(f["packets"] for f in mine)
    share       = my_bytes / total_bytes

    ts_all     = [f["timestamp"] for f in mine if f["timestamp"] > 0]
    duration_s = max((max(ts_all) - min(ts_all)) if len(ts_all) > 1 else 0, 1)
    avg_mbps   = (my_bytes * 8 / duration_s) / 1_000_000

    r["ioc"].append("Traffic share: {:.2f}% of total capture bytes".format(share * 100))
    r["ioc"].append("Bandwidth: {} total | avg {:.2f} Mbps over {}s window".format(
        fmt_bytes(my_bytes), avg_mbps, duration_s))
    r["ioc"].append("{} flows | {} pkts".format(len(mine), fmt_pkts(my_pkts)))
    return r

SOURCE_URLS = {
    "AbuseIPDB":       "https://www.abuseipdb.com/check/{ip}",
    "VirusTotal":      "https://www.virustotal.com/gui/ip-address/{ip}",
    "AlienVault OTX":  "https://otx.alienvault.com/indicator/ip/{ip}",
    "Hybrid Analysis": "https://www.hybrid-analysis.com/search?query={ip}&dataType=ip",
    "GreyNoise":       "https://viz.greynoise.io/ip/{ip}",
    "ThreatFox":       "https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}",
    "ip-api":          "https://ip-api.com/#{ip}",
}

ALL_SOURCES = ["abuseipdb", "virustotal", "otx", "hybrid", "greynoise", "ipapi", "threatfox", "behavior"]

# Task-key -> display name, used when a worker raises before returning a
# result dict so the fallback entry still carries a proper name + URL.
_TASK_NAMES = {
    "abuse": "AbuseIPDB", "vt": "VirusTotal", "otx": "AlienVault OTX",
    "ha": "Hybrid Analysis", "gn": "GreyNoise", "ipapi": "ip-api",
    "threatfox": "ThreatFox", "behavior": "Traffic Behavior", "mb": "MalwareBazaar",
}

def investigate(ip, cfg, active_sources=None):
    """active_sources: list of source ids to query. None = all configured sources."""
    if active_sources is None:
        active_sources = ALL_SOURCES

    tasks = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        # Behavior layer: only runs when a traffic capture is loaded, so
        # plain TI investigations don't get a noisy "no capture" card.
        if "behavior" in active_sources and _TRAFFIC_CACHE["flows"]:
            tasks["behavior"] = ex.submit(q_behavior, ip)
        if "abuseipdb" in active_sources and get_key_pool(cfg, "ABUSEIPDB_KEY"):
            tasks["abuse"] = ex.submit(query_with_key_failover, "ABUSEIPDB_KEY", cfg, lambda k: q_abuse(ip, k))
        if "virustotal" in active_sources and get_key_pool(cfg, "VIRUSTOTAL_KEY"):
            tasks["vt"] = ex.submit(query_with_key_failover, "VIRUSTOTAL_KEY", cfg, lambda k: q_vt(ip, k))
        if "otx" in active_sources and get_key_pool(cfg, "OTX_KEY"):
            tasks["otx"] = ex.submit(query_with_key_failover, "OTX_KEY", cfg, lambda k: q_otx(ip, k))
        if "hybrid" in active_sources and get_key_pool(cfg, "HA_KEY"):
            tasks["ha"] = ex.submit(query_with_key_failover, "HA_KEY", cfg, lambda k: q_ha(ip, k))
        if "greynoise" in active_sources and get_key_pool(cfg, "GREYNOISE_KEY"):
            tasks["gn"] = ex.submit(query_with_key_failover, "GREYNOISE_KEY", cfg, lambda k: q_greynoise(ip, k))
        if "ipapi" in active_sources:
            tasks["ipapi"] = ex.submit(q_ipapi, ip)
        if "threatfox" in active_sources:
            tf_pool = get_key_pool(cfg, "THREATFOX_KEY")
            if tf_pool:
                tasks["threatfox"] = ex.submit(query_with_key_failover, "THREATFOX_KEY", cfg, lambda k: q_threatfox(ip, k))
            else:
                tasks["threatfox"] = ex.submit(q_threatfox, ip, "")
        results = []
        for k, fut in tasks.items():
            try:
                res = fut.result()
                results.append(res if res is not None else {"source": _TASK_NAMES.get(k, k), "score": 0, "ioc": [], "error": "No API key"})
            except Exception as e:
                results.append({"source": _TASK_NAMES.get(k, k), "score": 0, "ioc": [], "error": str(e)})

    # ── Whitelist dampening (cross-source) ─────────────────────────
    # If any source marks the IP as whitelisted shared infrastructure,
    # dampen the OTX pulse contribution: pulses list IPs that malware
    # *contacted*, which for Google/CDN infra is co-occurrence, not
    # attribution (MITRE ATT&CK T1102 abuse of legitimate web services).
    wl_by = [r["source"] for r in results if r.get("whitelisted")]
    if wl_by:
        for r in results:
            if r["source"] == "AlienVault OTX" and r.get("score", 0) > 0:
                orig = r["score"]
                r["score"] = round(orig * SC["wl_otx_dampen"], 2)
                r["ioc"].append("Score dampened {:.1f} → {:.1f} pts: IP whitelisted by {} (pulse hits on shared infra are co-occurrence)".format(
                    orig, r["score"], ", ".join(wl_by)))

    score, v = calc_verdict(results)
    return {
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "score": score,
        "verdict": v,
        "sources": [{"source": r["source"], "score": round(r.get("score", 0), 2),
                     "ioc": r.get("ioc", []), "error": r.get("error"),
                     "url": SOURCE_URLS.get(r["source"], "").format(ip=ip)} for r in results],
    }

# ── Flask App ─────────────────────────────────────────────────────
app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
# The UI is served from this same origin, so cross-origin access is not
# needed. A wildcard CORS policy would let any web page the analyst visits
# call /api/config/reveal and exfiltrate the stored API keys. Opt-in only:
#   NXG_CORS_ORIGINS="https://soc.example.com,https://other.example.com"
_cors_origins = [o.strip() for o in os.environ.get("NXG_CORS_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    CORS(app, origins=_cors_origins)

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

CONFIG_FIELDS = ["ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "OTX_KEY", "HA_KEY", "GREYNOISE_KEY", "THREATFOX_KEY"]

def _mask_key(v):
    if not v:
        return ""
    # Short, fixed-width preview (e.g. "65bd...b411") instead of a full-length
    # run of asterisks -- long keys were overflowing/overlapping the Settings UI.
    return v[:4] + "..." + v[-4:] if len(v) > 8 else "*" * len(v)

@app.route("/api/config", methods=["GET"])
def get_config():
    cfg = load_config()
    # Mask primary keys for display
    masked = {}
    for k in CONFIG_FIELDS:
        v = cfg.get(k)
        if isinstance(v, str):
            masked[k] = _mask_key(v)
    # Mask backup keys for display, keyed by the base field name
    backup_keys = {}
    for k in CONFIG_FIELDS:
        backups = cfg.get(k + BACKUP_SUFFIX)
        if isinstance(backups, list) and backups:
            backup_keys[k] = [_mask_key(b) for b in backups]
    keys_configured = [k for k in CONFIG_FIELDS if get_key_pool(cfg, k)]
    return jsonify({
        "config": masked,
        "backup_keys": backup_keys,
        "key_counts": {k: len(get_key_pool(cfg, k)) for k in CONFIG_FIELDS},
        "keys_configured": keys_configured,
    })

@app.route("/api/config/reveal", methods=["GET"])
def reveal_config_key():
    """Return the real (unmasked) value of a stored key so the Settings UI's
    eye/show button can display it. This app is single-user and local-only —
    the same plaintext value already lives in config.json on disk — so this
    does not expose anything beyond what's already readable on this machine."""
    field = request.args.get("field", "")
    index_raw = request.args.get("index")
    if field not in CONFIG_FIELDS:
        return jsonify({"error": "Unknown field: {}".format(field)}), 400
    cfg = load_config()
    if index_raw is None:
        value = cfg.get(field)
        if not value:
            return jsonify({"error": "No primary key set for this source"}), 404
        return jsonify({"key": value})
    try:
        index = int(index_raw)
    except ValueError:
        return jsonify({"error": "index must be an integer"}), 400
    backups = cfg.get(field + BACKUP_SUFFIX)
    if not isinstance(backups, list) or index < 0 or index >= len(backups):
        return jsonify({"error": "Backup key not found"}), 404
    return jsonify({"key": backups[index]})

@app.route("/api/config", methods=["POST"])
def update_config():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    cfg = load_config()
    for k in CONFIG_FIELDS:
        if k in data and data[k]:
            cfg[k] = data[k].strip()
        elif k in data and data[k] == "":
            cfg.pop(k, None)
    save_config(cfg)
    return jsonify({"success": True, "message": "Configuration saved"})

@app.route("/api/config/backup-key", methods=["POST"])
def add_backup_key():
    """Add an additional (backup) API key for a source. When the primary key
    for that source gets rate-limited, the app automatically rolls over to
    backup keys in the order they were added."""
    data = request.get_json() or {}
    field = data.get("field", "")
    key = (data.get("key") or "").strip()
    if field not in CONFIG_FIELDS:
        return jsonify({"error": "Unknown field: {}".format(field)}), 400
    if not key:
        return jsonify({"error": "No key provided"}), 400
    cfg = load_config()
    existing_pool = get_key_pool(cfg, field)
    if key in existing_pool:
        return jsonify({"error": "That key is already configured for this source"}), 400
    backups = cfg.get(field + BACKUP_SUFFIX)
    if not isinstance(backups, list):
        backups = []
    if not cfg.get(field):
        # No primary key set yet — this becomes the primary instead of a backup
        cfg[field] = key
    else:
        backups.append(key)
        cfg[field + BACKUP_SUFFIX] = backups
    save_config(cfg)
    return jsonify({"success": True, "key_count": len(get_key_pool(cfg, field))})

@app.route("/api/config/backup-key", methods=["DELETE"])
def remove_backup_key():
    """Remove a backup key (by index, 0-based, within that source's backup list)."""
    data = request.get_json() or {}
    field = data.get("field", "")
    index = data.get("index")
    if field not in CONFIG_FIELDS:
        return jsonify({"error": "Unknown field: {}".format(field)}), 400
    if not isinstance(index, int):
        return jsonify({"error": "index must be an integer"}), 400
    cfg = load_config()
    backups = cfg.get(field + BACKUP_SUFFIX)
    if not isinstance(backups, list) or index < 0 or index >= len(backups):
        return jsonify({"error": "Backup key not found"}), 404
    removed_key = backups.pop(index)
    cfg[field + BACKUP_SUFFIX] = backups
    # Clear any cooldown state tied to the removed key so it doesn't linger
    with _KEY_STATE_LOCK:
        _KEY_COOLDOWN.pop((field, removed_key), None)
        if _KEY_LAST_GOOD.get(field) == removed_key:
            _KEY_LAST_GOOD.pop(field, None)
    save_config(cfg)
    return jsonify({"success": True, "key_count": len(get_key_pool(cfg, field))})

@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    raw_ips = data.get("ips", [])
    if isinstance(raw_ips, str):
        raw_ips = [x.strip() for x in raw_ips.replace(",", "\n").splitlines() if x.strip()]

    valid_ips, invalid, expansion_notes = expand_targets(raw_ips)

    if not valid_ips:
        return jsonify({"error": "No valid IP addresses provided", "invalid": invalid}), 400

    cfg = load_config()
    active_sources = data.get("active_sources", None)  # None = use all configured
    workers = min(max(int(data.get("parallel", BATCH_WORKERS_DEFAULT)), 1),
                  BATCH_WORKERS_MAX, len(valid_ips))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda ip: investigate(ip, cfg, active_sources), valid_ips))

    summary = {
        "total": len(results),
        "malicious": sum(1 for r in results if r["verdict"] == "MALICIOUS"),
        "high_risk": sum(1 for r in results if r["verdict"] == "HIGH RISK"),
        "suspicious": sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
        "clean": sum(1 for r in results if r["verdict"] == "CLEAN"),
    }

    return jsonify({
        "results": results,
        "summary": summary,
        "invalid_ips": invalid,
        "expansion_notes": expansion_notes,
    })

@app.route("/api/investigate/stream", methods=["POST"])
def api_investigate_stream():
    """SSE endpoint — streams one result per IP as it completes."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    raw_ips = data.get("ips", [])
    if isinstance(raw_ips, str):
        raw_ips = [x.strip() for x in raw_ips.replace(",", "\n").splitlines() if x.strip()]

    valid_ips, invalid, expansion_notes = expand_targets(raw_ips)

    if not valid_ips:
        return jsonify({"error": "No valid IP addresses provided"}), 400

    cfg            = load_config()
    active_sources = data.get("active_sources", None)
    total          = len(valid_ips)
    workers        = min(max(int(data.get("parallel", BATCH_WORKERS_DEFAULT)), 1),
                         BATCH_WORKERS_MAX, total)

    def generate():
        # Send initial metadata
        yield "data: {}\n\n".format(json.dumps({
            "type": "start", "total": total, "invalid": invalid, "workers": workers,
            "expansion_notes": expansion_notes
        }))
        results = []
        # Parallel across IPs; results stream in completion order. Per-source
        # rate limiters (VT, ip-api) keep us inside free-tier quotas.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(investigate, ip, cfg, active_sources): ip for ip in valid_ips}
            for idx, fut in enumerate(as_completed(futs), 1):
                try:
                    result = fut.result()
                except Exception as e:
                    result = {"ip": futs[fut], "score": 0, "verdict": "CLEAN",
                              "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                              "sources": [], "error": str(e)}
                results.append(result)
                pct = round(idx / total * 100)
                yield "data: {}\n\n".format(json.dumps({
                    "type": "result",
                    "index": idx,
                    "total": total,
                    "percent": pct,
                    "result": result,
                }))
        summary = {
            "total":     len(results),
            "malicious": sum(1 for r in results if r["verdict"] == "MALICIOUS"),
            "high_risk": sum(1 for r in results if r["verdict"] == "HIGH RISK"),
            "suspicious":sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
            "clean":     sum(1 for r in results if r["verdict"] == "CLEAN"),
        }
        yield "data: {}\n\n".format(json.dumps({
            "type": "done", "summary": summary
        }))

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )

from xml.sax.saxutils import escape as _xml_escape

def _lookup_url(source, indicator, kind="ip"):
    """Public lookup URL for a (source, indicator) pair — fallback for result
    objects produced before the API started embedding per-source URLs."""
    tbl = HASH_SOURCE_URLS if kind == "hash" else SOURCE_URLS
    tpl = tbl.get(source, "")
    if not tpl:
        return ""
    return tpl.format(ip=indicator, hash=indicator)

def pdf_esc(text):
    """Escape text for ReportLab Paragraph mini-markup. Raw '&', '<', '>' in
    API data (e.g. ISP 'AT&T', tags like '<script>') otherwise make
    Paragraph raise a parse error and the whole export fails."""
    return _xml_escape(str(text if text is not None else ""))

def pdf_link(url, label=None):
    """Clickable hyperlink inside a Paragraph (also readable as plain text)."""
    if not url:
        return ""
    return '<a href="{u}" color="#58a6ff"><u>{l}</u></a>'.format(
        u=pdf_esc(url), l=pdf_esc(label or url))

def build_pdf(results, kind="ip"):
    """Threat-intel report. kind="ip" (IP reputation) or kind="hash" (file hash).
    Every source row carries the public lookup URL so the reader can verify
    each finding at the originating threat feed."""
    id_field = "hash" if kind == "hash" else "ip"
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, KeepTogether)
    from reportlab.graphics.shapes import Drawing, Rect

    BG_DARK    = colors.HexColor("#0d1117")
    BG_CARD    = colors.HexColor("#161b22")
    BG_ROW     = colors.HexColor("#21262d")
    COL_BORDER = colors.HexColor("#30363d")
    COL_TEXT   = colors.HexColor("#e6edf3")
    COL_TEXT2  = colors.HexColor("#8b949e")
    COL_CYAN   = colors.HexColor("#58a6ff")
    VCOL = {
        "MALICIOUS":  colors.HexColor("#f85149"),
        "HIGH RISK":  colors.HexColor("#f0883e"),
        "SUSPICIOUS": colors.HexColor("#d29922"),
        "CLEAN":      colors.HexColor("#3fb950"),
    }
    VBGCOL = {
        "MALICIOUS":  colors.HexColor("#2d1517"),
        "HIGH RISK":  colors.HexColor("#2d1b0f"),
        "SUSPICIOUS": colors.HexColor("#2a1d0e"),
        "CLEAN":      colors.HexColor("#0f2518"),
    }
    SRC_COL = {
        "AbuseIPDB":       colors.HexColor("#58a6ff"),
        "VirusTotal":      colors.HexColor("#bc8cff"),
        "AlienVault OTX":  colors.HexColor("#f0883e"),
        "Hybrid Analysis": colors.HexColor("#3fb950"),
        "GreyNoise":       colors.HexColor("#58a6ff"),
        "ip-api":          colors.HexColor("#d29922"),
        "ThreatFox":       colors.HexColor("#f85149"),
        "MalwareBazaar":   colors.HexColor("#f85149"),
    }

    def vc(v):
        return VCOL.get(v, COL_TEXT2)

    def ps(name, **kw):
        base = dict(fontName="Helvetica", fontSize=8, textColor=COL_TEXT, leading=11)
        base.update(kw)
        return ParagraphStyle(name, **base)

    def score_bar_drawing(score, width=120, height=12):
        d = Drawing(width, height)
        d.add(Rect(0, 3, width, 6, fillColor=BG_ROW, strokeColor=None))
        v = max(0, min(score, 100))
        if v > 0:
            c = vc("MALICIOUS" if v >= 70 else "HIGH RISK" if v >= 45 else "SUSPICIOUS" if v >= 20 else "CLEAN")
            d.add(Rect(0, 3, width * v / 100, 6, fillColor=c, strokeColor=None))
        return d

    def score_bar_text(score):
        filled = int(score / 10)
        empty  = 10 - filled
        v = "MALICIOUS" if score >= 70 else "HIGH RISK" if score >= 45 else "SUSPICIOUS" if score >= 20 else "CLEAN"
        bar_color = {"MALICIOUS":"#f85149","HIGH RISK":"#f0883e","SUSPICIOUS":"#d29922","CLEAN":"#3fb950"}[v]
        score_line = '<font color="{}" size="9"><b>{:.1f} / 100</b></font>'.format(bar_color, score)
        bar_line   = '<font color="{}">&#x2588;&#x2588;</font>'.format(bar_color) * filled + '<font color="#555e6a">&#x2591;&#x2591;</font>' * empty
        return score_line + "<br/>" + bar_line

    def verdict_badge(v, col_w=60):
        bg  = VBGCOL.get(v, BG_ROW)
        fc  = vc(v)
        inner = Table([[Paragraph(v, ps("vbdg"+v[:3], fontName="Helvetica-Bold",
                                        fontSize=8, textColor=fc, alignment=TA_CENTER))]],
                      colWidths=[col_w])
        inner.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), bg),
            ("TOPPADDING",    (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LEFTPADDING",   (0,0), (-1,-1), 5),
            ("RIGHTPADDING",  (0,0), (-1,-1), 5),
            ("BOX",           (0,0), (-1,-1), 0.5, fc),
        ]))
        return inner

    buf = BytesIO()
    W   = A4[0] - 36*mm
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm)
    story = []

    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("FILE HASH INVESTIGATOR" if kind == "hash" else "IP REPUTATION INVESTIGATOR",
                            ps("h1", fontName="Helvetica-Bold", fontSize=18,
                               textColor=COL_CYAN, alignment=TA_CENTER, leading=24)))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Threat Intelligence Report",
                            ps("sub", fontSize=10, textColor=COL_TEXT2, alignment=TA_CENTER, leading=14)))
    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width="100%", thickness=1, color=COL_BORDER))
    story.append(Spacer(1, 2*mm))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(
        "Generated: {}   |   Total {}: {}".format(ts, "hashes" if kind == "hash" else "IPs", len(results)),
        ps("meta", fontSize=7, textColor=COL_TEXT2, alignment=TA_CENTER)))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph(
        "Each source row includes the public lookup URL of the threat feed so every finding can be verified at its origin.",
        ps("meta2", fontSize=6.5, textColor=COL_TEXT2, alignment=TA_CENTER)))
    story.append(Spacer(1, 5*mm))

    # Sort: highest risk first, then by score descending
    _order = {"MALICIOUS": 4, "HIGH RISK": 3, "SUSPICIOUS": 2, "CLEAN": 1}
    results = sorted(results,
                     key=lambda r: (_order.get(r.get("verdict", "CLEAN"), 0), r.get("score", 0)),
                     reverse=True)

    dist = {"MALICIOUS": 0, "HIGH RISK": 0, "SUSPICIOUS": 0, "CLEAN": 0}
    if kind == "hash":
        dist.pop("HIGH RISK")
    for r in results:
        dist[r.get("verdict", "CLEAN")] = dist.get(r.get("verdict", "CLEAN"), 0) + 1

    sum_data = [
        [Paragraph(k, ps("sk{}".format(i), fontName="Helvetica-Bold", fontSize=8,
                         textColor=vc(k), alignment=TA_CENTER)) for i, k in enumerate(dist)],
        [Paragraph(str(dist[k]), ps("sv{}".format(i), fontName="Helvetica-Bold", fontSize=22,
                                    textColor=vc(k), alignment=TA_CENTER)) for i, k in enumerate(dist)],
    ]
    st = Table(sum_data, colWidths=[W/len(dist)]*len(dist), rowHeights=[20, 40])
    st.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), BG_CARD),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("GRID",          (0,0), (-1,-1), 0.5, COL_BORDER),
    ]))
    story.append(st)
    story.append(Spacer(1, 5*mm))

    story.append(Paragraph("INVESTIGATION OVERVIEW",
                            ps("ov", fontName="Helvetica-Bold", fontSize=10, textColor=COL_TEXT)))
    story.append(Spacer(1, 2*mm))

    ov = [["File Hash" if kind == "hash" else "IP Address", "Score  /  Bar", "Verdict", "Timestamp"]]
    cw = [W*0.34, W*0.32, W*0.14, W*0.20] if kind == "hash" else [W*0.25, W*0.35, W*0.17, W*0.23]
    for r in results:
        v   = r.get("verdict", "CLEAN")
        rid = str(r.get(id_field, ""))
        score_cell = Paragraph(score_bar_text(r.get("score", 0)),
                               ps("sc_bar{}".format(rid), fontName="Helvetica", fontSize=8,
                                  textColor=vc(v), leading=13))
        id_txt = pdf_esc(rid)
        if kind == "hash":
            id_txt = '<font size="6.5">{}</font><br/><font size="6" color="#8b949e">{}</font>'.format(
                id_txt, pdf_esc(r.get("hash_type", "")))
        ov.append([
            Paragraph(id_txt, ps("ipc{}".format(rid), fontName="Helvetica-Bold", fontSize=8, textColor=COL_CYAN, leading=9)),
            score_cell,
            verdict_badge(v, col_w=int(W*0.13 if kind == "hash" else W*0.15)),
            Paragraph(pdf_esc(r.get("timestamp", "")), ps("tsc{}".format(rid), fontSize=7, textColor=COL_TEXT2)),
        ])
    ov_t = Table(ov, colWidths=cw, repeatRows=1)
    ov_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), BG_CARD),
        ("TEXTCOLOR",     (0,0), (-1,0), COL_TEXT2),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 7.5),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_DARK]),
        ("ALIGN",         (2,0), (2,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
    ]))
    story.append(ov_t)

    for r in results:
        story.append(Spacer(1, 7*mm))
        story.append(HRFlowable(width="100%", thickness=1, color=COL_BORDER))
        story.append(Spacer(1, 3*mm))
        v   = r.get("verdict", "CLEAN")
        rid = str(r.get(id_field, ""))
        hdr_txt = pdf_esc(rid)
        if kind == "hash":
            hdr_txt = '<font size="8">{}</font>'.format(hdr_txt)
        ip_hdr = Table([[
            Paragraph(hdr_txt, ps("iph"+rid[:6], fontName="Helvetica-Bold", fontSize=13, textColor=COL_CYAN, leading=15)),
            verdict_badge(v, col_w=int(W*0.20)),
            Paragraph("Score: {:.1f} / 100".format(r.get("score", 0)),
                      ps("sch"+rid[:6], fontName="Helvetica-Bold", fontSize=10,
                         textColor=vc(v), alignment=TA_RIGHT)),
        ]], colWidths=[W*0.45, W*0.23, W*0.32])
        ip_hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), VBGCOL.get(v, BG_CARD)),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("LEFTPADDING",   (0,0), (-1,-1), 12),
            ("RIGHTPADDING",  (0,0), (-1,-1), 12),
            ("LINEBELOW",     (0,0), (-1,-1), 2, vc(v)),
            ("BOX",           (0,0), (-1,-1), 0.5, vc(v)),
        ]))
        story.append(ip_hdr)
        story.append(Spacer(1, 2*mm))
        story.append(score_bar_drawing(r.get("score", 0), width=int(W), height=14))
        story.append(Spacer(1, 2*mm))
        if r.get("manual_override"):
            story.append(Paragraph(
                "Analyst override: verdict set manually to <b>{}</b> (system verdict: {})".format(
                    pdf_esc(v), pdf_esc(r.get("system_verdict", ""))),
                ps("man"+rid[:6], fontSize=7, textColor=colors.HexColor("#d29922"))))
            story.append(Spacer(1, 1*mm))
        if kind == "hash" and r.get("file_info"):
            fi = r["file_info"]
            story.append(Paragraph(
                "File: {}  |  Type: {}  |  Size: {} bytes  |  Detections: {}/{}".format(
                    pdf_esc(fi.get("name", "—")), pdf_esc(fi.get("type", "—")), pdf_esc(fi.get("size", "—")),
                    pdf_esc(fi.get("detections", "—")), pdf_esc(fi.get("total_engines", "—"))),
                ps("fi"+rid[:6], fontSize=7.5, textColor=COL_TEXT2)))
            story.append(Spacer(1, 1*mm))
        story.append(Spacer(1, 2*mm))

        src_rows = [["Source", "Score", "Findings  /  Verification URL"]]
        for s in r.get("sources", []):
            sname = str(s.get("source", ""))
            sc   = round(s.get("score", 0) or 0, 1)
            sign = "+{:.1f}".format(sc) if sc > 0 else "{:.1f}".format(sc)
            scol = SRC_COL.get(sname, COL_CYAN)
            lines = [pdf_esc(l) for l in (s.get("ioc") or [])]
            if s.get("error"):
                lines.insert(0, "WARNING: " + pdf_esc(s["error"]))
            if not lines:
                lines.append("No data returned")
            url = s.get("url") or _lookup_url(sname, rid, kind)
            if url:
                lines.append('<font color="#8b949e">Verify:</font> ' + pdf_link(url))
            src_rows.append([
                Paragraph(pdf_esc(sname), ps("srn{}".format(sname), fontName="Helvetica-Bold",
                                             fontSize=8, textColor=scol)),
                Paragraph(sign + " pts", ps("srs{}".format(sname), fontName="Helvetica-Bold",
                                             fontSize=9,
                                             textColor=colors.HexColor("#f85149") if sc > 0 else COL_TEXT2,
                                             alignment=TA_CENTER)),
                Paragraph("<br/>".join(lines),
                           ps("sri{}".format(sname), fontSize=7.5, textColor=COL_TEXT2, leading=11)),
            ])
        src_t = Table(src_rows, colWidths=[W*0.22, W*0.12, W*0.66], repeatRows=1)
        src_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BG_CARD),
            ("TEXTCOLOR",     (0,0), (-1,0), COL_TEXT2),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 7.5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_DARK]),
            ("ALIGN",         (1,0), (1,-1), "CENTER"),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
            ("LINEBELOW",     (0,0), (-1,0), 1, COL_BORDER),
        ]))
        story.append(KeepTogether(src_t))

    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=COL_BORDER))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "NXG SOC Platform  |  " +
        ("VirusTotal, MalwareBazaar, AlienVault OTX, Hybrid Analysis" if kind == "hash" else
         "AbuseIPDB, VirusTotal, AlienVault OTX, Hybrid Analysis, GreyNoise, ip-api, ThreatFox") +
        "  |  Source URLs are included per finding for independent verification  |  For SOC / Threat Hunting use only.",
        ps("ft", fontSize=6.5, textColor=COL_TEXT2, alignment=TA_CENTER)))

    def dark_bg(canvas, _doc):
        canvas.saveState()
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    buf.seek(0)
    return buf


@app.route("/api/export/pdf", methods=["POST"])
def export_pdf():
    try:
        import reportlab  # noqa
    except ImportError:
        return jsonify({"error": "reportlab not installed. Run: pip install reportlab"}), 500
    data = request.get_json()
    if not data or not data.get("results"):
        return jsonify({"error": "No results data provided"}), 400
    try:
        buf      = build_pdf(data["results"], kind="ip")
        filename = "ip_report_{}.pdf".format(datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
        response = make_response(buf.read())
        response.headers["Content-Type"]        = "application/pdf"
        response.headers["Content-Disposition"] = "attachment; filename={}".format(filename)
        return response
    except Exception as e:
        import traceback
        return jsonify({"error": "PDF generation failed: {}".format(str(e)),
                        "detail": traceback.format_exc()}), 500


@app.route("/api/export/hash/pdf", methods=["POST"])
def export_hash_pdf():
    try:
        import reportlab  # noqa
    except ImportError:
        return jsonify({"error": "reportlab not installed. Run: pip install reportlab"}), 500
    data = request.get_json()
    if not data or not data.get("results"):
        return jsonify({"error": "No results data provided"}), 400
    try:
        buf      = build_pdf(data["results"], kind="hash")
        filename = "hash_report_{}.pdf".format(datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
        response = make_response(buf.read())
        response.headers["Content-Type"]        = "application/pdf"
        response.headers["Content-Disposition"] = "attachment; filename={}".format(filename)
        return response
    except Exception as e:
        import traceback
        return jsonify({"error": "PDF generation failed: {}".format(str(e)),
                        "detail": traceback.format_exc()}), 500


@app.route("/api/investigate/hash/stream", methods=["POST"])
def api_investigate_hash_stream():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    raw_hashes = data.get("hashes", [])
    if isinstance(raw_hashes, str):
        raw_hashes = [x.strip() for x in raw_hashes.replace(",", "\n").splitlines() if x.strip()]
    valid   = [h.strip().lower() for h in raw_hashes if detect_hash_type(h.strip())]
    invalid = [h for h in raw_hashes if not detect_hash_type(h.strip())]
    if not valid:
        return jsonify({"error": "No valid hashes (MD5=32, SHA1=40, SHA256=64 hex chars)", "invalid": invalid}), 400
    if len(valid) > 20:
        return jsonify({"error": "Maximum 20 hashes per request"}), 400
    cfg            = load_config()
    active_sources = data.get("active_sources", None)
    total          = len(valid)

    workers = min(max(int(data.get("parallel", BATCH_WORKERS_DEFAULT)), 1),
                  BATCH_WORKERS_MAX, total)

    def generate():
        yield "data: {}\n\n".format(json.dumps({"type": "start", "total": total, "invalid": invalid, "workers": workers}))
        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(investigate_hash, h, cfg, active_sources): h for h in valid}
            for idx, fut in enumerate(as_completed(futs), 1):
                try:
                    result = fut.result()
                except Exception as e:
                    result = {"hash": futs[fut], "hash_type": "UNKNOWN", "score": 0, "verdict": "CLEAN",
                              "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                              "file_info": {}, "sources": [], "error": str(e)}
                results.append(result)
                pct = round(idx / total * 100)
                yield "data: {}\n\n".format(json.dumps({
                    "type": "result", "index": idx, "total": total, "percent": pct, "result": result,
                }))
        summary = {
            "total":      len(results),
            "malicious":  sum(1 for r in results if r["verdict"] == "MALICIOUS"),
            "suspicious": sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
            "clean":      sum(1 for r in results if r["verdict"] == "CLEAN"),
        }
        yield "data: {}\n\n".format(json.dumps({"type": "done", "summary": summary}))

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/health", methods=["GET"])
def health():
    cfg = load_config()
    configured = [k for k in CONFIG_FIELDS if get_key_pool(cfg, k)]
    return jsonify({"status":"ok","sources_configured":len(configured),"sources":configured,
                    "timestamp":datetime.now(timezone.utc).isoformat()})



# ══════════════════════════════════════════════════════════════════
# TRAFFIC CSV ANALYSIS
# ══════════════════════════════════════════════════════════════════

import csv as csv_mod
from collections import Counter, defaultdict

# ── Mitigation recommendations (NetShield filter mapping) ─────────
# Maps each attack indicator type to recommended mitigation filters,
# ordered by the NetShield mitigation sequence (Allow/Blocklist → NTIF →
# Bogons → Anti-Flood → FlexFilter → Zombie → Traffic Policing).
MITIGATION_MAP = {
    "SYN_FLOOD": {
        "filter": "TCP Anti-Flood",
        "actions": [
            "Enable TCP Anti-Spoofing in 'TCP Retransmission' mode (Half-Open Validation) to drop spoofed SYNs",
            "Enable 'TCP SYN with Reserved Flags' and 'TCP SYN with Data' malformed-packet rules",
            "If attack persists, configure Traffic Policing (SYN/SYN-ACK) thresholds for Total / Validated / Suspicious IPs",
        ],
    },
    "LAYER7_HTTP_FLOOD": {
        "filter": "L7 HTTP / SSL-TLS Anti-Flood",
        "actions": [
            "Create an L7 protection profile for the targeted HTTP/HTTPS ports",
            "Enable TCP Connection Protection (Source IP New/Half-Open/Idle/Total Connection rules) in Ratelimit or Block mode",
            "Enable HTTP Authentication challenge (302 redirect or JavaScript) to eliminate bot/spoofed sources",
            "For HTTPS targets: enable SSL/TLS Session (per Source IP) and SSL/TLS Traffic Shaping",
        ],
    },
    "UDP_PORT443_ABUSE": {
        "filter": "L7 QUIC Anti-Flood + UDP Anti-Flood",
        "actions": [
            "Create a QUIC protection profile for UDP/443: enable Malformed Packets rule and QUIC Flood Authentication (Retry-token validation)",
            "Enable Ratelimit (per Session) and Session (per Source IP) sub-rules",
            "If traffic is not legitimate HTTP/3, drop UDP/443 entirely via FlexFilter Basic Network Filtering",
        ],
    },
    "UDP_MIXED_ATTACK": {
        "filter": "NTIF + UDP Anti-Flood + S.M.A.RT",
        "actions": [
            "Set NTIF Botnet/DDoS-attacks and Botnet/Reputation sub-categories to Drop mode",
            "Enable UDP Fragmentation, UDP Payload Attack, and 'Drop all 0's Attack Pattern' rules",
            "Enable S.M.A.RT filter (Amplification Attacks + Threat Intelligence categories) for reflection/amplification vectors",
        ],
    },
    "CDN_REFLECTION": {
        "filter": "FlexFilter + Zombie",
        "actions": [
            "Do NOT blanket-blocklist CDN ranges — legitimate traffic also originates there",
            "Use FlexFilter Basic Network Filtering to rate-limit the specific source/destination/port pattern observed",
            "Enable Zombie Host ratelimit to slow aggressive CDN-origin sources without full blocking",
            "Review origin-server exposure: restrict origin to accept traffic only from your CDN provider's published ranges",
        ],
    },
    "DISTRIBUTED_SOURCES": {
        "filter": "NTIF + Zombie Network + Geo Blocklist",
        "actions": [
            "Set NTIF Botnet/DDoS-attacks sub-category to Drop mode (botnet-sourced distributed floods)",
            "Enable Zombie Network rule (/24 ratelimit or block) against aggressive source networks",
            "Apply country Blocklist for regions with no business operations",
        ],
    },
    "TRAFFIC_CONCENTRATION": {
        "filter": "Blocklist / Zombie Host",
        "actions": [
            "Verify the top source IP via threat intel (auto-investigation), then add to IP Blocklist if malicious",
            "Alternatively enable Zombie Host Block mode for the offending source with a defined block duration",
        ],
    },
    "NONSTANDARD_PORTS": {
        "filter": "FlexFilter / Custom Anti-Flood",
        "actions": [
            "If the ports serve no legitimate service: drop them via FlexFilter Basic Network Filtering",
            "If the ports are legitimate custom services: create a Custom Anti-Flood profile with TCP Connection Protection",
        ],
    },
    "ANOMALOUS_FLOW_SIZE": {
        "filter": "Protocol Anti-Flood + Traffic Policing",
        "actions": [
            "Enable Protocol Anti-Flood TCP/UDP Ratelimit to cap per-protocol throughput",
            "Configure Traffic Policing as the final safeguard to shape residual traffic to a safe delivery rate",
        ],
    },
}

BASELINE_MITIGATION = {
    "indicator": "BASELINE",
    "severity":  "INFO",
    "filter":    "Baseline hardening",
    "actions": [
        "Enable Bogons filter (Martian Address + Land Attack) — always safe",
        "Allowlist trusted corporate/partner IP ranges so they bypass aggressive filters",
        "Keep Traffic Policing enabled as the last line of defense",
    ],
}

CDN_PREFIXES = [
    ("142.250.", "Google"), ("142.251.", "Google"), ("74.125.", "Google"),
    ("64.233.", "Google"), ("172.217.", "Google"), ("172.253.", "Google"),
    ("216.239.", "Google"), ("209.85.", "Google"), ("8.8.8.", "Google DNS"),
    ("8.8.4.", "Google DNS"),
    ("13.35.", "Amazon CloudFront"), ("13.249.", "Amazon CloudFront"),
    ("3.174.", "Amazon CloudFront"), ("3.170.", "Amazon CloudFront"),
    ("3.171.", "Amazon CloudFront"), ("3.172.", "Amazon CloudFront"),
    ("108.156.", "Amazon CloudFront"), ("65.8.", "Amazon CloudFront"),
    ("65.9.", "Amazon CloudFront"), ("18.155.", "Amazon CloudFront"),
    ("52.84.", "Amazon CloudFront"), ("99.86.", "Amazon CloudFront"),
    ("52.222.", "Amazon CloudFront"), ("54.182.", "Amazon CloudFront"),
    ("23.214.", "Akamai"), ("23.215.", "Akamai"), ("23.200.", "Akamai"),
    ("23.40.", "Akamai"), ("23.44.", "Akamai"), ("23.46.", "Akamai"),
    ("104.88.", "Akamai"), ("104.89.", "Akamai"), ("184.25.", "Akamai"),
    ("199.232.", "Fastly"), ("151.101.", "Fastly"),
    ("157.240.", "Meta"), ("31.13.", "Meta"), ("129.134.", "Meta"),
    ("17.248.", "Apple"), ("17.57.", "Apple"), ("17.253.", "Apple"),
    ("162.125.", "Dropbox"),
    ("170.114.", "Edgenext"), ("148.222.", "Edgenext"),
    ("162.141.", "Unknown/Custom"),
]

def get_cdn_org(ip):
    for prefix, org in CDN_PREFIXES:
        if ip.startswith(prefix):
            return org
    return None

def is_cdn_ip(ip):
    return get_cdn_org(ip) is not None

FLAG_MAP = {0: "None", 2: "SYN", 4: "RST", 16: "ACK",
            17: "FIN+ACK", 18: "SYN+ACK", 24: "PSH+ACK", 25: "PSH+ACK+FIN"}
PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}

def fmt_bytes(b):
    if b >= 1e9: return "{:.2f} GB".format(b / 1e9)
    if b >= 1e6: return "{:.1f} MB".format(b / 1e6)
    if b >= 1e3: return "{:.1f} KB".format(b / 1e3)
    return "{} B".format(b)

def fmt_bps(v):
    for u in ("bps", "Kbps", "Mbps"):
        if v < 1000:
            return "{:.1f} {}".format(v, u)
        v /= 1000.0
    return "{:.2f} Gbps".format(v)

def fmt_pps(v):
    for u in ("pps", "Kpps"):
        if v < 1000:
            return "{:.1f} {}".format(v, u)
        v /= 1000.0
    return "{:.2f} Mpps".format(v)

def fmt_pkts(p):
    if p >= 1e6: return "{:.2f}M".format(p / 1e6)
    if p >= 1e3: return "{:.1f}K".format(p / 1e3)
    return str(p)

# ── Deep mitigation plan (Mitigation Optimization page) ──────────
def _nice_ceil(v):
    """Round up to a 'nice' config number: 1/2/5 x 10^n."""
    if v <= 0:
        return 0
    exp = math.floor(math.log10(v))
    for m in (1, 2, 5, 10):
        cand = m * (10 ** exp)
        if cand >= v:
            return int(cand)
    return int(10 ** (exp + 1))


def build_mitigation_plan(flows, total_bytes, total_packets):
    """Compute concrete mitigation values: block candidates, policing
    thresholds, and per-filter parameter recommendations."""
    timestamps = [f["timestamp"] for f in flows if f["timestamp"] > 0]
    duration_s = max((max(timestamps) - min(timestamps)), 1) if len(timestamps) > 1 else 1

    avg_mbps = total_bytes * 8 / duration_s / 1e6
    avg_kpps = total_packets / duration_s / 1e3

    proto_pkts = defaultdict(int)
    for f in flows:
        proto_pkts[f["protocol"]] += f["packets"]
    tcp_pps  = proto_pkts.get(6, 0)  / duration_s
    udp_pps  = proto_pkts.get(17, 0) / duration_s
    icmp_pps = proto_pkts.get(1, 0)  / duration_s

    # ── Per-source stats & block scoring ──────────────────────────
    standard_ports = {80, 443, 8080, 8443, 53, 853}
    src_stats = {}
    for f in flows:
        s = src_stats.setdefault(f["src_ip"], {
            "bytes": 0, "packets": 0, "flows": 0,
            "syn": 0, "tcp": 0, "udp443": 0, "ns_ports": set()})
        s["bytes"]   += f["bytes"]
        s["packets"] += f["packets"]
        s["flows"]   += 1
        if f["protocol"] == 6:
            s["tcp"] += 1
            if f["flags"] == 2:
                s["syn"] += 1
        if f["protocol"] == 17 and f["dst_port"] == 443:
            s["udp443"] += 1
        if f["dst_port"] not in standard_ports and f["dst_port"] > 0:
            s["ns_ports"].add(f["dst_port"])

    candidates = []
    for ip, s in src_stats.items():
        score, reasons = 0, []
        byte_share = s["bytes"] / total_bytes if total_bytes else 0
        if byte_share > 0.02:
            score += min(byte_share * 200, 40)
            reasons.append("{:.1f}% of total volume".format(byte_share * 100))
        if s["tcp"] >= 5 and s["syn"] / s["tcp"] > 0.6:
            score += 25
            reasons.append("SYN-dominant ({}/{} TCP flows)".format(s["syn"], s["tcp"]))
        if s["udp443"] >= 5:
            score += 20
            reasons.append("{} UDP/443 flows (QUIC/reflection abuse)".format(s["udp443"]))
        if len(s["ns_ports"]) >= 5:
            score += 15
            reasons.append("targets {} non-standard ports (scanning pattern)".format(len(s["ns_ports"])))
        pps = s["packets"] / duration_s
        if pps > 1000:
            score += 10
            reasons.append("sustained {:.0f} pps".format(pps))
        if score >= 20:
            cdn = is_cdn_ip(ip)
            candidates.append({
                "ip": ip, "score": round(score, 1),
                "bytes": s["bytes"], "bytes_fmt": fmt_bytes(s["bytes"]),
                "flows": s["flows"], "pps": round(pps, 1),
                "reasons": reasons, "is_cdn": cdn,
                "action": "Ratelimit (CDN — do not hard-block)" if cdn else "Block",
            })
    candidates.sort(key=lambda c: c["score"], reverse=True)
    block_candidates = candidates[:10]

    # ── /24 aggregation (Zombie Network targets) ──────────────────
    net_groups = defaultdict(list)
    for c in candidates:
        if "." in c["ip"] and ":" not in c["ip"]:
            net_groups[".".join(c["ip"].split(".")[:3]) + ".0/24"].append(c["ip"])
    network_blocks = [
        {"network": n, "offenders": ips, "count": len(ips)}
        for n, ips in sorted(net_groups.items(), key=lambda x: len(x[1]), reverse=True)
        if len(ips) >= 3
    ][:5]

    # ── Clean baseline (traffic excluding offenders) ──────────────
    offender_ips = set(c["ip"] for c in candidates)
    clean_bytes  = sum(s["bytes"]   for ip, s in src_stats.items() if ip not in offender_ips)
    clean_pkts   = sum(s["packets"] for ip, s in src_stats.items() if ip not in offender_ips)
    baseline_mbps = clean_bytes * 8 / duration_s / 1e6
    baseline_kpps = clean_pkts / duration_s / 1e3
    pol_mbps = _nice_ceil(max(baseline_mbps * 1.5, 1))
    pol_kpps = _nice_ceil(max(baseline_kpps * 1.5, 1))

    clean_tcp_pps = sum(f["packets"] for f in flows
                        if f["protocol"] == 6  and f["src_ip"] not in offender_ips) / duration_s
    clean_udp_pps = sum(f["packets"] for f in flows
                        if f["protocol"] == 17 and f["src_ip"] not in offender_ips) / duration_s
    tcp_limit = _nice_ceil(max(clean_tcp_pps * 1.5, 100))
    udp_limit = _nice_ceil(max(clean_udp_pps * 1.5, 100))

    clean_src_pps = sorted(s["packets"] / duration_s
                           for ip, s in src_stats.items() if ip not in offender_ips)
    p95 = clean_src_pps[int(len(clean_src_pps) * 0.95)] if clean_src_pps else 0
    zombie_pps = _nice_ceil(max(p95 * 2, 50))

    # Per-source flows/minute → TCP Connection Protection threshold
    flows_per_min = sorted(s["flows"] / (duration_s / 60.0)
                           for ip, s in src_stats.items() if ip not in offender_ips)
    fpm95 = flows_per_min[int(len(flows_per_min) * 0.95)] if flows_per_min else 0
    conn_limit = _nice_ceil(max(fpm95 * 2, 30))

    filter_values = [
        {"filter": "Traffic Policing", "parameter": "Throughput limit",
         "recommended": "{} Mbps  /  {} Kpps".format(pol_mbps, pol_kpps),
         "rationale": "Clean baseline {:.1f} Mbps / {:.1f} Kpps (excluding {} offender IPs) + 50% headroom, rounded up".format(
             baseline_mbps, baseline_kpps, len(offender_ips))},
        {"filter": "Protocol Anti-Flood", "parameter": "TCP Ratelimit",
         "recommended": "{} pps".format(tcp_limit),
         "rationale": "Clean TCP baseline {:.0f} pps + 50% headroom (attack-period total: {:.0f} pps)".format(
             clean_tcp_pps, tcp_pps)},
        {"filter": "Protocol Anti-Flood", "parameter": "UDP Ratelimit",
         "recommended": "{} pps".format(udp_limit),
         "rationale": "Clean UDP baseline {:.0f} pps + 50% headroom (attack-period total: {:.0f} pps)".format(
             clean_udp_pps, udp_pps)},
        {"filter": "Zombie Host", "parameter": "Per-source ratelimit",
         "recommended": "{} pps".format(zombie_pps),
         "rationale": "2x the 95th-percentile clean per-source rate ({:.0f} pps)".format(p95)},
        {"filter": "TCP Connection Protection", "parameter": "Total Connection (per src IP / min)",
         "recommended": "{} connections/min".format(conn_limit),
         "rationale": "2x the 95th-percentile clean per-source flow rate ({:.0f} flows/min)".format(fpm95)},
    ]

    syn_pps = sum(f["packets"] for f in flows
                  if f["protocol"] == 6 and f["flags"] == 2) / duration_s
    if syn_pps > 100:
        filter_values.append({
            "filter": "TCP Anti-Spoofing", "parameter": "Mode",
            "recommended": "TCP Retransmission (Half-Open Validation)",
            "rationale": "SYN rate {:.0f} pps observed — retransmission challenge drops spoofed sources; "
                         "add Traffic Policing (SYN) at ~{} pps".format(syn_pps, _nice_ceil(max(syn_pps * 0.1, 100)))})
    udp443_flows = sum(1 for f in flows if f["protocol"] == 17 and f["dst_port"] == 443)
    if udp443_flows > 50:
        filter_values.append({
            "filter": "QUIC Anti-Flood", "parameter": "QUIC Flood sub-rules",
            "recommended": "Authentication ON; Session 2000 pps/src; Ratelimit 30 new sessions/s/src",
            "rationale": "{} UDP/443 flows observed — Retry-token authentication rejects spoofed QUIC initials "
                         "(values are NetShield defaults; tighten if abuse persists)".format(udp443_flows)})
    if icmp_pps > 100:
        filter_values.append({
            "filter": "ICMP Anti-Flood", "parameter": "Drop all ICMP traffic",
            "recommended": "ON",
            "rationale": "ICMP at {:.0f} pps — ICMP is not used for data exchange; safe to drop during attack".format(icmp_pps)})

    return {
        "observed": {
            "duration_s":  duration_s,
            "avg_mbps":    round(avg_mbps, 2),
            "avg_kpps":    round(avg_kpps, 2),
            "tcp_pps":     round(tcp_pps, 1),
            "udp_pps":     round(udp_pps, 1),
            "icmp_pps":    round(icmp_pps, 1),
            "baseline_mbps": round(baseline_mbps, 2),
            "baseline_kpps": round(baseline_kpps, 2),
            "sources":     len(src_stats),
            "offenders":   len(offender_ips),
        },
        "block_candidates": block_candidates,
        "network_blocks":   network_blocks,
        "filter_values":    filter_values,
    }


def analyze_traffic_csv(file_content, cache_files=None):
    flows = []
    try:
        text = file_content.decode("utf-8", errors="replace")
        reader = csv_mod.reader(text.splitlines())
        for row in reader:
            if len(row) < 12:
                continue
            try:
                flows.append({
                    "flags":     int(row[0]),
                    "dst_port":  int(row[2]),
                    "src_port":  int(row[3]),
                    "src_ip":    row[4].strip('"').strip(),
                    "dst_ip":    row[5].strip('"').strip(),
                    "bytes":     int(row[6]),
                    "packets":   int(row[7]),
                    "protocol":  int(row[8]),
                    "timestamp": int(row[11]),
                })
            except (ValueError, IndexError):
                continue
    except Exception as e:
        return {"error": "CSV parse error: {}".format(str(e))}

    if not flows:
        return {"error": "No valid flow rows found. Expected format: flags,profile,dst_port,src_port,src_ip,dst_ip,bytes,packets,proto,router,metric,timestamp"}

    # Cache parsed flows so IP investigations can layer traffic-behavior
    # scoring (q_behavior) on top of threat intelligence.
    cache_traffic_flows(flows, cache_files)

    total_bytes   = sum(f["bytes"]   for f in flows)
    total_packets = sum(f["packets"] for f in flows)

    src_bytes   = defaultdict(int)
    src_packets = defaultdict(int)
    for f in flows:
        src_bytes[f["src_ip"]]   += f["bytes"]
        src_packets[f["src_ip"]] += f["packets"]

    top10_bytes       = sorted(src_bytes.items(),   key=lambda x: x[1], reverse=True)[:10]
    top10_packets     = sorted(src_packets.items(), key=lambda x: x[1], reverse=True)[:10]
    all_sources_bytes = sorted(src_bytes.items(),   key=lambda x: x[1], reverse=True)

    # ── Peak rate per source (Nexusguard-style bps/pps) ───────────
    # NetFlow records are aggregated per export interval, so bucket by
    # timestamp and estimate the interval from the median gap between
    # distinct export timestamps. Peak = a source's busiest bucket.
    bkt_bytes = defaultdict(lambda: defaultdict(int))  # ts -> src -> bytes
    bkt_pkts  = defaultdict(lambda: defaultdict(int))
    for f in flows:
        if f["timestamp"] > 0:
            bkt_bytes[f["timestamp"]][f["src_ip"]] += f["bytes"]
            bkt_pkts[f["timestamp"]][f["src_ip"]]  += f["packets"]
    ts_sorted = sorted(bkt_bytes.keys())
    gaps = [b - a for a, b in zip(ts_sorted, ts_sorted[1:]) if b > a]
    interval = sorted(gaps)[len(gaps) // 2] if gaps else 1  # median gap, fallback 1s
    peak_bps, peak_pps = {}, {}
    for ts, per_src in bkt_bytes.items():
        for s, v in per_src.items():
            r = v * 8.0 / interval
            if r > peak_bps.get(s, 0): peak_bps[s] = r
    for ts, per_src in bkt_pkts.items():
        for s, v in per_src.items():
            r = v / float(interval)
            if r > peak_pps.get(s, 0): peak_pps[s] = r
    # Percentage basis = network peak rate (busiest bucket total), matching
    # Nexusguard's methodology: "at its peak, this source equaled X% of the
    # network's peak traffic rate."
    net_peak_bps = max((sum(s.values()) for s in bkt_bytes.values()), default=0) * 8.0 / interval or 1
    net_peak_pps = max((sum(s.values()) for s in bkt_pkts.values()),  default=0) / float(interval) or 1
    top10_peak_bps = [
        {"ip": s, "rate": round(r, 1), "rate_fmt": fmt_bps(r),
         "pct": round(r / net_peak_bps * 100, 2),
         "total_fmt": fmt_bytes(src_bytes[s]), "cdn": get_cdn_org(s) or ""}
        for s, r in sorted(peak_bps.items(), key=lambda x: x[1], reverse=True)[:10]]
    top10_peak_pps = [
        {"ip": s, "rate": round(r, 1), "rate_fmt": fmt_pps(r),
         "pct": round(r / net_peak_pps * 100, 2),
         "total_fmt": fmt_pkts(src_packets[s]), "cdn": get_cdn_org(s) or ""}
        for s, r in sorted(peak_pps.items(), key=lambda x: x[1], reverse=True)[:10]]

    dst_ip_counter   = Counter(f["dst_ip"]   for f in flows)
    dst_port_counter = Counter(f["dst_port"] for f in flows)
    proto_counter    = Counter(PROTO_MAP.get(f["protocol"], str(f["protocol"])) for f in flows)
    flag_counter     = Counter(FLAG_MAP.get(f["flags"], str(f["flags"]))
                                for f in flows if f["protocol"] == 6)

    # ── Attack indicators ─────────────────────────────────────────
    indicators = []
    attack_score = 0

    cdn_bytes = sum(v for k, v in src_bytes.items() if is_cdn_ip(k))
    cdn_ratio = cdn_bytes / total_bytes if total_bytes else 0
    if cdn_ratio > 0.4:
        indicators.append({
            "type": "CDN_REFLECTION", "severity": "HIGH",
            "detail": "{:.1f}% of traffic originates from CDN IPs (Google/Amazon/Akamai/Fastly). "
                      "Attackers are using CDN origin-forwarding to amplify and disguise the flood.".format(cdn_ratio * 100),
        })
        attack_score += 30

    if top10_bytes:
        top1_ratio = top10_bytes[0][1] / total_bytes if total_bytes else 0
        if top1_ratio > 0.25:
            indicators.append({
                "type": "TRAFFIC_CONCENTRATION", "severity": "MEDIUM",
                "detail": "Top source {} contributes {:.1f}% of total bytes — abnormal single-source concentration.".format(
                    top10_bytes[0][0], top1_ratio * 100),
            })
            attack_score += 15

    tcp_flows   = [f for f in flows if f["protocol"] == 6]
    psh_flows   = [f for f in tcp_flows if f["flags"] == 24]
    syn_flows   = [f for f in tcp_flows if f["flags"] == 2]
    if tcp_flows:
        psh_ratio = len(psh_flows) / len(tcp_flows)
        syn_ratio = len(syn_flows) / len(tcp_flows)
        if psh_ratio > 0.4:
            indicators.append({
                "type": "LAYER7_HTTP_FLOOD", "severity": "HIGH",
                "detail": "PSH+ACK flag dominates {:.1f}% of TCP flows — confirmed Layer 7 HTTP(S) application flood. "
                          "Flows represent active data-pushing sessions, not idle connections.".format(psh_ratio * 100),
            })
            attack_score += 25
        if syn_ratio > 0.4:
            indicators.append({
                "type": "SYN_FLOOD", "severity": "HIGH",
                "detail": "SYN flag in {:.1f}% of TCP flows — SYN flood pattern detected.".format(syn_ratio * 100),
            })
            attack_score += 25

    udp_443 = [f for f in flows if f["protocol"] == 17 and f["dst_port"] == 443]
    if udp_443:
        udp_bytes = sum(f["bytes"] for f in udp_443)
        indicators.append({
            "type": "UDP_PORT443_ABUSE", "severity": "MEDIUM",
            "detail": "{} UDP flows on port 443 ({}) — potential QUIC protocol abuse or UDP reflection attack.".format(
                len(udp_443), fmt_bytes(udp_bytes)),
        })
        attack_score += 15

    standard_ports = {80, 443, 8080, 8443, 53, 853}
    nonstandard_flows = [f for f in flows if f["dst_port"] not in standard_ports and f["dst_port"] > 0]
    if nonstandard_flows:
        ns_ports = Counter(f["dst_port"] for f in nonstandard_flows).most_common(5)
        indicators.append({
            "type": "NONSTANDARD_PORTS", "severity": "LOW",
            "detail": "Traffic on non-standard destination ports: {}. "
                      "May indicate port scanning or custom protocol abuse.".format(
                          ", ".join(str(p) for p, _ in ns_ports)),
        })
        attack_score += 8

    large_flows = [f for f in flows if f["bytes"] > 50_000_000]
    if large_flows:
        max_b = max(f["bytes"] for f in large_flows)
        indicators.append({
            "type": "ANOMALOUS_FLOW_SIZE", "severity": "HIGH",
            "detail": "{} individual flow records exceed 50 MB each (largest: {}). "
                      "Sustained per-flow volume is abnormal for legitimate browsing sessions.".format(
                          len(large_flows), fmt_bytes(max_b)),
        })
        attack_score += 20

    unique_sources = len(src_bytes)
    if unique_sources > 15:
        indicators.append({
            "type": "DISTRIBUTED_SOURCES", "severity": "MEDIUM",
            "detail": "{} unique source IPs all targeting the same destination — "
                      "distributed multi-source attack pattern.".format(unique_sources),
        })
        attack_score += 10

    udp_flows = [f for f in flows if f["protocol"] == 17]
    if udp_flows and len(udp_flows) / len(flows) > 0.05:
        udp_srcs = set(f["src_ip"] for f in udp_flows)
        indicators.append({
            "type": "UDP_MIXED_ATTACK", "severity": "MEDIUM",
            "detail": "{} UDP flows from {} source IPs alongside TCP flood — "
                      "mixed-vector attack (HTTP flood + UDP component).".format(len(udp_flows), len(udp_srcs)),
        })
        attack_score += 10

    # ── Verdict ───────────────────────────────────────────────────
    if attack_score >= 55:
        verdict, confidence, color = "ATTACK", "HIGH", "red"
    elif attack_score >= 30:
        verdict, confidence, color = "ATTACK", "MEDIUM", "orange"
    elif attack_score >= 15:
        verdict, confidence, color = "SUSPICIOUS", "LOW", "yellow"
    else:
        verdict, confidence, color = "CLEAN", "HIGH", "green"

    timestamps = [f["timestamp"] for f in flows if f["timestamp"] > 0]
    duration_s = (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0

    # Packet size distribution — 11 fine-grained buckets (avg bytes/packet per flow)
    _psd_labels = ["0-150","151-300","301-450","451-600","601-750",
                   "751-900","901-1050","1051-1200","1201-1350","1351-1500","1500+"]
    _psd = {k: 0 for k in _psd_labels}
    for _f in flows:
        if _f["packets"] > 0:
            _avg = _f["bytes"] / _f["packets"]
            if   _avg <= 150:  _psd["0-150"]     += 1
            elif _avg <= 300:  _psd["151-300"]   += 1
            elif _avg <= 450:  _psd["301-450"]   += 1
            elif _avg <= 600:  _psd["451-600"]   += 1
            elif _avg <= 750:  _psd["601-750"]   += 1
            elif _avg <= 900:  _psd["751-900"]   += 1
            elif _avg <= 1050: _psd["901-1050"]  += 1
            elif _avg <= 1200: _psd["1051-1200"] += 1
            elif _avg <= 1350: _psd["1201-1350"] += 1
            elif _avg <= 1500: _psd["1351-1500"] += 1
            else:              _psd["1500+"]     += 1
    _psd_total = sum(_psd.values()) or 1

    # Build mitigation recommendations from detected indicators
    mitigations = []
    for ind in indicators:
        m = MITIGATION_MAP.get(ind["type"])
        if m:
            mitigations.append({
                "indicator": ind["type"],
                "severity":  ind["severity"],
                "filter":    m["filter"],
                "actions":   m["actions"],
            })
    if mitigations:
        mitigations.append(BASELINE_MITIGATION)

    return {
        "verdict":      verdict,
        "confidence":   confidence,
        "color":        color,
        "attack_score": attack_score,
        "indicators":   indicators,
        "mitigations":  mitigations,
        "mitigation_plan": build_mitigation_plan(flows, total_bytes, total_packets),
        "pkt_size_dist": {"labels": _psd_labels, "data": {k: {"count": v, "pct": round(v/_psd_total*100,1)} for k,v in _psd.items()}},
        "summary": {
            "total_flows":    len(flows),
            "total_bytes":    total_bytes,
            "total_bytes_fmt": fmt_bytes(total_bytes),
            "total_packets":  total_packets,
            "total_packets_fmt": fmt_pkts(total_packets),
            "unique_sources": unique_sources,
            "duration_seconds": duration_s,
            "cdn_ratio":      round(cdn_ratio * 100, 1),
        },
        "targets": {
            "ips":   [{"ip": ip,   "flows": c} for ip, c in dst_ip_counter.most_common(5)],
            "ports": [{"port": p,  "flows": c, "name": {80:"HTTP",443:"HTTPS",53:"DNS",8080:"HTTP-alt",8443:"HTTPS-alt",853:"DoT",9502:"custom",5222:"XMPP"}.get(p,"")}
                      for p, c in dst_port_counter.most_common(10)],
        },
        "top10_bytes": [
            {"ip": ip, "bytes": b, "bytes_fmt": fmt_bytes(b),
             "packets": src_packets[ip], "packets_fmt": fmt_pkts(src_packets[ip]),
             "cdn": get_cdn_org(ip) or ""}
            for ip, b in top10_bytes
        ],
        "all_sources_bytes": [
            {"ip": ip, "bytes": b, "bytes_fmt": fmt_bytes(b),
             "packets": src_packets[ip], "packets_fmt": fmt_pkts(src_packets[ip]),
             "cdn": get_cdn_org(ip) or ""}
            for ip, b in all_sources_bytes
        ],
        "top10_packets": [
            {"ip": ip, "packets": p, "packets_fmt": fmt_pkts(p),
             "bytes": src_bytes[ip], "bytes_fmt": fmt_bytes(src_bytes[ip]),
             "cdn": get_cdn_org(ip) or ""}
            for ip, p in top10_packets
        ],
        "top10_peak_bps": top10_peak_bps,
        "top10_peak_pps": top10_peak_pps,
        "rate_interval_s": interval,
        "protocol_dist": dict(proto_counter),
        "flag_dist":     dict(flag_counter),
    }


@app.route("/api/analyze/traffic", methods=["POST"])
def api_analyze_traffic():
    files = request.files.getlist("csv")
    if not files:
        return jsonify({"error": "No CSV file uploaded. Send multipart field 'csv'."}), 400

    merged_chunks = []
    file_names    = []
    total_size    = 0
    for f in files:
        chunk = f.read()
        total_size += len(chunk)
        if total_size > 15 * 1024 * 1024:
            return jsonify({"error": "Combined file size too large (max 15 MB)."}), 400
        if chunk and not chunk.endswith(b"\n"):
            chunk += b"\n"
        merged_chunks.append(chunk)
        file_names.append(f.filename or "unnamed.csv")

    merged_content = b"".join(merged_chunks)
    result = analyze_traffic_csv(merged_content, cache_files=file_names)
    if "error" in result:
        return jsonify(result), 400

    result["merged_files"] = file_names
    result["file_count"]   = len(files)
    return jsonify(result)


@app.route("/api/investigate/behavior", methods=["POST"])
def api_investigate_behavior():
    """Standalone traffic-behavior investigation for one or more IPs,
    profiled against the last analyzed traffic capture."""
    data = request.get_json() or {}
    raw_ips = data.get("ips", [])
    if isinstance(raw_ips, str):
        raw_ips = [x.strip() for x in raw_ips.replace(",", "\n").splitlines() if x.strip()]
    valid_ips = [ip for ip in raw_ips if is_valid_ip(ip)]
    if not valid_ips:
        return jsonify({"error": "No valid IP addresses provided"}), 400
    with _TRAFFIC_CACHE_LOCK:
        cap = {"flows": len(_TRAFFIC_CACHE["flows"]), "ts": _TRAFFIC_CACHE["ts"],
               "files": _TRAFFIC_CACHE["files"]}
    results = []
    for ip in valid_ips:
        b = q_behavior(ip)
        b["ip"] = ip
        b["score"] = round(b.get("score", 0), 2)
        results.append(b)
    return jsonify({"results": results, "capture": cap})



def build_traffic_pdf(payload):
    """Generate a dark-themed PDF report for traffic analysis + IP investigation results."""
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, KeepTogether)
    from reportlab.graphics.shapes import Drawing, Rect, String as GStr

    BG_DARK    = colors.HexColor("#0d1117")
    BG_CARD    = colors.HexColor("#161b22")
    BG_ROW     = colors.HexColor("#21262d")
    COL_BORDER = colors.HexColor("#30363d")
    COL_TEXT   = colors.HexColor("#e6edf3")
    COL_TEXT2  = colors.HexColor("#8b949e")
    COL_CYAN   = colors.HexColor("#58a6ff")
    COL_RED    = colors.HexColor("#f85149")
    COL_ORANGE = colors.HexColor("#f0883e")
    COL_YELLOW = colors.HexColor("#d29922")
    COL_GREEN  = colors.HexColor("#3fb950")
    COL_PURPLE = colors.HexColor("#bc8cff")
    VCOL = {
        "MALICIOUS":  COL_RED,
        "HIGH RISK":  COL_ORANGE,
        "SUSPICIOUS": COL_YELLOW,
        "CLEAN":      COL_GREEN,
        "ATTACK":     COL_RED,
    }
    VBGCOL = {
        "MALICIOUS":  colors.HexColor("#2d1517"),
        "HIGH RISK":  colors.HexColor("#2d1b0f"),
        "SUSPICIOUS": colors.HexColor("#2a1d0e"),
        "CLEAN":      colors.HexColor("#0f2518"),
    }
    SRC_COL = {
        "AbuseIPDB":      COL_CYAN,
        "VirusTotal":     COL_PURPLE,
        "AlienVault OTX": COL_ORANGE,
        "ip-api":         COL_GREEN,
    }

    def vc(v):
        return VCOL.get(v, COL_TEXT)

    def ps(name, **kw):
        base = dict(fontName="Helvetica", fontSize=8, textColor=COL_TEXT, leading=11)
        base.update(kw)
        return ParagraphStyle(name, **base)

    def verdict_badge(v, is_manual=False, col_w=68):
        bg  = VBGCOL.get(v, BG_ROW)
        fc  = VCOL.get(v, COL_TEXT2)
        lbl = v + ("  • manual" if is_manual else "")
        inner = Table([[Paragraph(lbl, ps("vb"+v[:3]+str(is_manual),
                                          fontName="Helvetica-Bold", fontSize=7.5,
                                          textColor=fc, alignment=TA_CENTER))]],
                      colWidths=[col_w])
        inner.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), bg),
            ("TOPPADDING",    (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LEFTPADDING",   (0,0), (-1,-1), 5),
            ("RIGHTPADDING",  (0,0), (-1,-1), 5),
            ("BOX",           (0,0), (-1,-1), 0.5, fc),
        ]))
        return inner

    def score_bar_drawing(score, width=120, height=12):
        d  = Drawing(width, height)
        d.add(Rect(0, 3, width, 6, fillColor=BG_ROW, strokeColor=None))
        v  = max(0, min(float(score), 100))
        if v > 0:
            c = vc("MALICIOUS" if v >= 70 else "HIGH RISK" if v >= 45 else
                   "SUSPICIOUS" if v >= 20 else "CLEAN")
            d.add(Rect(0, 3, width * v / 100, 6, fillColor=c, strokeColor=None))
        return d

    def pkt_size_chart(psd, width, row_h=13, gap=3):
        labels_all = psd.get("labels", [])
        data       = psd.get("data", {})
        labels_rev = list(reversed(labels_all))
        max_cnt    = max((data.get(l, {}).get("count", 0) for l in labels_all), default=1) or 1
        label_w    = 48
        count_w    = 62
        bar_area   = max(width - label_w - count_w, 20)
        n          = len(labels_rev)
        total_h    = n * (row_h + gap) + 12
        d          = Drawing(width, total_h)
        ORANGE     = colors.HexColor("#e8914f")
        for i, lbl in enumerate(labels_rev):
            y   = i * (row_h + gap) + 6
            cnt = data.get(lbl, {}).get("count", 0)
            pct = data.get(lbl, {}).get("pct", 0.0)
            d.add(Rect(label_w, y, bar_area, row_h, fillColor=BG_ROW, strokeColor=None))
            if cnt > 0:
                d.add(Rect(label_w, y, bar_area * cnt / max_cnt, row_h,
                           fillColor=ORANGE, strokeColor=None))
            d.add(GStr(0, y + 3, lbl, fontName="Helvetica", fontSize=7,
                       fillColor=COL_TEXT2))
            d.add(GStr(label_w + bar_area + 4, y + 3,
                       "{} ({:.1f}%)".format(cnt, pct),
                       fontName="Helvetica", fontSize=7, fillColor=COL_TEXT2))
        return d

    def kv_table(rows, col_widths):
        t = Table(rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), BG_CARD),
            ("ROWBACKGROUNDS",(0,0), (-1,-1), [BG_ROW, BG_CARD]),
            ("TEXTCOLOR",     (0,0), (0,-1), COL_TEXT2),
            ("TEXTCOLOR",     (1,0), (1,-1), COL_TEXT),
            ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))
        return t

    def section_header(text):
        return Paragraph(text, ps("sh_"+text[:8], fontName="Helvetica-Bold", fontSize=9,
                                   textColor=COL_TEXT2))

    traffic   = payload.get("traffic", {})
    inv       = payload.get("investigation", [])
    manual_v  = payload.get("manual_verdicts", {})
    ts_gen    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    # Override score/verdict with the effective values from the dashboard (includes IP rep bonus)
    if "override_score" in payload:
        traffic = dict(traffic)  # shallow copy — don't mutate original
        traffic["attack_score"] = payload["override_score"]
    if "override_confidence" in payload:
        traffic = dict(traffic)
        traffic["confidence"] = payload["override_confidence"]
    if "override_verdict" in payload:
        traffic = dict(traffic)
        traffic["verdict"] = payload["override_verdict"]

    buf = BytesIO()
    W   = A4[0] - 36*mm
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm)
    story = []

    # ── Title ─────────────────────────────────────────────────────
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("TRAFFIC ANALYSIS REPORT",
                            ps("h1", fontName="Helvetica-Bold", fontSize=18,
                               textColor=COL_CYAN, alignment=TA_CENTER, leading=24)))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("DDoS / NetFlow Threat Intelligence Report",
                            ps("sub", fontSize=10, textColor=COL_TEXT2, alignment=TA_CENTER)))
    story.append(Spacer(1, 3*mm))
    story.append(HRFlowable(width="100%", thickness=1, color=COL_BORDER))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("Generated: {}".format(ts_gen),
                            ps("meta", fontSize=7, textColor=COL_TEXT2, alignment=TA_CENTER)))
    story.append(Spacer(1, 5*mm))

    # ── Verdict Banner ────────────────────────────────────────────
    verdict    = traffic.get("verdict", "UNKNOWN")
    confidence = traffic.get("confidence", "—")
    atk_score  = traffic.get("attack_score", 0)
    v_color    = vc(verdict)
    v_bg       = VBGCOL.get(verdict, BG_CARD)

    banner_data = [[
        Paragraph(verdict, ps("vv", fontName="Helvetica-Bold", fontSize=22,
                              textColor=v_color, leading=28)),
        Paragraph("Confidence: {}".format(confidence),
                  ps("vc", fontName="Helvetica-Bold", fontSize=10, textColor=COL_TEXT2,
                     alignment=TA_RIGHT)),
        Paragraph("Attack Score: {}/100".format(atk_score),
                  ps("vs", fontName="Helvetica-Bold", fontSize=14, textColor=v_color,
                     alignment=TA_RIGHT)),
    ]]
    banner_t = Table(banner_data, colWidths=[W*0.38, W*0.32, W*0.30])
    banner_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), v_bg),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("RIGHTPADDING",  (0,0), (-1,-1), 14),
        ("LINEBELOW",     (0,0), (-1,-1), 3, v_color),
        ("BOX",           (0,0), (-1,-1), 0.5, v_color),
    ]))
    story.append(banner_t)
    story.append(Spacer(1, 2*mm))
    story.append(score_bar_drawing(atk_score, width=int(W), height=14))
    story.append(Spacer(1, 5*mm))

    # ── Summary Stats ─────────────────────────────────────────────
    story.append(section_header("TRAFFIC SUMMARY"))
    story.append(Spacer(1, 2*mm))
    s = traffic.get("summary", {})
    dur = s.get("duration_seconds", 0)
    dur_str = "{}m {}s".format(dur//60, dur%60) if dur >= 60 else "{}s".format(dur)
    sum_rows = [
        ["Total Flows",    str(s.get("total_flows", 0))],
        ["Total Bytes",    s.get("total_bytes_fmt", "—")],
        ["Total Packets",  s.get("total_packets_fmt", "—")],
        ["Unique Sources", str(s.get("unique_sources", 0))],
        ["Duration",       dur_str],
        ["CDN Traffic",    "{}%".format(s.get("cdn_ratio", 0))],
    ]
    story.append(kv_table(
        [[Paragraph(r[0], ps("sk"+r[0][:4], fontName="Helvetica-Bold", fontSize=8, textColor=COL_TEXT2)),
          Paragraph(r[1], ps("sv"+r[0][:4], fontSize=9, textColor=COL_TEXT, fontName="Helvetica-Bold"))]
         for r in sum_rows],
        [W*0.35, W*0.65]
    ))
    story.append(Spacer(1, 5*mm))

    # ── Attack Indicators ─────────────────────────────────────────
    indicators = traffic.get("indicators", [])
    if indicators:
        story.append(section_header("ATTACK INDICATORS  ({})".format(len(indicators))))
        story.append(Spacer(1, 2*mm))
        ind_rows = [["Severity", "Type", "Detail"]]
        sev_col  = {"HIGH": COL_RED, "MEDIUM": COL_ORANGE, "LOW": COL_YELLOW}
        for ind in indicators:
            sev  = ind.get("severity", "")
            typ  = ind.get("type", "").replace("_", " ")
            det  = ind.get("detail", "")
            ind_rows.append([
                Paragraph(sev, ps("is"+sev, fontName="Helvetica-Bold", fontSize=8,
                                  textColor=sev_col.get(sev, COL_TEXT2))),
                Paragraph(typ, ps("it"+typ[:6], fontName="Helvetica-Bold", fontSize=8,
                                  textColor=COL_TEXT)),
                Paragraph(det, ps("id"+typ[:6], fontSize=7.5, textColor=COL_TEXT2, leading=11)),
            ])
        ind_t = Table(ind_rows, colWidths=[W*0.12, W*0.22, W*0.66], repeatRows=1)
        ind_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BG_CARD),
            ("TEXTCOLOR",     (0,0), (-1,0), COL_TEXT2),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 7.5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_CARD]),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
        ]))
        story.append(ind_t)
        story.append(Spacer(1, 5*mm))

    # ── Mitigation Recommendations (opt-in via include_mitigations) ─
    mitigations = traffic.get("mitigations", [])
    if payload.get("include_mitigations") and mitigations:
        story.append(section_header("MITIGATION RECOMMENDATIONS  (NetShield)"))
        story.append(Spacer(1, 2*mm))
        sev_col = {"HIGH": COL_RED, "MEDIUM": COL_ORANGE, "LOW": COL_YELLOW}
        mit_rows = [["Indicator", "Filter", "Recommended Actions"]]
        for m in mitigations:
            sev = m.get("severity", "")
            act = "<br/>".join("•  " + a for a in m.get("actions", []))
            mit_rows.append([
                Paragraph(m.get("indicator", "").replace("_", " "),
                          ps("mi"+m.get("indicator","")[:6], fontName="Helvetica-Bold",
                             fontSize=7.5, textColor=sev_col.get(sev, COL_TEXT2))),
                Paragraph(m.get("filter", ""),
                          ps("mf"+m.get("indicator","")[:6], fontName="Helvetica-Bold",
                             fontSize=7.5, textColor=COL_TEXT)),
                Paragraph(act, ps("ma"+m.get("indicator","")[:6], fontSize=7.5,
                                  textColor=COL_TEXT2, leading=11)),
            ])
        mit_t = Table(mit_rows, colWidths=[W*0.18, W*0.22, W*0.60], repeatRows=1)
        mit_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BG_CARD),
            ("TEXTCOLOR",     (0,0), (-1,0), COL_TEXT2),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 7.5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_CARD]),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
        ]))
        story.append(mit_t)
        story.append(Spacer(1, 5*mm))

    # ── Targets ───────────────────────────────────────────────────
    targets = traffic.get("targets", {})
    if targets.get("ips") or targets.get("ports"):
        story.append(section_header("TARGETED IP & PORTS"))
        story.append(Spacer(1, 2*mm))
        tgt_left  = [[Paragraph("Destination IPs", ps("ti", fontName="Helvetica-Bold",
                                                       fontSize=8, textColor=COL_TEXT2))]]
        for t in targets.get("ips", []):
            tgt_left.append([Paragraph("{} — {} flows".format(t["ip"], t["flows"]),
                              ps("tip"+t["ip"][:4], fontSize=8, textColor=COL_CYAN,
                                 fontName="Helvetica-Bold"))])
        tgt_right = [[Paragraph("Destination Ports", ps("tp", fontName="Helvetica-Bold",
                                                         fontSize=8, textColor=COL_TEXT2))]]
        for p in targets.get("ports", []):
            lbl = "{}{} — {} flows".format(p["port"],
                  " ({})".format(p.get("name")) if p.get("name") else "", p["flows"])
            tgt_right.append([Paragraph(lbl, ps("tpp"+str(p["port"]), fontSize=8, textColor=COL_TEXT))])

        while len(tgt_left) < len(tgt_right): tgt_left.append([Paragraph("", ps("_"))])
        while len(tgt_right) < len(tgt_left): tgt_right.append([Paragraph("", ps("__"))])

        tgt_l_t = Table(tgt_left,  colWidths=[W*0.48])
        tgt_r_t = Table(tgt_right, colWidths=[W*0.48])
        for t in [tgt_l_t, tgt_r_t]:
            t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), BG_CARD),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_CARD]),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
            ]))
        tgt_outer = Table([[tgt_l_t, tgt_r_t]], colWidths=[W*0.50, W*0.50])
        tgt_outer.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"),
                                       ("LEFTPADDING",(0,0),(-1,-1),0),
                                       ("RIGHTPADDING",(0,0),(-1,-1),0)]))
        story.append(tgt_outer)
        story.append(Spacer(1, 5*mm))

    # ── Top 10 by Bytes ───────────────────────────────────────────
    top10b = traffic.get("top10_bytes", [])
    if top10b:
        story.append(section_header("TOP 10 SOURCE IPs — BY BYTES"))
        story.append(Spacer(1, 2*mm))
        t10b_rows = [["#", "Source IP", "CDN", "Bytes", "Packets"]]
        for i, row in enumerate(top10b):
            t10b_rows.append([
                Paragraph(str(i+1), ps("n"+str(i), fontSize=8, textColor=COL_TEXT2)),
                Paragraph(row["ip"], ps("ip"+str(i), fontName="Helvetica-Bold",
                                        fontSize=8, textColor=COL_CYAN)),
                Paragraph(row.get("cdn","") or "—", ps("cdn"+str(i), fontSize=7.5, textColor=COL_TEXT2)),
                Paragraph(row["bytes_fmt"], ps("by"+str(i), fontName="Helvetica-Bold",
                                               fontSize=8, textColor=COL_RED)),
                Paragraph(row["packets_fmt"], ps("pk"+str(i), fontSize=8, textColor=COL_TEXT2)),
            ])
        t10b_t = Table(t10b_rows, colWidths=[W*0.06,W*0.30,W*0.24,W*0.20,W*0.20], repeatRows=1)
        t10b_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BG_CARD),
            ("TEXTCOLOR",     (0,0), (-1,0), COL_TEXT2),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 7.5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_CARD]),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
        ]))
        story.append(t10b_t)
        story.append(Spacer(1, 5*mm))

    # ── Packet Size Distribution ──────────────────────────────────
    psd = traffic.get("pkt_size_dist")
    if psd and psd.get("labels"):
        story.append(section_header("PACKET SIZE DISTRIBUTION"))
        story.append(Spacer(1, 2*mm))
        psd_note = traffic.get("pkt_size_note", "")
        chart = pkt_size_chart(psd, width=int(W))
        chart_wrap = Table([[chart]], colWidths=[W])
        chart_wrap.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), BG_CARD),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("RIGHTPADDING",  (0,0), (-1,-1), 10),
            ("BOX",           (0,0), (-1,-1), 0.4, COL_BORDER),
        ]))
        story.append(chart_wrap)
        if psd_note:
            story.append(Spacer(1, 1.5*mm))
            story.append(Paragraph(psd_note,
                                    ps("pnote", fontSize=7, textColor=COL_TEXT2,
                                       fontName="Helvetica-Oblique")))
        story.append(Spacer(1, 5*mm))

    # ── IP Reputation Investigation ───────────────────────────────
    if inv:
        story.append(HRFlowable(width="100%", thickness=1, color=COL_BORDER))
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph("IP REPUTATION INVESTIGATION — TOP 10 SOURCE IPs",
                                ps("invh", fontName="Helvetica-Bold", fontSize=11,
                                   textColor=COL_CYAN, alignment=TA_CENTER)))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("Sources: AbuseIPDB  ·  VirusTotal  ·  AlienVault OTX  ·  ip-api",
                                ps("invs", fontSize=7.5, textColor=COL_TEXT2, alignment=TA_CENTER)))
        story.append(Spacer(1, 4*mm))

        # Overview table
        _vord = {"MALICIOUS":4,"HIGH RISK":3,"SUSPICIOUS":2,"CLEAN":1}
        inv_sorted = sorted(inv,
                            key=lambda r: (_vord.get(manual_v.get(r.get("ip",""), r.get("verdict","CLEAN")),0),
                                           r.get("score",0)),
                            reverse=True)

        ov_rows = [["IP Address", "Verdict", "Score / Bar"]]
        for r in inv_sorted:
            ip    = r.get("ip", "")
            sys_v = r.get("verdict", "CLEAN")
            eff_v = manual_v.get(ip, sys_v)
            score = r.get("score", 0)
            is_manual_flag = ip in manual_v
            ov_rows.append([
                Paragraph(ip, ps("oi"+ip[:6], fontName="Helvetica-Bold", fontSize=8,
                                 textColor=COL_CYAN)),
                verdict_badge(eff_v, is_manual=is_manual_flag, col_w=70),
                Table([[score_bar_drawing(score, width=int(W*0.37), height=10),
                        Paragraph("{:.0f}/100".format(score),
                                  ps("osc"+ip[:6], fontName="Helvetica-Bold", fontSize=8,
                                     textColor=vc(eff_v)))]],
                      colWidths=[W*0.37, W*0.10]),
            ])

        ov_t = Table(ov_rows, colWidths=[W*0.28, W*0.15, W*0.57], repeatRows=1)
        ov_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BG_CARD),
            ("TEXTCOLOR",     (0,0), (-1,0), COL_TEXT2),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 7.5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_CARD]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
        ]))
        story.append(ov_t)
        story.append(Spacer(1, 5*mm))

        # Per-IP detail cards
        story.append(section_header("DETAILED IP FINDINGS"))
        story.append(Spacer(1, 3*mm))

        for r in inv_sorted:
            ip       = r.get("ip", "")
            sys_v    = r.get("verdict", "CLEAN")
            eff_v    = manual_v.get(ip, sys_v)
            score    = r.get("score", 0)
            srcs     = r.get("sources", [])
            is_man   = ip in manual_v

            ip_hdr = Table([[
                Paragraph(ip, ps("iph"+ip[:6], fontName="Helvetica-Bold", fontSize=12,
                                 textColor=COL_CYAN)),
                verdict_badge(eff_v, is_manual=is_man, col_w=80),
                Paragraph("Score: {:.1f} / 100".format(score),
                          ps("sch"+ip[:6], fontName="Helvetica-Bold", fontSize=10,
                             textColor=vc(eff_v), alignment=TA_RIGHT)),
            ]], colWidths=[W*0.40, W*0.18, W*0.42])
            ip_hdr.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), VBGCOL.get(eff_v, BG_CARD)),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0), (-1,-1), 9),
                ("BOTTOMPADDING", (0,0), (-1,-1), 9),
                ("LEFTPADDING",   (0,0), (-1,-1), 12),
                ("RIGHTPADDING",  (0,0), (-1,-1), 12),
                ("LINEBELOW",     (0,0), (-1,-1), 2, vc(eff_v)),
                ("BOX",           (0,0), (-1,-1), 0.5, vc(eff_v)),
            ]))
            story.append(ip_hdr)
            story.append(Spacer(1, 1*mm))
            story.append(score_bar_drawing(score, width=int(W), height=10))
            story.append(Spacer(1, 2*mm))

            src_rows = [["Source", "Score", "Findings  /  Verification URL"]]
            for s in srcs:
                sc   = round(s.get("score", 0) or 0, 1)
                sign = "+{:.1f}".format(sc) if sc > 0 else "{:.1f}".format(sc)
                scol = SRC_COL.get(s.get("source",""), COL_CYAN)
                lines = [pdf_esc(l) for l in (s.get("ioc") or [])]
                if s.get("error"):
                    lines.insert(0, "ERR: " + pdf_esc(s["error"]))
                if not lines:
                    lines.append("No data returned")
                _url = s.get("url") or _lookup_url(s.get("source",""), ip, "ip")
                if _url:
                    lines.append('<font color="#8b949e">Verify:</font> ' + pdf_link(_url))
                ioc_text = "<br/>".join(lines)
                src_rows.append([
                    Paragraph(pdf_esc(s.get("source","")), ps("srn"+s.get("source","")[:4]+ip[:4],
                                                     fontName="Helvetica-Bold", fontSize=8,
                                                     textColor=scol)),
                    Paragraph(sign + " pts", ps("srs"+ip[:4]+s.get("source","")[:3],
                                                fontName="Helvetica-Bold", fontSize=9,
                                                textColor=COL_RED if sc > 0 else COL_TEXT2,
                                                alignment=TA_CENTER)),
                    Paragraph(ioc_text,
                               ps("sri"+ip[:4]+s.get("source","")[:3], fontSize=7.5,
                                  textColor=COL_TEXT2, leading=11)),
                ])
            src_t = Table(src_rows, colWidths=[W*0.22, W*0.12, W*0.66], repeatRows=1)
            src_t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0), BG_CARD),
                ("TEXTCOLOR",     (0,0), (-1,0), COL_TEXT2),
                ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0), (-1,0), 7.5),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [BG_ROW, BG_CARD]),
                ("ALIGN",         (1,0), (1,-1), "CENTER"),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                ("GRID",          (0,0), (-1,-1), 0.4, COL_BORDER),
            ]))
            story.append(KeepTogether(src_t))
            story.append(Spacer(1, 4*mm))

    # Footer
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=COL_BORDER))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "IP Reputation Investigator  |  Traffic Analysis Report  |  For SOC / Threat Hunting use only.",
        ps("ft", fontSize=6.5, textColor=COL_TEXT2, alignment=TA_CENTER)))

    def dark_bg(canvas, _doc):
        canvas.saveState()
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    buf.seek(0)
    return buf


@app.route("/api/export/traffic/pdf", methods=["POST"])
def export_traffic_pdf():
    try:
        import reportlab  # noqa
    except ImportError:
        return jsonify({"error": "reportlab not installed. Run: pip install reportlab"}), 500
    try:
        payload = request.get_json(force=True)
        buf = build_traffic_pdf(payload)
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True,
                         download_name="traffic_analysis_report.pdf")
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════
#  PCAP ANALYSIS  (pure-Python parser — no scapy/tshark dependency)
# ══════════════════════════════════════════════════════════════════
import struct

PCAP_SUSPICIOUS_PORTS = {
    23:   "Telnet", 445: "SMB", 3389: "RDP", 4444: "Metasploit default",
    1433: "MSSQL", 3306: "MySQL", 5900: "VNC", 6667: "IRC/botnet C2",
    135:  "MS-RPC", 139: "NetBIOS", 21: "FTP", 69: "TFTP",
    5060: "SIP", 25: "SMTP", 8333: "Bitcoin", 9001: "Tor ORPort",
}
PCAP_PORT_NAMES = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 23: "Telnet", 21: "FTP",
    25: "SMTP", 110: "POP3", 143: "IMAP", 445: "SMB", 3389: "RDP",
    3306: "MySQL", 1433: "MSSQL", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    123: "NTP", 161: "SNMP", 389: "LDAP", 636: "LDAPS", 5900: "VNC",
}
TCP_FLAG_BITS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                 (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]


def _tcp_flag_label(flags):
    if flags & 0x02 and not flags & 0x10: return "SYN"
    if flags & 0x02 and flags & 0x10:     return "SYN+ACK"
    if flags & 0x04:                      return "RST" if not flags & 0x10 else "RST+ACK"
    if flags & 0x01:                      return "FIN"
    if flags & 0x08 and flags & 0x10:     return "PSH+ACK"
    if flags & 0x10:                      return "ACK"
    return "OTHER"


def _iter_pcap_packets(data):
    """Yield (ts_float, raw_bytes, orig_len) from classic pcap OR pcapng."""
    if len(data) < 4:
        return
    magic = data[:4]
    # ── classic pcap ──
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                 b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        big    = magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
        nano   = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        e      = ">" if big else "<"
        off    = 24
        div    = 1e9 if nano else 1e6
        while off + 16 <= len(data):
            ts_s, ts_f, incl, orig = struct.unpack(e + "IIII", data[off:off+16])
            off += 16
            if incl > len(data) - off:
                break
            yield ts_s + ts_f / div, data[off:off+incl], orig
            off += incl
        return
    # ── pcapng ──
    if magic == b"\x0a\x0d\x0d\x0a":
        off = 0
        endian = "<"
        if_tsres = []  # per-interface timestamp resolution divisor
        while off + 12 <= len(data):
            btype = struct.unpack(endian + "I", data[off:off+4])[0]
            if btype == 0x0A0D0D0A:  # SHB — re-detect endianness
                bom = data[off+8:off+12]
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                if_tsres = []
                btype = struct.unpack(endian + "I", data[off:off+4])[0]
            blen = struct.unpack(endian + "I", data[off+4:off+8])[0]
            if blen < 12 or off + blen > len(data):
                break
            body = data[off+8:off+blen-4]
            if btype == 0x00000001:  # IDB
                tsres = 1e6
                oo = 8
                while oo + 4 <= len(body):
                    ocode, olen = struct.unpack(endian + "HH", body[oo:oo+4])
                    if ocode == 0:
                        break
                    oval = body[oo+4:oo+4+olen]
                    if ocode == 9 and olen >= 1:  # if_tsresol
                        v = oval[0]
                        tsres = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                    oo += 4 + ((olen + 3) // 4) * 4
                if_tsres.append(tsres)
            elif btype == 0x00000006 and len(body) >= 20:  # EPB
                iface, ts_hi, ts_lo, cap_len, orig = struct.unpack(endian + "IIIII", body[:20])
                res = if_tsres[iface] if iface < len(if_tsres) else 1e6
                ts = ((ts_hi << 32) | ts_lo) / res
                yield ts, body[20:20+cap_len], orig
            off += blen


def _parse_dns_qname(payload, qoff):
    labels, guard = [], 0
    while qoff < len(payload) and guard < 40:
        ln = payload[qoff]
        if ln == 0 or ln >= 0xC0:
            break
        labels.append(payload[qoff+1:qoff+1+ln].decode("ascii", "replace"))
        qoff += 1 + ln
        guard += 1
    return ".".join(labels)


def analyze_pcap(data, filename="capture.pcap"):
    """Full-packet analysis of a pcap/pcapng byte blob → dict for the UI."""
    pkt_count = 0
    total_bytes = 0
    ts_min, ts_max = None, None
    proto_dist   = Counter()
    flag_dist    = Counter()
    src_stats    = defaultdict(lambda: {"packets": 0, "bytes": 0})
    dst_stats    = defaultdict(lambda: {"packets": 0, "bytes": 0})
    dst_ports    = Counter()
    convs        = defaultdict(lambda: {"packets": 0, "bytes": 0, "protos": set()})
    syn_per_src  = Counter()
    synack_seen  = Counter()
    dports_per_src = defaultdict(set)
    dips_per_src   = defaultdict(set)
    dns_queries  = []
    http_requests = []
    truncated    = 0
    non_ip       = 0

    for ts, raw, orig in _iter_pcap_packets(data):
        pkt_count += 1
        total_bytes += orig
        ts_min = ts if ts_min is None else min(ts_min, ts)
        ts_max = ts if ts_max is None else max(ts_max, ts)
        if orig > len(raw):
            truncated += 1
        if len(raw) < 14:
            non_ip += 1
            continue
        eth_type = struct.unpack(">H", raw[12:14])[0]
        off = 14
        if eth_type == 0x8100 and len(raw) >= 18:  # 802.1Q VLAN
            eth_type = struct.unpack(">H", raw[16:18])[0]
            off = 18
        if eth_type == 0x0806:
            proto_dist["ARP"] += 1
            continue
        if eth_type == 0x86DD:  # IPv6 — basic accounting only
            proto_dist["IPv6"] += 1
            continue
        if eth_type != 0x0800 or len(raw) < off + 20:
            non_ip += 1
            proto_dist["Other"] += 1
            continue

        ihl   = (raw[off] & 0x0F) * 4
        proto = raw[off+9]
        src   = ".".join(str(b) for b in raw[off+12:off+16])
        dst   = ".".join(str(b) for b in raw[off+16:off+20])
        l4    = off + ihl

        src_stats[src]["packets"] += 1; src_stats[src]["bytes"] += orig
        dst_stats[dst]["packets"] += 1; dst_stats[dst]["bytes"] += orig
        dips_per_src[src].add(dst)

        if proto == 6 and len(raw) >= l4 + 14:
            proto_dist["TCP"] += 1
            sport, dport = struct.unpack(">HH", raw[l4:l4+4])
            flags = raw[l4+13]
            flag_dist[_tcp_flag_label(flags)] += 1
            dst_ports[dport] += 1
            dports_per_src[src].add(dport)
            if flags & 0x02 and not flags & 0x10:
                syn_per_src[src] += 1
            if flags & 0x02 and flags & 0x10:
                synack_seen[dst] += 1  # dst of SYN+ACK = original SYN sender
            key = (src, dst)
            convs[key]["packets"] += 1; convs[key]["bytes"] += orig
            convs[key]["protos"].add("TCP/" + str(dport))
            # HTTP request sniff
            doff = (raw[l4+12] >> 4) * 4
            payload = raw[l4+doff:]
            if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI"):
                try:
                    head = payload[:512].decode("ascii", "replace")
                    line1 = head.split("\r\n")[0]
                    host  = ""
                    ua    = ""
                    for ln in head.split("\r\n")[1:]:
                        low = ln.lower()
                        if low.startswith("host:"):       host = ln[5:].strip()
                        elif low.startswith("user-agent:"): ua = ln[11:].strip()
                    http_requests.append({"src": src, "dst": dst, "dport": dport,
                                          "request": line1[:200], "host": host[:100],
                                          "user_agent": ua[:150]})
                except Exception:
                    pass
        elif proto == 17 and len(raw) >= l4 + 8:
            proto_dist["UDP"] += 1
            sport, dport = struct.unpack(">HH", raw[l4:l4+4])
            dst_ports[dport] += 1
            dports_per_src[src].add(dport)
            key = (src, dst)
            convs[key]["packets"] += 1; convs[key]["bytes"] += orig
            convs[key]["protos"].add("UDP/" + str(dport))
            if dport == 53 and len(raw) >= l4 + 8 + 12:
                dpl = raw[l4+8:]
                if len(dpl) >= 13 and (dpl[2] & 0x80) == 0:  # query
                    qname = _parse_dns_qname(dpl, 12)
                    if qname:
                        dns_queries.append({"src": src, "query": qname[:150]})
        elif proto == 1:
            proto_dist["ICMP"] += 1
            key = (src, dst)
            convs[key]["packets"] += 1; convs[key]["bytes"] += orig
            convs[key]["protos"].add("ICMP")
        else:
            proto_dist["Other"] += 1

    if pkt_count == 0:
        return {"error": "No packets parsed. File may be corrupt or an unsupported "
                         "format (expected .pcap or .pcapng with Ethernet link type)."}

    duration = round((ts_max - ts_min), 2) if ts_max and ts_min else 0

    # ── Threat indicators ──────────────────────────────────────────
    indicators = []
    score = 0

    def add(sev, typ, detail, pts):
        nonlocal score
        indicators.append({"severity": sev, "type": typ, "detail": detail})
        score += pts

    total_tcp = proto_dist.get("TCP", 0)
    syn_total = flag_dist.get("SYN", 0)
    rst_total = flag_dist.get("RST", 0) + flag_dist.get("RST+ACK", 0)

    # Port scan: one source probing many distinct ports
    for ip, ports in dports_per_src.items():
        if len(ports) >= 10:
            add("HIGH", "PORT_SCAN",
                f"{ip} probed {len(ports)} distinct destination ports — vertical port scan behavior (MITRE T1046).", 30)
        elif len(ports) >= 5:
            add("MEDIUM", "PORT_PROBE",
                f"{ip} contacted {len(ports)} distinct destination ports.", 12)

    # Network sweep: one source hitting many distinct hosts
    for ip, dips in dips_per_src.items():
        if len(dips) >= 10:
            add("HIGH", "NETWORK_SWEEP",
                f"{ip} contacted {len(dips)} distinct hosts — horizontal sweep / lateral-movement recon (MITRE T1018).", 25)

    # SYN flood pattern: many SYNs, few completions
    if total_tcp >= 10 and syn_total >= max(5, total_tcp * 0.5):
        completions = sum(synack_seen.values())
        if completions < syn_total * 0.3:
            add("HIGH", "SYN_FLOOD_PATTERN",
                f"{syn_total} SYN packets vs {completions} SYN+ACK responses — half-open connection pattern consistent with SYN flood or aggressive scanning (MITRE T1499).", 30)

    # High RST ratio — rejected/aborted connections
    if total_tcp >= 10 and rst_total >= total_tcp * 0.3:
        add("MEDIUM", "HIGH_RST_RATIO",
            f"{rst_total}/{total_tcp} TCP packets are RST — connections being rejected or torn down, common during scans and failed exploitation.", 15)

    # Many unique sources hitting one destination (dDoS/scan target)
    top_dst = max(dst_stats.items(), key=lambda kv: kv[1]["packets"]) if dst_stats else None
    uniq_src = len(src_stats)
    if top_dst and uniq_src >= 10:
        dst_share = top_dst[1]["packets"] / pkt_count
        if dst_share >= 0.7:
            add("HIGH", "MANY_TO_ONE",
                f"{uniq_src} distinct sources targeting {top_dst[0]} ({round(dst_share*100)}% of all packets) — distributed scan or DDoS pattern.", 25)

    # Suspicious destination ports
    hit_susp = [(p, c) for p, c in dst_ports.items() if p in PCAP_SUSPICIOUS_PORTS]
    for p, c in sorted(hit_susp, key=lambda x: -x[1])[:5]:
        add("MEDIUM", "SUSPICIOUS_PORT",
            f"Port {p} ({PCAP_SUSPICIOUS_PORTS[p]}) contacted {c} time(s) — commonly abused service port.", 8)

    # DNS anomalies (possible tunneling / DGA)
    long_q = [q for q in dns_queries if len(q["query"]) > 60]
    if long_q:
        add("MEDIUM", "DNS_LONG_QUERY",
            f"{len(long_q)} DNS quer(ies) exceed 60 chars (e.g. {long_q[0]['query'][:60]}…) — possible DNS tunneling/exfiltration (MITRE T1071.004).", 15)

    # Plaintext HTTP with unusual UA
    for h in http_requests:
        ua = h["user_agent"].lower()
        if any(t in ua for t in ("curl", "python", "wget", "nikto", "sqlmap", "masscan", "nmap", "zgrab")):
            add("MEDIUM", "SCANNER_USER_AGENT",
                f"HTTP request from {h['src']} with tool-like User-Agent: {h['user_agent'][:80]}", 10)

    if truncated:
        add("LOW", "TRUNCATED_CAPTURE",
            f"{truncated} packet(s) truncated by snaplen — payload analysis is partial.", 0)

    score = min(score, 100)
    verdict = "ATTACK" if score >= 55 else "SUSPICIOUS" if score >= 30 else "CLEAN"
    confidence = "HIGH" if score >= 70 or score < 15 else "MEDIUM"

    def top_list(stats, n=10):
        rows = sorted(stats.items(), key=lambda kv: -kv[1]["packets"])[:n]
        return [{"ip": ip, "packets": v["packets"], "bytes": v["bytes"],
                 "bytes_fmt": fmt_bytes(v["bytes"])} for ip, v in rows]

    conv_rows = sorted(convs.items(), key=lambda kv: -kv[1]["packets"])[:200]
    conversations = [{"src": k[0], "dst": k[1], "packets": v["packets"],
                      "bytes_fmt": fmt_bytes(v["bytes"]),
                      "protos": sorted(v["protos"])[:6]} for k, v in conv_rows]

    port_rows = dst_ports.most_common(12)
    top_ports = [{"port": p, "name": PCAP_PORT_NAMES.get(p, ""),
                  "count": c, "suspicious": p in PCAP_SUSPICIOUS_PORTS}
                 for p, c in port_rows]

    return {
        "filename": filename,
        "verdict": verdict,
        "attack_score": score,
        "confidence": confidence,
        "indicators": indicators,
        "summary": {
            "total_packets": pkt_count,
            "total_bytes": total_bytes,
            "total_bytes_fmt": fmt_bytes(total_bytes),
            "duration_seconds": duration,
            "start_time": datetime.fromtimestamp(ts_min, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts_min else "-",
            "end_time":   datetime.fromtimestamp(ts_max, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts_max else "-",
            "unique_sources": len(src_stats),
            "unique_destinations": len(dst_stats),
            "avg_pps": round(pkt_count / duration, 1) if duration else pkt_count,
            "truncated_packets": truncated,
        },
        "protocol_dist": dict(proto_dist),
        "flag_dist": dict(flag_dist),
        "top_sources": top_list(src_stats),
        "top_destinations": top_list(dst_stats),
        "top_ports": top_ports,
        "conversations": conversations,
        "dns_queries": dns_queries[:25],
        "http_requests": http_requests[:25],
        "unique_source_ips": sorted(src_stats.keys(),
                                    key=lambda ip: -src_stats[ip]["packets"]),
        # full source list (sorted by packets desc) — feeds the auto-investigation picker
        "all_sources": [{"ip": ip, "packets": v["packets"], "bytes": v["bytes"],
                         "bytes_fmt": fmt_bytes(v["bytes"])}
                        for ip, v in sorted(src_stats.items(),
                                            key=lambda kv: -kv[1]["packets"])],
    }


@app.route("/api/analyze/pcap", methods=["POST"])
def api_analyze_pcap():
    files = request.files.getlist("pcap")
    if not files:
        return jsonify({"error": "No PCAP file uploaded. Send multipart field 'pcap'."}), 400

    results, names, total_size = [], [], 0
    for f in files:
        blob = f.read()
        total_size += len(blob)
        if total_size > 50 * 1024 * 1024:
            return jsonify({"error": "Combined file size too large (max 50 MB)."}), 400
        r = analyze_pcap(blob, f.filename or "capture.pcap")
        if "error" in r:
            return jsonify({"error": f"{f.filename}: {r['error']}"}), 400
        results.append(r)
        names.append(f.filename or "capture.pcap")

    if len(results) == 1:
        out = results[0]
    else:
        # merge: keep highest-scoring file's verdict, concat indicators
        out = max(results, key=lambda r: r["attack_score"])
        seen = set()
        merged_ind = []
        for r in results:
            for ind in r["indicators"]:
                k = (ind["type"], ind["detail"])
                if k not in seen:
                    seen.add(k); merged_ind.append(ind)
        out["indicators"] = merged_ind
    out["merged_files"] = names
    out["file_count"] = len(names)
    return jsonify(out)


if __name__ == "__main__":  # entrypoint
    # Debug (Werkzeug interactive debugger = remote code execution if reachable)
    # is OFF unless NXG_DEBUG=1. Bind to loopback unless NXG_HOST is set —
    # this app has no authentication; put a reverse proxy with TLS + auth in
    # front before exposing it beyond the local machine.
    _debug = os.environ.get("NXG_DEBUG", "0").lower() in ("1", "true", "yes")
    _host  = os.environ.get("NXG_HOST", "127.0.0.1")
    _port  = int(os.environ.get("NXG_PORT", "5000"))
    app.run(debug=_debug, host=_host, port=_port)
