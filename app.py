#!/usr/bin/env python3
"""
IP REPUTATION INVESTIGATOR - Web Application
Flask backend wrapping ip_investigator logic
"""

import json
import os
import re
import sys
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

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
    "abuse_reports_bonus":      5,
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
}

SESSION = req_lib.Session()
SESSION.mount("https://", HTTPAdapter(
    max_retries=Retry(total=3, backoff_factor=0.6, status_forcelist=[429, 500, 502, 503, 504])
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

# ── Validation ────────────────────────────────────────────────────
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

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
        d = resp.json().get("data", {})
        conf   = d.get("abuseConfidenceScore", 0)
        total  = d.get("totalReports", 0)
        is_tor = d.get("isTor", False)
        wl     = d.get("isWhitelisted", False)
        r["ioc"].append("Confidence: {}%  |  Reports: {}  |  Country: {}".format(conf, total, d.get("countryCode", "N/A")))
        r["ioc"].append("ISP: {}  |  Usage: {}".format(d.get("isp", "N/A"), d.get("usageType", "N/A")))
        if wl:
            r["score"] = -10
            r["ioc"].append("Whitelisted (score reduced)")
            return r
        r["score"] += conf * SC["abuse_conf_weight"]
        if total > 10:
            r["score"] += SC["abuse_reports_bonus"]
            r["ioc"].append("High report volume: {}".format(total))
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
        gen = SESSION.get("{}/general".format(base), headers=hdrs, timeout=15).json()
        mal = SESSION.get("{}/malware".format(base), headers=hdrs, timeout=15).json()
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
        gen = SESSION.get("{}/general".format(base), headers=hdrs, timeout=15).json()
        ana = SESSION.get("{}/analysis".format(base), headers=hdrs, timeout=15).json()
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
        if "virustotal" in active_sources and cfg.get("VIRUSTOTAL_KEY"):
            tasks["vt"] = ex.submit(q_vt_hash, h, cfg["VIRUSTOTAL_KEY"])
        if "malwarebazaar" in active_sources:
            tasks["mb"] = ex.submit(q_malwarebazaar, h)
        if "otx" in active_sources and cfg.get("OTX_KEY"):
            tasks["otx"] = ex.submit(q_otx_hash, h, cfg["OTX_KEY"])
        if "hybrid" in active_sources and cfg.get("HA_KEY"):
            tasks["ha"] = ex.submit(q_ha_hash, h, cfg["HA_KEY"])
        results = []
        for k, fut in tasks.items():
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"source": k, "score": 0, "ioc": [], "error": str(e)})
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
    total = min(sum(max(r.get("score", 0), 0) for r in results), 100)
    if total >= 70:
        v = "MALICIOUS"
    elif total >= 45:
        v = "HIGH RISK"
    elif total >= 20:
        v = "SUSPICIOUS"
    else:
        v = "CLEAN"
    return round(total, 1), v

SOURCE_URLS = {
    "AbuseIPDB":       "https://www.abuseipdb.com/check/{ip}",
    "VirusTotal":      "https://www.virustotal.com/gui/ip-address/{ip}",
    "AlienVault OTX":  "https://otx.alienvault.com/indicator/ip/{ip}",
    "Hybrid Analysis": "https://www.hybrid-analysis.com/search?query={ip}&dataType=ip",
    "GreyNoise":       "https://viz.greynoise.io/ip/{ip}",
    "ThreatFox":       "https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}",
    "ip-api":          "https://ip-api.com/#{ip}",
}

ALL_SOURCES = ["abuseipdb", "virustotal", "otx", "hybrid", "greynoise", "ipapi", "threatfox"]

def investigate(ip, cfg, active_sources=None):
    """active_sources: list of source ids to query. None = all configured sources."""
    if active_sources is None:
        active_sources = ALL_SOURCES

    tasks = {}
    with ThreadPoolExecutor(max_workers=7) as ex:
        if "abuseipdb" in active_sources and cfg.get("ABUSEIPDB_KEY"):
            tasks["abuse"] = ex.submit(q_abuse, ip, cfg["ABUSEIPDB_KEY"])
        if "virustotal" in active_sources and cfg.get("VIRUSTOTAL_KEY"):
            tasks["vt"] = ex.submit(q_vt, ip, cfg["VIRUSTOTAL_KEY"])
        if "otx" in active_sources and cfg.get("OTX_KEY"):
            tasks["otx"] = ex.submit(q_otx, ip, cfg["OTX_KEY"])
        if "hybrid" in active_sources and cfg.get("HA_KEY"):
            tasks["ha"] = ex.submit(q_ha, ip, cfg["HA_KEY"])
        if "greynoise" in active_sources and cfg.get("GREYNOISE_KEY"):
            tasks["gn"] = ex.submit(q_greynoise, ip, cfg["GREYNOISE_KEY"])
        if "ipapi" in active_sources:
            tasks["ipapi"] = ex.submit(q_ipapi, ip)
        if "threatfox" in active_sources:
            tasks["threatfox"] = ex.submit(q_threatfox, ip, cfg.get("THREATFOX_KEY", ""))
        results = []
        for k, fut in tasks.items():
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"source": k, "score": 0, "ioc": [], "error": str(e)})
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
CORS(app)

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

@app.route("/api/config", methods=["GET"])
def get_config():
    cfg = load_config()
    # Mask keys for display
    masked = {}
    for k, v in cfg.items():
        if v and len(v) > 8:
            masked[k] = v[:4] + "*" * (len(v) - 8) + v[-4:]
        else:
            masked[k] = "*" * len(v) if v else ""
    return jsonify({"config": masked, "keys_configured": list(cfg.keys())})

@app.route("/api/config", methods=["POST"])
def update_config():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    cfg = load_config()
    allowed = ["ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "OTX_KEY", "HA_KEY", "GREYNOISE_KEY", "THREATFOX_KEY"]
    for k in allowed:
        if k in data and data[k]:
            cfg[k] = data[k]
        elif k in data and data[k] == "":
            cfg.pop(k, None)
    save_config(cfg)
    return jsonify({"success": True, "message": "Configuration saved"})

@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    raw_ips = data.get("ips", [])
    if isinstance(raw_ips, str):
        raw_ips = [x.strip() for x in raw_ips.replace(",", "\n").splitlines() if x.strip()]

    valid_ips = [ip for ip in raw_ips if is_valid_ip(ip)]
    invalid   = [ip for ip in raw_ips if not is_valid_ip(ip)]

    if not valid_ips:
        return jsonify({"error": "No valid IP addresses provided", "invalid": invalid}), 400

    cfg = load_config()
    active_sources = data.get("active_sources", None)  # None = use all configured
    results = []
    for ip in valid_ips:
        result = investigate(ip, cfg, active_sources)
        results.append(result)

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

    valid_ips = [ip for ip in raw_ips if is_valid_ip(ip)]
    invalid   = [ip for ip in raw_ips if not is_valid_ip(ip)]

    if not valid_ips:
        return jsonify({"error": "No valid IP addresses provided"}), 400

    cfg            = load_config()
    active_sources = data.get("active_sources", None)
    total          = len(valid_ips)

    def generate():
        # Send initial metadata
        yield "data: {}\n\n".format(json.dumps({
            "type": "start", "total": total, "invalid": invalid
        }))
        results = []
        for idx, ip in enumerate(valid_ips, 1):
            result = investigate(ip, cfg, active_sources)
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

def build_pdf(results):
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
    story.append(Paragraph("IP REPUTATION INVESTIGATOR",
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
        "Generated: {}   |   Total IPs: {}".format(ts, len(results)),
        ps("meta", fontSize=7, textColor=COL_TEXT2, alignment=TA_CENTER)))
    story.append(Spacer(1, 5*mm))

    # Sort: highest risk first, then by score descending
    _order = {"MALICIOUS": 4, "HIGH RISK": 3, "SUSPICIOUS": 2, "CLEAN": 1}
    results = sorted(results,
                     key=lambda r: (_order.get(r.get("verdict", "CLEAN"), 0), r.get("score", 0)),
                     reverse=True)

    dist = {"MALICIOUS": 0, "HIGH RISK": 0, "SUSPICIOUS": 0, "CLEAN": 0}
    for r in results:
        dist[r.get("verdict", "CLEAN")] = dist.get(r.get("verdict", "CLEAN"), 0) + 1

    sum_data = [
        [Paragraph(k, ps("sk{}".format(i), fontName="Helvetica-Bold", fontSize=8,
                         textColor=vc(k), alignment=TA_CENTER)) for i, k in enumerate(dist)],
        [Paragraph(str(dist[k]), ps("sv{}".format(i), fontName="Helvetica-Bold", fontSize=22,
                                    textColor=vc(k), alignment=TA_CENTER)) for i, k in enumerate(dist)],
    ]
    st = Table(sum_data, colWidths=[W/4]*4, rowHeights=[20, 40])
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

    ov = [["IP Address", "Score  /  Bar", "Verdict", "Timestamp"]]
    cw = [W*0.25, W*0.35, W*0.17, W*0.23]
    for r in results:
        v = r.get("verdict", "CLEAN")
        score_cell = Paragraph(score_bar_text(r["score"]),
                               ps("sc_bar{}".format(r["ip"]), fontName="Helvetica", fontSize=8,
                                  textColor=vc(v), leading=13))
        ov.append([
            Paragraph(r["ip"], ps("ipc{}".format(r["ip"]), fontName="Helvetica-Bold", fontSize=8, textColor=COL_CYAN)),
            score_cell,
            verdict_badge(v, col_w=int(W*0.15)),
            Paragraph(r.get("timestamp", ""), ps("tsc{}".format(r["ip"]), fontSize=7, textColor=COL_TEXT2)),
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
        v = r.get("verdict", "CLEAN")
        ip_hdr = Table([[
            Paragraph(r["ip"], ps("iph"+r["ip"][:6], fontName="Helvetica-Bold", fontSize=13, textColor=COL_CYAN)),
            verdict_badge(v, col_w=int(W*0.20)),
            Paragraph("Score: {:.1f} / 100".format(r["score"]),
                      ps("sch"+r["ip"][:6], fontName="Helvetica-Bold", fontSize=10,
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
        story.append(score_bar_drawing(r["score"], width=int(W), height=14))
        story.append(Spacer(1, 4*mm))

        src_rows = [["Source", "Score", "Findings"]]
        for s in r.get("sources", []):
            sc   = round(s.get("score", 0), 1)
            sign = "+{:.1f}".format(sc) if sc > 0 else "{:.1f}".format(sc)
            scol = SRC_COL.get(s["source"], COL_CYAN)
            ioc_text = "\n".join(s.get("ioc") or [])
            if s.get("error"):
                ioc_text = ("WARNING: " + str(s["error"])) + ("\n" + ioc_text if ioc_text else "")
            if not ioc_text:
                ioc_text = "No data returned"
            src_rows.append([
                Paragraph(s["source"], ps("srn{}".format(s["source"]), fontName="Helvetica-Bold",
                                          fontSize=8, textColor=scol)),
                Paragraph(sign + " pts", ps("srs{}".format(s["source"]), fontName="Helvetica-Bold",
                                             fontSize=9,
                                             textColor=colors.HexColor("#f85149") if sc > 0 else COL_TEXT2,
                                             alignment=TA_CENTER)),
                Paragraph(ioc_text.replace("\n", "<br/>"),
                           ps("sri{}".format(s["source"]), fontSize=7.5, textColor=COL_TEXT2, leading=11)),
            ])
        src_t = Table(src_rows, colWidths=[W*0.26, W*0.14, W*0.60], repeatRows=1)
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
        "IP Reputation Investigator v2.0  |  "
        "AbuseIPDB, VirusTotal, AlienVault OTX, Hybrid Analysis, GreyNoise, ip-api, ThreatFox  |  "
        "For SOC / Threat Hunting use only.",
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
        buf      = build_pdf(data["results"])
        filename = "ip_report_{}.pdf".format(datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
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

    def generate():
        yield "data: {}\n\n".format(json.dumps({"type": "start", "total": total, "invalid": invalid}))
        results = []
        for idx, h in enumerate(valid, 1):
            result = investigate_hash(h, cfg, active_sources)
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
    configured = [k for k in ["ABUSEIPDB_KEY","VIRUSTOTAL_KEY","OTX_KEY","HA_KEY","GREYNOISE_KEY","THREATFOX_KEY"] if cfg.get(k)]
    return jsonify({"status":"ok","sources_configured":len(configured),"sources":configured,
                    "timestamp":datetime.now(timezone.utc).isoformat()})



# ══════════════════════════════════════════════════════════════════
# TRAFFIC CSV ANALYSIS
# ══════════════════════════════════════════════════════════════════

import csv as csv_mod
from collections import Counter, defaultdict

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

def fmt_pkts(p):
    if p >= 1e6: return "{:.2f}M".format(p / 1e6)
    if p >= 1e3: return "{:.1f}K".format(p / 1e3)
    return str(p)

def analyze_traffic_csv(file_content):
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

    return {
        "verdict":      verdict,
        "confidence":   confidence,
        "color":        color,
        "attack_score": attack_score,
        "indicators":   indicators,
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
        "protocol_dist": dict(proto_counter),
        "flag_dist":     dict(flag_counter),
    }


@app.route("/api/analyze/traffic", methods=["POST"])
def api_analyze_traffic():
    f = request.files.get("csv")
    if not f:
        return jsonify({"error": "No CSV file uploaded. Send multipart field 'csv'."}), 400
    content = f.read()
    if len(content) > 10 * 1024 * 1024:
        return jsonify({"error": "File too large (max 10 MB)."}), 400
    result = analyze_traffic_csv(content)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)



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

            src_rows = [["Source", "Score", "Findings"]]
            for s in srcs:
                sc   = round(s.get("score", 0), 1)
                sign = "+{:.1f}".format(sc) if sc > 0 else "0.0"
                scol = SRC_COL.get(s.get("source",""), COL_CYAN)
                ioc_text = "\n".join(s.get("ioc") or [])
                if s.get("error"):
                    ioc_text = ("ERR: " + str(s["error"])) + ("\n" + ioc_text if ioc_text else "")
                if not ioc_text:
                    ioc_text = "No data returned"
                src_rows.append([
                    Paragraph(s.get("source",""), ps("srn"+s.get("source","")[:4]+ip[:4],
                                                     fontName="Helvetica-Bold", fontSize=8,
                                                     textColor=scol)),
                    Paragraph(sign + " pts", ps("srs"+ip[:4]+s.get("source","")[:3],
                                                fontName="Helvetica-Bold", fontSize=9,
                                                textColor=COL_RED if sc > 0 else COL_TEXT2,
                                                alignment=TA_CENTER)),
                    Paragraph(ioc_text.replace("\n", "<br/>"),
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
