"""
URL scanning — multi-layer threat detection:

  Layer 1  Google Safe Browsing API v4    (known malware/phishing)
  Layer 2  URLhaus (Abuse.ch)             (active malware URLs, no key needed)
  Layer 3  Redirect chain resolution      (unshorten bit.ly, follow redirects)
  Layer 4  Domain age (WHOIS)             (newly registered = high risk)
  Layer 5  Suspicious TLD list            (free/abused TLDs)
  Layer 6  Local heuristics              (patterns, keywords, IP URLs)
"""

import re
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

from app import db
from app.models.scans import URLScan
from app.utils.url_ip_utils import (
    validate_url, extract_domain_from_url,
    is_url_suspicious, is_https
)

# ── High-risk TLDs ─────────────────────────────────────────────────────────────
HIGH_RISK_TLDS = {
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click',
    '.loan', '.work', '.date', '.download', '.racing', '.win',
    '.bid', '.stream', '.trade', '.accountant', '.science', '.faith',
    '.review', '.party', '.cricket', '.space', '.webcam', '.gdn',
    '.country', '.kim', '.men', '.pw', '.link',
}

# ── Lookalike brand detection ──────────────────────────────────────────────────
_KNOWN_BRANDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
    'facebook', 'instagram', 'twitter', 'bankofamerica', 'chase',
    'wellsfargo', 'dropbox', 'linkedin', 'whatsapp', 'icloud',
    'outlook', 'office365', 'docusign', 'fedex', 'ups', 'dhl',
]


def _is_lookalike_domain(domain: str) -> str | None:
    """Return the brand name if domain looks like a spoofed brand, else None."""
    domain_lower = domain.lower()
    # Strip port
    domain_lower = domain_lower.split(':')[0]
    # Get base label (no TLD)
    parts = domain_lower.split('.')
    base = parts[0] if len(parts) >= 2 else domain_lower

    for brand in _KNOWN_BRANDS:
        if brand == base:
            continue  # exact match = probably real
        # Contains brand + extra chars (paypal-secure, amazon-login, etc.)
        if brand in base and len(base) > len(brand):
            return brand
        # Levenshtein distance ≤ 2 (e.g. "paypa1", "arnazon")
        if _levenshtein(base, brand) <= 2 and len(base) >= len(brand) - 1:
            return brand
    return None


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        new_row = [i + 1]
        for j, cb in enumerate(b):
            new_row.append(min(row[j + 1] + 1, new_row[j] + 1,
                               row[j] + (ca != cb)))
        row = new_row
    return row[-1]


# ── Redirect resolution ────────────────────────────────────────────────────────
def _resolve_final_url(url: str, timeout: int = 5) -> tuple[str, list[str]]:
    """Follow redirect chain, return (final_url, list_of_hops)."""
    hops = []
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout,
                          headers={'User-Agent': 'Mozilla/5.0'})
        current = url
        for resp in r.history:
            loc = resp.headers.get('Location', '')
            if loc and loc != current:
                hops.append(loc)
                current = loc
        final = r.url
        if final != url:
            hops.append(final)
        return final, hops
    except Exception:
        return url, []


# ── URLhaus check ──────────────────────────────────────────────────────────────
def _check_urlhaus(url: str) -> dict:
    """Query URLhaus (Abuse.ch) — free, no API key required."""
    try:
        r = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            status = data.get('query_status', '')
            if status == 'is_phishing':
                return {'found': True, 'verdict': 'phishing', 'tags': data.get('tags', [])}
            if status in ('is_malware', 'online', 'offline') and data.get('threat'):
                return {'found': True, 'verdict': data['threat'], 'tags': data.get('tags', [])}
            if status == 'no_results':
                return {'found': False}
    except Exception as e:
        print(f'[URLhaus] {e}')
    return {'found': False}


# ── Domain age ────────────────────────────────────────────────────────────────
def _domain_age_days(domain: str) -> int | None:
    """Return domain age in days, or None if WHOIS fails."""
    try:
        import whois
        # Strip port and www
        base = domain.lower().split(':')[0]
        if base.startswith('www.'):
            base = base[4:]
        w = whois.whois(base)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).days
            return max(age, 0)
    except Exception:
        pass
    return None


# ── Google Safe Browsing ──────────────────────────────────────────────────────
def check_url_with_api(url: str) -> dict:
    from flask import current_app
    api_key = current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
    if not api_key:
        return {'status': 'not_configured', 'is_safe': True, 'threats': []}

    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
    payload = {
        'client': {'clientId': 'securecheck-scanner', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING',
                            'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=10)
        if resp.status_code == 200:
            matches = resp.json().get('matches', [])
            if matches:
                threat_type = matches[0].get('threatType', 'MALWARE')
                type_map = {
                    'MALWARE': 'malware',
                    'SOCIAL_ENGINEERING': 'phishing',
                    'UNWANTED_SOFTWARE': 'unwanted_software',
                    'POTENTIALLY_HARMFUL_APPLICATION': 'harmful_app'
                }
                return {'status': type_map.get(threat_type, 'unsafe'),
                        'is_safe': False, 'threats': matches}
            return {'status': 'safe', 'is_safe': True, 'threats': []}
        elif resp.status_code == 403:
            print('[GSB] Invalid API key or quota exceeded')
    except Exception as e:
        print(f'[GSB] {e}')
    return {'status': 'error', 'is_safe': True, 'threats': []}


# ── Threat score ──────────────────────────────────────────────────────────────
def _calculate_threat_score(indicators: list[str], uses_https: bool,
                             gsb: dict, urlhaus: dict,
                             domain_age: int | None, tld_risky: bool,
                             lookalike: str | None, redirected: bool) -> float:
    score = 0.0

    # Definitive external verdicts
    gsb_status = gsb.get('status', '').lower()
    if gsb_status in ('phishing', 'malware', 'unsafe', 'unwanted_software', 'harmful_app'):
        score += 0.55
    elif gsb_status == 'suspicious':
        score += 0.25

    if urlhaus.get('found'):
        score += 0.50

    # Domain age
    if domain_age is not None:
        if domain_age < 7:
            score += 0.30
        elif domain_age < 30:
            score += 0.20
        elif domain_age < 90:
            score += 0.10

    # Lookalike brand spoofing
    if lookalike:
        score += 0.35

    # Risky TLD
    if tld_risky:
        score += 0.15

    # Redirect chain (shortener resolves to something suspicious)
    if redirected and indicators:
        score += 0.10

    # No HTTPS
    if not uses_https:
        score += 0.10

    # Local pattern indicators
    score += min(len(indicators) * 0.08, 0.25)

    return max(0.0, min(score, 1.0))


def _determine_threat_type(indicators: list[str], gsb: dict,
                            urlhaus: dict, lookalike: str | None) -> str:
    if urlhaus.get('found'):
        verdict = urlhaus.get('verdict', 'malware')
        return 'Phishing' if 'phish' in verdict.lower() else 'Malware Distribution'
    gsb_status = gsb.get('status', '').lower()
    if gsb_status in ('phishing', 'social_engineering'):
        return 'Phishing'
    if gsb_status == 'malware':
        return 'Malware Distribution'
    if gsb_status in ('unwanted_software', 'harmful_app'):
        return 'Unwanted Software'
    if lookalike:
        return f'Brand Spoofing ({lookalike.capitalize()})'
    if 'shortener' in str(indicators).lower():
        return 'URL Shortener / Redirect'
    if indicators:
        return 'Suspicious Pattern'
    return 'Safe'


# ── Public API ────────────────────────────────────────────────────────────────
def scan_url(url: str, user=None) -> dict:
    """
    Scan a URL through all detection layers.
    Returns: dict with scan results.
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        if not validate_url(url):
            return {'success': False, 'error': 'Invalid URL format'}

        domain     = extract_domain_from_url(url)
        uses_https = is_https(url)

        # Layer 3: resolve redirects first (so we scan the real destination)
        final_url, redirect_hops = _resolve_final_url(url)
        scanned_url = final_url if final_url != url else url
        scanned_domain = extract_domain_from_url(scanned_url) or domain
        redirected = len(redirect_hops) > 0

        # Layer 6: local heuristics (run on final URL)
        is_suspicious, indicators = is_url_suspicious(scanned_url)

        # TLD risk
        tld = '.' + scanned_domain.rsplit('.', 1)[-1].lower() if '.' in scanned_domain else ''
        tld_risky = tld in HIGH_RISK_TLDS
        if tld_risky:
            indicators.append(f'High-risk TLD: {tld}')

        # Lookalike detection
        lookalike = _is_lookalike_domain(scanned_domain)
        if lookalike:
            indicators.append(f'Possible brand spoofing: looks like {lookalike.capitalize()}')

        # Layer 1: Google Safe Browsing
        gsb = check_url_with_api(scanned_url)

        # Layer 2: URLhaus
        urlhaus = _check_urlhaus(scanned_url)
        if urlhaus.get('found'):
            indicators.append(f'Listed in URLhaus malware database')

        # Layer 4: domain age
        domain_age = _domain_age_days(scanned_domain)
        if domain_age is not None and domain_age < 30:
            indicators.append(f'Newly registered domain ({domain_age} days old)')

        # Redirect info
        if redirect_hops:
            indicators.append(f'Redirected through {len(redirect_hops)} hop(s) → {scanned_domain}')

        # Score and verdict
        threat_score = _calculate_threat_score(
            indicators, uses_https, gsb, urlhaus,
            domain_age, tld_risky, lookalike, redirected
        )
        is_malicious  = threat_score > 0.55
        threat_type   = _determine_threat_type(indicators, gsb, urlhaus, lookalike)

        # Persist
        scan_record = None
        if user:
            scan_record = URLScan(
                user_id=user.id,
                url=url[:2000],
                domain=domain[:255] if domain else 'Unknown',
                is_malicious=is_malicious,
                threat_type=threat_type,
                reputation_score=threat_score,
                google_safe_browsing=gsb.get('status', 'unknown')
            )
            db.session.add(scan_record)
            db.session.commit()

        return {
            'success'              : True,
            'url'                  : url,
            'final_url'            : scanned_url if redirected else url,
            'domain'               : domain,
            'is_malicious'         : is_malicious,
            'threat_type'          : threat_type,
            'threat_score'         : round(threat_score * 100, 2),
            'uses_https'           : uses_https,
            'suspicious_indicators': indicators,
            'api_status'           : gsb.get('status', 'Not checked'),
            'urlhaus_status'       : 'found' if urlhaus.get('found') else 'clean',
            'domain_age_days'      : domain_age,
            'redirected'           : redirected,
            'scan_id'              : scan_record.id if scan_record else None,
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}
