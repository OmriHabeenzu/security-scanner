"""
Email Security Analysis with ML-based Phishing Detection and dkimpy DKIM verification.
"""
import re
import os
import numpy as np
import joblib
from app import db
from app.models.scans import EmailScan
from app.utils.email_utils import (
    parse_email_headers, extract_sender_domain,
    check_spf_record, check_dmarc_record
)

# ── ML model loading ───────────────────────────────────────────────────────────
_MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'ml_models')
_email_model = None
_email_scaler = None

def _load_ml_models():
    global _email_model, _email_scaler
    if _email_model is None:
        try:
            _email_model  = joblib.load(os.path.join(_MODEL_DIR, 'email_phishing_model.pkl'))
            _email_scaler = joblib.load(os.path.join(_MODEL_DIR, 'email_feature_scaler.pkl'))
        except Exception as e:
            print(f"[email_scanner] Could not load ML models: {e}")


# ── DKIM verification ──────────────────────────────────────────────────────────
def check_dkim_status(headers, email_text_raw: bytes | None = None):
    """
    Verify DKIM using dkimpy when a DKIM-Signature is present.
    Falls back to Authentication-Results header parsing.
    Returns 'pass', 'fail', or 'none'.
    """
    dkim_sig = headers.get('dkim_signature', '')

    # Try actual cryptographic verification first
    if dkim_sig and email_text_raw:
        try:
            import dkim
            result = dkim.verify(email_text_raw)
            return 'pass' if result else 'fail'
        except Exception:
            pass  # DNS errors, malformed sig, etc. – fall through

    # Fall back: parse Authentication-Results header
    auth_results = headers.get('authentication_results', '').lower()
    if 'dkim=pass' in auth_results:
        return 'pass'
    if 'dkim=fail' in auth_results:
        return 'fail'
    if dkim_sig:
        return 'present'   # signature present but unverified
    return 'none'


# ── Feature extraction ─────────────────────────────────────────────────────────
_FREE_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'protonmail.com', 'icloud.com', 'aol.com', 'mail.com', 'yandex.com'
}

_URGENCY_WORDS  = ['urgent', 'immediately', 'action required', 'asap', 'suspended', 'expires']
_PRIZE_WORDS    = ['won', 'winner', 'prize', 'lottery', 'inheritance', 'reward', 'congratulations']
_VERIFY_WORDS   = ['verify', 'confirm', 'validate', 'authenticate']


def extract_email_features(headers, content_analysis, dkim, spf, dmarc,
                            sender_email, subject):
    """
    Build the 30-element feature vector that matches train_email_phishing_model.py.

    Index reference:
     0  dkim_pass               13 total_links_norm
     1  dkim_fail               14 has_suspicious_link
     2  spf_pass                15 has_crypto_content
     3  dmarc_pass              16 has_credential_request
     4  sender_is_free_email    17 has_money_request
     5  no_return_path          18 scam_indicators_norm
     6  no_message_id           19 legitimate_indicators_norm
     7  subject_has_urgency     20 risk_factors_norm
     8  subject_has_prize       21 has_act_now
     9  subject_has_verify      22 has_html_content
    10  subject_length_norm     23 keyword_count_norm
    11  subject_uppercase_ratio 24 both_auth_fail
    12  suspicious_links_norm   25 has_return_path
                                26 has_valid_message_id
                                27-29 padding
    """
    f = np.zeros(30)

    # Auth
    f[0]  = 1.0 if dkim  == 'pass' else 0.0
    f[1]  = 1.0 if dkim  == 'fail' else 0.0
    f[2]  = 1.0 if spf   == 'pass' else 0.0
    f[3]  = 1.0 if dmarc == 'pass' else 0.0

    # Sender
    domain = extract_sender_domain(sender_email) or ''
    f[4]  = 1.0 if domain.lower() in _FREE_EMAIL_DOMAINS else 0.0

    return_path = headers.get('return_path', '')
    message_id  = headers.get('message_id', '')
    f[5]  = 0.0 if return_path else 1.0   # no_return_path
    f[6]  = 0.0 if message_id  else 1.0   # no_message_id

    # Subject features
    subj_lower = subject.lower()
    f[7]  = 1.0 if any(w in subj_lower for w in _URGENCY_WORDS) else 0.0
    f[8]  = 1.0 if any(w in subj_lower for w in _PRIZE_WORDS)   else 0.0
    f[9]  = 1.0 if any(w in subj_lower for w in _VERIFY_WORDS)  else 0.0
    f[10] = min(len(subject) / 100.0, 1.0)
    upper = sum(1 for c in subject if c.isupper())
    f[11] = upper / len(subject) if subject else 0.0

    # Link features
    susp = len(content_analysis['suspicious_links'])
    total = content_analysis['total_links']
    f[12] = min(susp  / 5.0,  1.0)
    f[13] = min(total / 10.0, 1.0)
    f[14] = 1.0 if susp > 0 else 0.0

    # Content flags
    f[15] = 1.0 if content_analysis.get('has_crypto') else 0.0
    f[16] = 1.0 if content_analysis.get('has_credential_request') else 0.0
    f[17] = 1.0 if content_analysis.get('has_money_request') else 0.0

    # Score norms
    f[18] = min(content_analysis['scam_indicators'] / 5.0, 1.0)
    f[19] = min(content_analysis['legitimate_indicators'] / 5.0, 1.0)
    f[20] = min(len(content_analysis['risk_factors']) / 4.0, 1.0)

    f[21] = 1.0 if content_analysis.get('has_act_now') else 0.0
    f[22] = 1.0 if content_analysis.get('has_html') else 0.0
    f[23] = min(len(content_analysis['top_keywords']) / 5.0, 1.0)

    f[24] = 1.0 if (dkim in ('fail',) and spf == 'fail') else 0.0
    f[25] = 1.0 if return_path  else 0.0
    f[26] = 1.0 if message_id   else 0.0
    # 27-29 stay zero

    return f


def _ml_phishing_score(feature_vec):
    """Return phishing probability 0-100 using the loaded RF model."""
    _load_ml_models()
    if _email_model is None or _email_scaler is None:
        return None
    try:
        scaled = _email_scaler.transform(feature_vec.reshape(1, -1))
        prob = _email_model.predict_proba(scaled)[0][1]  # P(phishing)
        return round(prob * 100, 2)
    except Exception as e:
        print(f"[email_scanner] ML prediction error: {e}")
        return None


# ── Content analysis ───────────────────────────────────────────────────────────
def analyze_email_content_advanced(email_text, headers):
    email_lower = email_text.lower()

    body_start = email_text.find('\n\n')
    email_body = email_text[body_start:] if body_start > 0 else email_text
    email_body_lower = email_body.lower()

    analysis = {
        'suspicious_links': [],
        'all_links': [],
        'total_links': 0,
        'top_keywords': [],
        'risk_factors': [],
        'scam_indicators': 0,
        'legitimate_indicators': 0,
        'has_crypto': False,
        'has_credential_request': False,
        'has_money_request': False,
        'has_act_now': False,
        'has_html': False,
    }

    # Detect HTML
    analysis['has_html'] = bool(re.search(r'<html|<body|<div|<table', email_body_lower))

    # Sender / envelope mismatch (From: domain ≠ Sender: / Return-Path: domain)
    from_addr   = headers.get('from', '')
    sender_addr = headers.get('return_path', '') or headers.get('sender', '')
    from_domain   = extract_sender_domain(from_addr) or ''
    sender_domain_val = extract_sender_domain(sender_addr) or ''
    if from_domain and sender_domain_val and from_domain.lower() != sender_domain_val.lower():
        analysis['risk_factors'].append(
            f'From domain ({from_domain}) does not match envelope sender ({sender_domain_val})'
        )
        analysis['scam_indicators'] += 2

    # Link extraction
    all_links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_body, re.IGNORECASE)
    unique_links = list(set(link.strip('.,;:()[]{}') for link in all_links))
    analysis['all_links'] = unique_links
    analysis['total_links'] = len(unique_links)

    known_safe = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'github.com', 'linkedin.com', 'facebook.com', 'twitter.com',
        'gov.', 'edu', '.ac.', 'wikipedia.org', 'office.com'
    ]
    for link in unique_links:
        link_lower = link.lower()
        is_safe = any(domain in link_lower for domain in known_safe)
        if not is_safe:
            if (re.search(r'\d{1,3}(?:\.\d{1,3}){3}', link) or
                    any(w in link_lower for w in ['bit.ly', 'tinyurl', 'login', 'verify',
                                                   'secure', 'wallet', 'crypto']) or
                    link_lower.count('-') > 4):
                analysis['suspicious_links'].append(link)

    # Scam patterns
    crypto_scam = (
        all(w in email_body_lower for w in ['btc', 'wallet']) or
        all(w in email_body_lower for w in ['bitcoin', 'transfer'])
    )
    credential_harvest = (
        all(w in email_body_lower for w in ['customer id', 'password']) or
        all(w in email_body_lower for w in ['username', 'login'])
    )
    advance_fee = (
        all(w in email_body_lower for w in ['fee', 'pay', 'release', 'funds']) or
        all(w in email_body_lower for w in ['won', 'prize', 'claim'])
    )
    money_request = any(w in email_body_lower for w in ['send money', 'wire transfer', 'bank transfer'])

    income_scam = (
        any(w in email_body_lower for w in ['automate your income', 'passive income',
                                             'make money online', 'earn from home']) or
        (any(w in email_body_lower for w in ['$1,000', '$2,000', '$3,000', '$5,000', '$10,000'])
         and any(w in email_body_lower for w in ['monthly', 'weekly', 'per month', 'per week']))
    )
    if income_scam:
        analysis['risk_factors'].append('Passive income / get-rich-quick scam pattern detected')
        analysis['scam_indicators'] += 3
        analysis['has_money_request'] = True

    if crypto_scam:
        analysis['risk_factors'].append('Cryptocurrency scam pattern detected')
        analysis['scam_indicators'] += 3
        analysis['has_crypto'] = True

    if credential_harvest:
        analysis['risk_factors'].append('Credential harvesting pattern detected')
        analysis['scam_indicators'] += 3
        analysis['has_credential_request'] = True

    if advance_fee:
        analysis['risk_factors'].append('Advance fee scam pattern detected')
        analysis['scam_indicators'] += 2
        analysis['has_money_request'] = True

    if money_request:
        analysis['has_money_request'] = True

    # High-risk keyword scoring
    main_body = email_body_lower[:1500]
    high_risk = {
        # Classic phishing
        'verify your account': 40, 'suspended': 35, 'unusual activity': 35,
        'customer id': 30, 'password': 25, 'btc': 30, 'bitcoin': 30,
        'wallet': 25, 'urgent action': 25, 'click here immediately': 25,
        'limited time': 20, 'confirm your identity': 20,
        # Income / passive-income scams
        'automate your income': 35, 'passive income': 30, 'make money online': 30,
        'earn from home': 28, 'work from home': 20, 'monthly without': 28,
        'direct payments': 25, 'free lifetime': 28, 'heavy lifting': 22,
        'ready-made': 20, 'generates all your': 30, 'no need for selling': 30,
        'without the need for selling': 35, 'ai system': 18,
        '$1,000': 20, '$2,000': 22, '$3,000': 25, '$5,000': 28, '$10,000': 30,
        'per month': 18, 'weekly earnings': 25, 'income stream': 22,
    }
    found_keywords = {}
    for keyword, weight in high_risk.items():
        if keyword in main_body:
            pos = main_body.find(keyword)
            ctx = main_body[max(0, pos - 100):pos + 100]
            if any(safe in ctx for safe in ['disclaimer', 'confidential', 'legal', 'unsubscribe']):
                weight //= 4
            if weight > 10:
                found_keywords[keyword] = weight

    analysis['top_keywords'] = sorted(found_keywords, key=lambda k: found_keywords[k], reverse=True)

    # Legitimate indicators
    legit_words = ['meeting', 'report', 'project', 'team', 'schedule',
                   'invoice', 'receipt', 'order', 'delivery', 'shipment']
    analysis['legitimate_indicators'] = sum(1 for w in legit_words if w in email_body_lower)

    # Additional risk factors
    if re.search(r'act (now|immediately|within \d+ hours)', email_body_lower):
        analysis['risk_factors'].append('Urgent action required')
        analysis['has_act_now'] = True

    if any(w in email_body_lower for w in ['won', 'winner', 'prize', 'lottery', 'inheritance']):
        analysis['risk_factors'].append('Too-good-to-be-true offer')

    return analysis


# ── Heuristic fallback score ───────────────────────────────────────────────────
def calculate_intelligent_phishing_score(dkim, spf, dmarc, content, sender, subject):
    score = 0.0
    auth_pass = 0

    if dkim == 'fail':    score += 12
    elif dkim == 'none':  score += 5
    elif dkim == 'pass':  auth_pass += 1

    if spf == 'fail':     score += 12
    elif spf == 'none':   score += 5
    elif spf == 'pass':   auth_pass += 1

    if dmarc == 'fail':   score += 8
    elif dmarc == 'none': score += 3

    if auth_pass >= 2:
        score -= 10

    score += min(content['scam_indicators'] * 15, 50)

    kw = len(content['top_keywords'])
    if kw >= 5:   score += 25
    elif kw >= 3: score += 15
    elif kw >= 1: score += 8

    susp = len(content['suspicious_links'])
    if susp >= 3:   score += 20
    elif susp >= 1: score += 10

    score += min(len(content['risk_factors']) * 5, 15)

    if content['legitimate_indicators'] >= 3:
        score *= 0.6
    elif content['legitimate_indicators'] >= 2:
        score *= 0.8

    subj_lower = subject.lower()
    if any(w in subj_lower for w in ['urgent', 'suspended', 'verify', 'action required']):
        score += 5

    return max(0, min(100, score))


# ── Body link scanner ──────────────────────────────────────────────────────────
def _scan_body_links(links: list, max_links: int = 5) -> list:
    """
    Scan up to max_links URLs from the email body using the URL scanner.
    Returns list of result dicts for each scanned URL.
    """
    if not links:
        return []
    try:
        from app.utils.url_scanner import scan_url
    except Exception:
        return []

    results = []
    for link in links[:max_links]:
        try:
            r = scan_url(link)
            if r.get('success'):
                results.append({
                    'url': link,
                    'is_malicious': r.get('is_malicious', False),
                    'threat_type': r.get('threat_type', 'Unknown'),
                    'threat_score': r.get('threat_score', 0),
                })
        except Exception:
            pass
    return results


# ── Public API ─────────────────────────────────────────────────────────────────
def scan_email(email_text, user=None):
    """
    Analyze email with ML-based phishing detection.
    Falls back to heuristic scoring when model is unavailable.
    """
    try:
        headers = parse_email_headers(email_text)
        if not headers:
            return {'success': False, 'error': 'Could not parse email headers'}

        sender_email = headers.get('from', 'Unknown')
        subject      = headers.get('subject', 'No Subject')
        sender_domain = extract_sender_domain(sender_email)

        # DKIM – try dkimpy with raw bytes
        raw_bytes = email_text.encode('utf-8', errors='replace')
        auth_hdr = headers.get('authentication_results', '')
        dkim_status  = check_dkim_status(headers, raw_bytes)
        spf_status   = check_spf_record(sender_domain, auth_hdr)   if sender_domain else 'none'
        dmarc_status = check_dmarc_record(sender_domain, auth_hdr)  if sender_domain else 'none'

        content_analysis = analyze_email_content_advanced(email_text, headers)

        # ── Body link scanning via URL scanner ─────────────────────────────────
        body_url_results = _scan_body_links(content_analysis.get('all_links', []))
        malicious_body_urls = [r for r in body_url_results if r.get('is_malicious')]
        if malicious_body_urls:
            for r in malicious_body_urls:
                content_analysis['risk_factors'].append(
                    f'Malicious URL in body: {r["url"]} ({r["threat_type"]})'
                )
            content_analysis['scam_indicators'] += len(malicious_body_urls) * 2

        # ML prediction
        feature_vec  = extract_email_features(
            headers, content_analysis, dkim_status, spf_status, dmarc_status,
            sender_email, subject
        )
        ml_score = _ml_phishing_score(feature_vec)

        if ml_score is not None:
            phishing_score = ml_score
        else:
            phishing_score = calculate_intelligent_phishing_score(
                dkim_status, spf_status, dmarc_status,
                content_analysis, sender_email, subject
            )

        is_phishing = phishing_score > 60

        scan_record = None
        if user:
            scan_record = EmailScan(
                user_id=user.id,
                sender_email=sender_email[:255],
                subject=subject[:500],
                dkim_status=dkim_status,
                spf_status=spf_status,
                dmarc_status=dmarc_status,
                phishing_score=phishing_score,
                is_phishing=is_phishing,
                suspicious_links=len(content_analysis['suspicious_links'])
            )
            db.session.add(scan_record)
            db.session.commit()

        return {
            'success': True,
            'sender_email': sender_email,
            'subject': subject,
            'dkim_status': dkim_status,
            'spf_status': spf_status,
            'dmarc_status': dmarc_status,
            'phishing_score': round(phishing_score, 2),
            'is_phishing': is_phishing,
            'suspicious_links': len(content_analysis['suspicious_links']),
            'suspicious_keywords': content_analysis['top_keywords'][:5],
            'total_links': content_analysis['total_links'],
            'risk_factors': content_analysis['risk_factors'],
            'body_url_scan': body_url_results,
            'scan_id': scan_record.id if scan_record else None
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}
