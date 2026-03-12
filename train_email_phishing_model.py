"""
Train ML model for email phishing detection.

Data sources (in order of priority):
  1. SpamAssassin Public Corpus (real labeled emails — spam + ham)
     Downloaded automatically from: https://spamassassin.apache.org/old/publiccorpus/
  2. Synthetic feature vectors (fallback if download fails, or mixed in for
     auth-state coverage since SpamAssassin emails predate DKIM/SPF/DMARC)

Three Scikit-learn classifiers are trained and compared:
  - Random Forest  (ensemble, robust to noise)
  - SVM            (effective margin-based classifier)
  - Decision Tree  (interpretable baseline)

The best-performing model (by test accuracy) is saved.

Feature vectors mirror extract_email_features() in email_scanner.py exactly.

Feature index reference:
  0:  dkim_pass            10: subject_length_norm     20: risk_factors_norm
  1:  dkim_fail            11: subject_uppercase_ratio 21: has_act_now
  2:  spf_pass             12: suspicious_links_norm   22: has_html_content
  3:  dmarc_pass           13: total_links_norm        23: keyword_count_norm
  4:  sender_is_free_email 14: has_suspicious_link     24: both_auth_fail
  5:  no_return_path       15: has_crypto_content      25: has_return_path
  6:  no_message_id        16: has_credential_request  26: has_valid_message_id
  7:  subject_has_urgency  17: has_money_request       27-29: padding zeros
  8:  subject_has_prize    18: scam_indicators_norm
  9:  subject_has_verify   19: legitimate_indicators_norm

Saves:
  ml_models/email_phishing_model.pkl
  ml_models/email_feature_scaler.pkl
"""

import re
import os
import io
import email as email_lib
import urllib.request
import tarfile
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

N_FEATURES = 30
rng = np.random.default_rng(42)

# ── Constants matching email_scanner.py ───────────────────────────────────────
_FREE_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'protonmail.com', 'icloud.com', 'aol.com', 'mail.com', 'yandex.com',
    'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'msn.com', 'live.com',
    'me.com', 'mac.com', 'inbox.com', 'gmx.com', 'gmx.net',
}
_URGENCY_WORDS  = ['urgent', 'immediately', 'action required', 'asap',
                   'suspended', 'expires', 'last chance', 'final notice']
_PRIZE_WORDS    = ['won', 'winner', 'prize', 'lottery', 'inheritance',
                   'reward', 'congratulations', 'selected', 'lucky']
_VERIFY_WORDS   = ['verify', 'confirm', 'validate', 'authenticate', 'update your']

_SCAM_KEYWORDS = {
    'verify your account', 'suspended', 'unusual activity', 'customer id',
    'password', 'btc', 'bitcoin', 'wallet', 'urgent action',
    'click here immediately', 'limited time', 'confirm your identity',
    'automate your income', 'passive income', 'make money online',
    'earn from home', 'work from home', 'direct payments', 'free lifetime',
    'generates all your', 'no need for selling', '$1,000', '$2,000',
    '$3,000', '$5,000', '$10,000', 'wire transfer', 'bank transfer',
    'send money', 'western union', 'moneygram', 'dear friend', 'dear beneficiary',
    'next of kin', 'inheritance fund', 'nigerian', 'transfer of funds',
    'click here to login', 'your account will be closed', 'verify your email',
}
_LEGIT_KEYWORDS = {
    'meeting', 'report', 'project', 'team', 'schedule',
    'invoice', 'receipt', 'order', 'delivery', 'shipment',
    'attached', 'please find', 'regards', 'sincerely', 'best regards',
    'unsubscribe', 'privacy policy', 'terms of service',
}
_SUSPICIOUS_LINK_WORDS = {'bit.ly', 'tinyurl', 'login', 'verify',
                           'secure', 'wallet', 'crypto', 'update',
                           'confirm', 'account'}


# ── Feature extraction from a real parsed email ───────────────────────────────

def _extract_domain(addr: str) -> str:
    m = re.search(r'@([\w.-]+)', addr)
    return m.group(1).lower() if m else ''


def _parse_auth_results(hdr: str) -> dict:
    h = hdr.lower()
    result = {}
    for proto in ('dkim', 'spf', 'dmarc'):
        m = re.search(rf'{proto}=(pass|fail|neutral|softfail|none|temperror|permerror)', h)
        if m:
            v = m.group(1)
            result[proto] = 'pass' if v == 'pass' else ('fail' if v in ('fail','softfail','neutral') else 'none')
        else:
            result[proto] = 'none'
    return result


def features_from_parsed_email(msg) -> np.ndarray:
    """
    Build the 30-element feature vector from a parsed email.Message object.
    """
    f = np.zeros(N_FEATURES)

    from_addr      = msg.get('From', '')
    return_path    = msg.get('Return-Path', '')
    message_id     = msg.get('Message-ID', '')
    subject        = msg.get('Subject', '') or ''
    auth_results   = msg.get('Authentication-Results', '') or ''
    dkim_signature = msg.get('DKIM-Signature', '') or ''

    # Auth
    auth = _parse_auth_results(auth_results)
    dkim_from_auth = auth.get('dkim', 'none')

    if dkim_signature and dkim_from_auth == 'none':
        dkim_from_auth = 'present'

    f[0] = 1.0 if dkim_from_auth == 'pass' else 0.0
    f[1] = 1.0 if dkim_from_auth == 'fail' else 0.0
    f[2] = 1.0 if auth.get('spf') == 'pass' else 0.0
    f[3] = 1.0 if auth.get('dmarc') == 'pass' else 0.0

    # Sender
    domain = _extract_domain(from_addr)
    f[4] = 1.0 if domain in _FREE_EMAIL_DOMAINS else 0.0
    f[5] = 0.0 if return_path.strip('<> ') else 1.0   # no_return_path
    f[6] = 0.0 if message_id else 1.0                 # no_message_id

    # Subject
    subj_lower = subject.lower()
    decoded_subj = _decode_header(subject)
    subj_lower = decoded_subj.lower()

    f[7]  = 1.0 if any(w in subj_lower for w in _URGENCY_WORDS) else 0.0
    f[8]  = 1.0 if any(w in subj_lower for w in _PRIZE_WORDS)   else 0.0
    f[9]  = 1.0 if any(w in subj_lower for w in _VERIFY_WORDS)  else 0.0
    f[10] = min(len(decoded_subj) / 100.0, 1.0)
    upper = sum(1 for c in decoded_subj if c.isupper())
    f[11] = upper / len(decoded_subj) if decoded_subj else 0.0

    # Body
    body = _get_body(msg)
    body_lower = body.lower()

    # Links
    links = list(set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body, re.IGNORECASE)))
    links = [l.strip('.,;:()[]{}') for l in links]
    susp_links = [l for l in links if any(w in l.lower() for w in _SUSPICIOUS_LINK_WORDS)]

    f[12] = min(len(susp_links) / 5.0, 1.0)
    f[13] = min(len(links) / 10.0, 1.0)
    f[14] = 1.0 if susp_links else 0.0

    # Content flags
    has_crypto     = any(w in body_lower for w in ('bitcoin', 'btc', 'ethereum', 'crypto wallet'))
    has_credential = any(w in body_lower for w in ('customer id', 'password', 'username', 'login'))
    has_money      = any(w in body_lower for w in ('wire transfer', 'bank transfer', 'send money', 'western union'))
    has_act_now    = bool(re.search(r'act (now|immediately|within \d+ hours)', body_lower))
    has_html       = bool(re.search(r'<html|<body|<div|<table', body_lower))

    f[15] = 1.0 if has_crypto else 0.0
    f[16] = 1.0 if has_credential else 0.0
    f[17] = 1.0 if has_money else 0.0

    # Scam / legit indicators
    scam_count  = sum(1 for kw in _SCAM_KEYWORDS  if kw in body_lower)
    legit_count = sum(1 for kw in _LEGIT_KEYWORDS if kw in body_lower)

    f[18] = min(scam_count  / 5.0, 1.0)
    f[19] = min(legit_count / 5.0, 1.0)

    # Risk factors count (approximate from available signals)
    risk_count = (
        (1 if f[1] else 0) +          # dkim fail
        (1 if f[5] else 0) +          # no return path
        (1 if susp_links else 0) +
        (1 if has_crypto or has_money else 0)
    )
    f[20] = min(risk_count / 4.0, 1.0)

    f[21] = 1.0 if has_act_now else 0.0
    f[22] = 1.0 if has_html else 0.0

    kw_count = sum(1 for kw in _SCAM_KEYWORDS if kw in body_lower[:1500])
    f[23] = min(kw_count / 5.0, 1.0)

    f[24] = 1.0 if (f[1] and not f[2]) else 0.0   # both_auth_fail (dkim fail + spf none/fail)
    f[25] = 1.0 if return_path.strip('<> ') else 0.0
    f[26] = 1.0 if message_id else 0.0
    # 27-29 stay zero

    return f


def _decode_header(value: str) -> str:
    """Best-effort decode of RFC 2047 encoded header."""
    try:
        from email.header import decode_header
        parts = decode_header(value)
        decoded = []
        for part, enc in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(enc or 'utf-8', errors='replace'))
            else:
                decoded.append(str(part))
        return ' '.join(decoded)
    except Exception:
        return value or ''


def _get_body(msg) -> str:
    """Extract plaintext + HTML body from a parsed email.Message."""
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ('text/plain', 'text/html'):
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    body += payload.decode(charset, errors='replace')
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='replace')
            else:
                body = str(msg.get_payload())
        except Exception:
            body = str(msg.get_payload())
    return body


# ── SpamAssassin corpus download ───────────────────────────────────────────────

SA_CORPUS = [
    # (url, label)  label: 1=spam/phishing, 0=ham/legit
    ('https://spamassassin.apache.org/old/publiccorpus/20021010_spam.tar.bz2',     1),
    ('https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2',     1),
    ('https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2',   1),
    ('https://spamassassin.apache.org/old/publiccorpus/20021010_easy_ham.tar.bz2', 0),
    ('https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2', 0),
    ('https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2', 0),
]


def _download_and_parse(url: str, label: int, max_emails: int = 800):
    """Download a tar.bz2 SpamAssassin corpus and extract features."""
    print(f"  Downloading {url.split('/')[-1]} ...")
    X, y = [], []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:bz2') as tar:
            members = [m for m in tar.getmembers() if m.isfile()]
            rng_idx = np.random.default_rng(42)
            rng_idx.shuffle(members)
            count = 0
            for member in members:
                if count >= max_emails:
                    break
                try:
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    raw = f.read()
                    msg = email_lib.message_from_bytes(raw)
                    feat = features_from_parsed_email(msg)
                    X.append(feat)
                    y.append(label)
                    count += 1
                except Exception:
                    pass
        print(f"    -> {count} emails parsed")
    except Exception as e:
        print(f"    FAILED: {e}")
    return X, y


def load_spamassassin_data(max_per_file: int = 800):
    """Download and parse all SpamAssassin corpus files."""
    X_all, y_all = [], []
    for url, label in SA_CORPUS:
        X, y = _download_and_parse(url, label, max_per_file)
        X_all.extend(X)
        y_all.extend(y)
    if X_all:
        return np.array(X_all), np.array(y_all)
    return np.empty((0, N_FEATURES)), np.empty(0)


# ── Synthetic generators (auth-state coverage) ────────────────────────────────

def _zero():
    return np.zeros(N_FEATURES)


def gen_credential_phishing(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 0
        f[1]  = rng.choice([0, 1], p=[0.25, 0.75])
        f[2]  = 0; f[3] = 0
        f[4]  = rng.choice([0, 1], p=[0.3, 0.7])
        f[5]  = rng.choice([0, 1], p=[0.55, 0.45])
        f[6]  = rng.choice([0, 1], p=[0.45, 0.55])
        f[7]  = rng.choice([0, 1], p=[0.15, 0.85])
        f[8]  = 0
        f[9]  = rng.choice([0, 1], p=[0.25, 0.75])
        f[10] = rng.uniform(0.10, 0.60)
        f[11] = rng.uniform(0.05, 0.50)
        f[12] = rng.uniform(0.20, 0.80); f[13] = rng.uniform(0.10, 0.50)
        f[14] = 1; f[15] = 0
        f[16] = rng.choice([0, 1], p=[0.15, 0.85])
        f[17] = 0
        f[18] = rng.uniform(0.40, 0.90); f[19] = rng.uniform(0.00, 0.20)
        f[20] = rng.uniform(0.30, 0.80)
        f[21] = rng.choice([0, 1], p=[0.45, 0.55])
        f[22] = rng.choice([0, 1], p=[0.35, 0.65])
        f[23] = rng.uniform(0.40, 0.90)
        f[24] = rng.choice([0, 1], p=[0.25, 0.75])
        f[25] = rng.choice([0, 1], p=[0.50, 0.50])
        f[26] = 0
        s.append(f)
    return np.array(s)


def gen_crypto_scam(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 0; f[1] = rng.choice([0, 1], p=[0.35, 0.65])
        f[2]  = 0; f[3] = 0; f[4] = 1; f[5] = rng.choice([0, 1], p=[0.40, 0.60])
        f[6]  = 1; f[7] = rng.choice([0, 1], p=[0.45, 0.55])
        f[8]  = rng.choice([0, 1], p=[0.25, 0.75]); f[9] = 0
        f[10] = rng.uniform(0.20, 0.55); f[11] = rng.uniform(0.00, 0.30)
        f[12] = rng.uniform(0.00, 0.40); f[13] = rng.uniform(0.00, 0.30)
        f[14] = rng.choice([0, 1], p=[0.35, 0.65])
        f[15] = 1; f[16] = 0; f[17] = 1
        f[18] = rng.uniform(0.60, 1.00); f[19] = rng.uniform(0.00, 0.10)
        f[20] = rng.uniform(0.50, 1.00)
        f[21] = rng.choice([0, 1], p=[0.25, 0.75])
        f[22] = 0; f[23] = rng.uniform(0.50, 1.00)
        f[24] = rng.choice([0, 1], p=[0.45, 0.55])
        f[25] = 0; f[26] = 0
        s.append(f)
    return np.array(s)


def gen_prize_lottery(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 0; f[1] = rng.choice([0, 1], p=[0.50, 0.50])
        f[2]  = 0; f[3] = 0
        f[4]  = rng.choice([0, 1], p=[0.25, 0.75])
        f[5]  = 1; f[6] = 1; f[7] = 1; f[8] = 1; f[9] = 0
        f[10] = rng.uniform(0.25, 0.80); f[11] = rng.uniform(0.10, 0.60)
        f[12] = rng.uniform(0.00, 0.30); f[13] = rng.uniform(0.00, 0.30)
        f[14] = rng.choice([0, 1], p=[0.35, 0.65])
        f[15] = 0; f[16] = 0; f[17] = 1
        f[18] = rng.uniform(0.40, 1.00); f[19] = rng.uniform(0.00, 0.10)
        f[20] = rng.uniform(0.50, 1.00); f[21] = 1; f[22] = 0
        f[23] = rng.uniform(0.40, 0.80)
        f[24] = rng.choice([0, 1], p=[0.50, 0.50])
        f[25] = 0; f[26] = 0
        s.append(f)
    return np.array(s)


def gen_account_suspended(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 0; f[1] = 1; f[2] = 0; f[3] = 0
        f[4]  = rng.choice([0, 1], p=[0.40, 0.60])
        f[5]  = rng.choice([0, 1], p=[0.40, 0.60])
        f[6]  = rng.choice([0, 1], p=[0.45, 0.55])
        f[7]  = 1; f[8] = 0; f[9] = 1
        f[10] = rng.uniform(0.20, 0.50); f[11] = rng.uniform(0.00, 0.20)
        f[12] = rng.uniform(0.20, 0.60); f[13] = rng.uniform(0.10, 0.40)
        f[14] = 1; f[15] = 0; f[16] = 1; f[17] = 0
        f[18] = rng.uniform(0.30, 0.80); f[19] = rng.uniform(0.00, 0.20)
        f[20] = rng.uniform(0.40, 0.80)
        f[21] = rng.choice([0, 1], p=[0.35, 0.65])
        f[22] = rng.choice([0, 1], p=[0.35, 0.65])
        f[23] = rng.uniform(0.40, 0.80)
        f[24] = 1
        f[25] = rng.choice([0, 1], p=[0.50, 0.50])
        f[26] = 0
        s.append(f)
    return np.array(s)


def gen_compromised_account(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 1; f[1] = 0; f[2] = 1
        f[3]  = rng.choice([0, 1], p=[0.40, 0.60])
        f[4]  = 1; f[5] = 0; f[6] = 0
        f[7]  = rng.choice([0, 1], p=[0.35, 0.65])
        f[8]  = rng.choice([0, 1], p=[0.45, 0.55])
        f[9]  = rng.choice([0, 1], p=[0.45, 0.55])
        f[10] = rng.uniform(0.15, 0.50); f[11] = rng.uniform(0.00, 0.20)
        f[12] = rng.uniform(0.20, 0.60); f[13] = rng.uniform(0.10, 0.50)
        f[14] = rng.choice([0, 1], p=[0.35, 0.65])
        f[15] = rng.choice([0, 1], p=[0.25, 0.75])
        f[16] = rng.choice([0, 1], p=[0.40, 0.60])
        f[17] = rng.choice([0, 1], p=[0.45, 0.55])
        f[18] = rng.uniform(0.40, 1.00); f[19] = rng.uniform(0.00, 0.20)
        f[20] = rng.uniform(0.40, 0.80)
        f[21] = rng.choice([0, 1], p=[0.45, 0.55])
        f[22] = rng.choice([0, 1]); f[23] = rng.uniform(0.40, 0.80)
        f[24] = 0; f[25] = 1; f[26] = 1
        s.append(f)
    return np.array(s)


def gen_corporate_email(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 1; f[1] = 0; f[2] = 1; f[3] = 1; f[4] = 0
        f[5]  = 0; f[6] = 0; f[7] = 0; f[8] = 0; f[9] = 0
        f[10] = rng.uniform(0.05, 0.40); f[11] = rng.uniform(0.00, 0.05)
        f[12] = 0; f[13] = rng.uniform(0.00, 0.20)
        f[14] = 0; f[15] = 0; f[16] = 0; f[17] = 0; f[18] = 0
        f[19] = rng.uniform(0.40, 1.00); f[20] = 0; f[21] = 0
        f[22] = rng.choice([0, 1], p=[0.40, 0.60]); f[23] = 0
        f[24] = 0; f[25] = 1; f[26] = 1
        s.append(f)
    return np.array(s)


def gen_newsletter(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = rng.choice([0, 1], p=[0.25, 0.75]); f[1] = 0
        f[2]  = rng.choice([0, 1], p=[0.25, 0.75])
        f[3]  = rng.choice([0, 1], p=[0.35, 0.65])
        f[4]  = 0; f[5] = 0; f[6] = 0; f[7] = 0
        f[8]  = rng.choice([0, 1], p=[0.75, 0.25])
        f[9]  = 0; f[10] = rng.uniform(0.10, 0.50); f[11] = rng.uniform(0.00, 0.10)
        f[12] = 0; f[13] = rng.uniform(0.20, 0.80)
        f[14] = 0; f[15] = 0; f[16] = 0; f[17] = 0; f[18] = 0
        f[19] = rng.uniform(0.20, 0.60); f[20] = 0; f[21] = 0
        f[22] = 1; f[23] = rng.uniform(0.00, 0.20)
        f[24] = 0; f[25] = 1; f[26] = 1
        s.append(f)
    return np.array(s)


def gen_receipt_invoice(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 1; f[1] = 0; f[2] = 1
        f[3]  = rng.choice([0, 1], p=[0.30, 0.70])
        f[4]  = 0; f[5] = 0; f[6] = 0; f[7] = 0; f[8] = 0; f[9] = 0
        f[10] = rng.uniform(0.10, 0.45); f[11] = rng.uniform(0.00, 0.05)
        f[12] = 0; f[13] = rng.uniform(0.10, 0.40)
        f[14] = 0; f[15] = 0; f[16] = 0; f[17] = 0; f[18] = 0
        f[19] = rng.uniform(0.40, 1.00); f[20] = 0; f[21] = 0
        f[22] = 1; f[23] = 0
        f[24] = 0; f[25] = 1; f[26] = 1
        s.append(f)
    return np.array(s)


def gen_personal_email(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = rng.choice([0, 1], p=[0.35, 0.65]); f[1] = 0
        f[2]  = rng.choice([0, 1], p=[0.35, 0.65])
        f[3]  = rng.choice([0, 1], p=[0.45, 0.55])
        f[4]  = rng.choice([0, 1], p=[0.15, 0.85])
        f[5]  = 0; f[6] = 0; f[7] = 0; f[8] = 0; f[9] = 0
        f[10] = rng.uniform(0.03, 0.30); f[11] = rng.uniform(0.00, 0.05)
        f[12] = 0; f[13] = rng.uniform(0.00, 0.20)
        f[14] = 0; f[15] = 0; f[16] = 0; f[17] = 0; f[18] = 0
        f[19] = rng.uniform(0.10, 0.40); f[20] = 0; f[21] = 0
        f[22] = 0; f[23] = 0; f[24] = 0; f[25] = 1; f[26] = 1
        s.append(f)
    return np.array(s)


def gen_internal_notification(n):
    s = []
    for _ in range(n):
        f = _zero()
        f[0]  = 1; f[1] = 0; f[2] = 1; f[3] = 1; f[4] = 0
        f[5]  = 0; f[6] = 0; f[7] = 0; f[8] = 0; f[9] = 0
        f[10] = rng.uniform(0.10, 0.50); f[11] = rng.uniform(0.00, 0.05)
        f[12] = 0; f[13] = rng.uniform(0.00, 0.20)
        f[14] = 0; f[15] = 0; f[16] = 0; f[17] = 0; f[18] = 0
        f[19] = rng.uniform(0.40, 1.00); f[20] = 0; f[21] = 0
        f[22] = rng.choice([0, 1]); f[23] = 0
        f[24] = 0; f[25] = 1; f[26] = 1
        s.append(f)
    return np.array(s)


def build_synthetic_dataset(n_per_type=300):
    phishing = np.vstack([
        gen_credential_phishing(n_per_type),
        gen_crypto_scam(n_per_type),
        gen_prize_lottery(n_per_type),
        gen_account_suspended(n_per_type),
        gen_compromised_account(n_per_type),
    ])
    legit = np.vstack([
        gen_corporate_email(n_per_type),
        gen_newsletter(n_per_type),
        gen_receipt_invoice(n_per_type),
        gen_personal_email(n_per_type),
        gen_internal_notification(n_per_type),
    ])
    y = np.concatenate([np.ones(len(phishing)), np.zeros(len(legit))])
    X = np.vstack([phishing, legit])
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


# ── Main training ─────────────────────────────────────────────────────────────

def train_and_save(output_dir='ml_models'):
    os.makedirs(output_dir, exist_ok=True)

    # 1. Try to download SpamAssassin corpus
    print("=== Loading SpamAssassin Public Corpus ===")
    X_real, y_real = load_spamassassin_data(max_per_file=800)

    # 2. Build synthetic dataset for auth-state coverage
    print("\n=== Generating Synthetic Dataset (auth-state coverage) ===")
    X_syn, y_syn = build_synthetic_dataset(n_per_type=300)
    print(f"Synthetic: {X_syn.shape[0]} samples")

    # 3. Combine
    if X_real.shape[0] > 0:
        X = np.vstack([X_real, X_syn])
        y = np.concatenate([y_real, y_syn])
        print(f"\nCombined dataset: {X.shape[0]} samples "
              f"(SpamAssassin: {X_real.shape[0]}, Synthetic: {X_syn.shape[0]})")
    else:
        print("\nWARNING: SpamAssassin download failed -- using synthetic data only")
        X, y = X_syn, y_syn

    print(f"Phishing: {int(y.sum())}  |  Legitimate: {int((y==0).sum())}")

    idx = rng.permutation(len(X))
    X, y = X[idx], y[idx]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── Train and compare classifiers ─────────────────────────────────────────
    classifiers = {
        'Random Forest': RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        ),
        'SVM': SVC(
            kernel='rbf',
            C=10,
            gamma='scale',
            class_weight='balanced',
            probability=True,
            random_state=42,
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=12,
            min_samples_leaf=3,
            class_weight='balanced',
            random_state=42,
        ),
    }

    results = {}
    print("\n=== Comparing Scikit-learn Classifiers for Email Phishing Detection ===\n")
    for name, clf in classifiers.items():
        clf.fit(X_train_s, y_train)
        preds = clf.predict(X_test_s)
        acc = accuracy_score(y_test, preds)
        results[name] = (acc, clf)
        print(f"--- {name} ---")
        print(f"Accuracy: {acc*100:.2f}%")
        print(classification_report(y_test, preds, target_names=['Legitimate', 'Phishing']))

    best_name, (best_acc, best_model) = max(results.items(), key=lambda x: x[1][0])
    print(f"\n>> Best model: {best_name}  (Accuracy: {best_acc*100:.2f}%)")

    joblib.dump(best_model, os.path.join(output_dir, 'email_phishing_model.pkl'))
    joblib.dump(scaler,     os.path.join(output_dir, 'email_feature_scaler.pkl'))
    print(f"Saved {best_name} model + scaler to {output_dir}/")


if __name__ == '__main__':
    train_and_save()
