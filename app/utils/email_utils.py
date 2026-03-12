import re
import email
from email import policy
from email.parser import BytesParser
import dns.resolver

def validate_email(email_address):
    """Validate email address format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email_address) is not None

def parse_email_headers(email_text):
    """
    Parse email headers from raw email text
    Returns: dict with parsed headers
    """
    try:
        # Parse email
        msg = email.message_from_string(email_text, policy=policy.default)
        
        headers = {
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'return_path': msg.get('Return-Path', ''),
            'received': msg.get_all('Received', []),
            'dkim_signature': msg.get('DKIM-Signature', ''),
            'authentication_results': msg.get('Authentication-Results', ''),
        }
        
        return headers
    
    except Exception as e:
        print(f"Error parsing email headers: {e}")
        return None

def extract_sender_domain(email_address):
    """Extract domain from email address"""
    try:
        if '@' in email_address:
            # Remove display name if present
            if '<' in email_address:
                email_address = email_address.split('<')[1].split('>')[0]
            return email_address.split('@')[1].strip()
    except:
        pass
    return None

def parse_auth_results_header(auth_results_header: str) -> dict:
    """
    Parse the Authentication-Results header to extract actual DKIM/SPF/DMARC verdicts.
    This is the ground truth for emails that have already been processed by a receiving MTA.
    Returns dict with keys 'dkim', 'spf', 'dmarc', each being 'pass', 'fail', or 'none'.
    """
    h = auth_results_header.lower()
    results = {}

    for proto in ('dkim', 'spf', 'dmarc'):
        m = re.search(rf'{proto}=(pass|fail|neutral|softfail|none|temperror|permerror)', h)
        if m:
            verdict = m.group(1)
            # Normalise softfail/neutral → 'fail' for our purposes
            results[proto] = 'fail' if verdict in ('fail', 'softfail', 'neutral') else (
                'pass' if verdict == 'pass' else 'none'
            )
        else:
            results[proto] = 'none'

    return results


def check_spf_record(domain, auth_results_header: str = ''):
    """
    Return SPF verdict for the given domain.
    Priority: Authentication-Results header (actual MTA verdict) → DNS record existence.
    Returns: 'pass', 'fail', or 'none'
    """
    # Use MTA-reported result when available
    if auth_results_header:
        parsed = parse_auth_results_header(auth_results_header)
        if parsed['spf'] != 'none':
            return parsed['spf']

    # Fallback: check whether the domain publishes an SPF record
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_bytes in rdata.strings:
                decoded = txt_bytes.decode('utf-8', errors='ignore').lower()
                if 'v=spf1' in decoded:
                    return 'pass'
            if 'v=spf1' in str(rdata).lower():
                return 'pass'
        return 'none'
    except Exception:
        return 'none'


def check_dmarc_record(domain, auth_results_header: str = ''):
    """
    Return DMARC verdict for the given domain.
    Priority: Authentication-Results header (actual MTA verdict) → DNS record existence.
    Returns: 'pass', 'fail', or 'none'
    """
    # Use MTA-reported result when available
    if auth_results_header:
        parsed = parse_auth_results_header(auth_results_header)
        if parsed['dmarc'] != 'none':
            return parsed['dmarc']

    # Fallback: check whether the domain publishes a DMARC record
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt_bytes in rdata.strings:
                decoded = txt_bytes.decode('utf-8', errors='ignore')
                if 'v=DMARC1' in decoded:
                    return 'pass'
            if 'v=DMARC1' in str(rdata):
                return 'pass'
        return 'none'
    except Exception:
        return 'none'

def extract_links_from_email(email_text):
    """Extract all URLs from email body"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, email_text)
    return list(set(urls))  # Remove duplicates

def detect_suspicious_keywords(text):
    """
    Detect suspicious phishing keywords in email
    Returns: list of found suspicious keywords
    """
    suspicious_keywords = [
        'verify your account', 'confirm your identity', 'urgent action required',
        'account suspended', 'unusual activity', 'click here immediately',
        'prize winner', 'claim your reward', 'limited time offer',
        'password reset', 'update payment', 'confirm payment',
        'act now', 'congratulations', 'you have won'
    ]
    
    text_lower = text.lower()
    found_keywords = []
    
    for keyword in suspicious_keywords:
        if keyword in text_lower:
            found_keywords.append(keyword)
    
    return found_keywords
