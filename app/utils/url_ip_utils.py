import re
import socket
from urllib.parse import urlparse
import ipaddress

def validate_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def extract_domain_from_url(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return None

def is_url_suspicious(url):
    """
    Check for suspicious URL patterns
    Returns: (is_suspicious, reasons)
    """
    suspicious_indicators = []
    url_lower = url.lower()
    
    # Check for IP address instead of domain
    domain = extract_domain_from_url(url)
    if domain:
        try:
            ipaddress.ip_address(domain)
            suspicious_indicators.append("Uses IP address instead of domain")
        except:
            pass
    
    # Check for excessive subdomains
    if domain and domain.count('.') > 3:
        suspicious_indicators.append("Excessive subdomains")
    
    # Check for suspicious keywords in URL
    suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'signin']
    for keyword in suspicious_keywords:
        if keyword in url_lower and domain and keyword not in domain.split('.')[0]:
            suspicious_indicators.append(f"Suspicious keyword: {keyword}")
            break
    
    # Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
    if domain and any(short in domain for short in shorteners):
        suspicious_indicators.append("URL shortener used")
    
    # Check for @ symbol (phishing technique)
    if '@' in url:
        suspicious_indicators.append("Contains @ symbol (phishing technique)")
    
    # Check for excessive hyphens
    if domain and domain.count('-') > 3:
        suspicious_indicators.append("Excessive hyphens in domain")
    
    return (len(suspicious_indicators) > 0, suspicious_indicators)

def validate_ip_address(ip):
    """Validate IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def get_ip_version(ip):
    """Get IP version (4 or 6)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version
    except:
        return None

def is_private_ip(ip):
    """Check if IP is private/internal"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def resolve_domain_to_ip(domain):
    """Resolve domain name to IP address"""
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_url_protocol(url):
    """Get URL protocol (http or https)"""
    try:
        parsed = urlparse(url)
        return parsed.scheme
    except:
        return None

def is_https(url):
    """Check if URL uses HTTPS"""
    return get_url_protocol(url) == 'https'
