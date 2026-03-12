import re
from datetime import datetime, timedelta

def sanitize_filename(filename):
    """Remove dangerous characters from filename"""
    # Remove path traversal attempts
    filename = filename.replace('..', '')
    # Keep only safe characters
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    return filename

def calculate_threat_level(confidence_score):
    """
    Calculate threat level based on confidence score
    Returns: 'Low', 'Medium', 'High', or 'Critical'
    """
    if confidence_score >= 0.9:
        return 'Critical'
    elif confidence_score >= 0.7:
        return 'High'
    elif confidence_score >= 0.5:
        return 'Medium'
    else:
        return 'Low'

def format_timestamp(dt):
    """Format datetime for display"""
    if not dt:
        return 'N/A'
    
    now = datetime.utcnow()
    diff = now - dt
    
    if diff < timedelta(minutes=1):
        return 'Just now'
    elif diff < timedelta(hours=1):
        mins = int(diff.total_seconds() / 60)
        return f'{mins} minute{"s" if mins > 1 else ""} ago'
    elif diff < timedelta(days=1):
        hours = int(diff.total_seconds() / 3600)
        return f'{hours} hour{"s" if hours > 1 else ""} ago'
    elif diff < timedelta(days=7):
        days = diff.days
        return f'{days} day{"s" if days > 1 else ""} ago'
    else:
        return dt.strftime('%Y-%m-%d %H:%M')

def truncate_text(text, length=50):
    """Truncate text to specified length"""
    if not text:
        return ''
    if len(text) <= length:
        return text
    return text[:length] + '...'

def get_color_for_threat(threat_level):
    """Get Bootstrap color class for threat level"""
    colors = {
        'Critical': 'danger',
        'High': 'warning',
        'Medium': 'info',
        'Low': 'success',
        'Clean': 'success',
        'Safe': 'success'
    }
    return colors.get(threat_level, 'secondary')

def get_icon_for_scan_type(scan_type):
    """Get icon for scan type"""
    icons = {
        'file': '📁',
        'email': '✉️',
        'url': '🔗',
        'ip': '🌐'
    }
    return icons.get(scan_type, '📄')

def validate_form_input(data, required_fields):
    """
    Validate form input
    Returns: (is_valid, errors)
    """
    errors = []
    
    for field in required_fields:
        if field not in data or not data[field]:
            errors.append(f'{field.replace("_", " ").title()} is required.')
    
    return (len(errors) == 0, errors)

def generate_scan_summary(scan_result):
    """Generate human-readable scan summary"""
    if scan_result.get('is_malicious'):
        return f"⚠️ Threat detected: {scan_result.get('threat_type', 'Unknown')}"
    else:
        return "✅ No threats detected"
