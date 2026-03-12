from app import db
from datetime import datetime

class FileScan(db.Model):
    """Model for file scan results"""
    __tablename__ = 'file_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA256
    file_size = db.Column(db.Integer)  # in bytes
    file_type = db.Column(db.String(50))
    is_malicious = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20))  # Low, Medium, High, Critical
    malware_type = db.Column(db.String(50))  # Trojan, Virus, Worm, etc.
    confidence_score = db.Column(db.Float)  # 0.0 to 1.0
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # ML model predictions (for ensemble)
    rf_prediction = db.Column(db.String(20))
    svm_prediction = db.Column(db.String(20))
    dt_prediction = db.Column(db.String(20))
    
    def __repr__(self):
        return f'<FileScan {self.filename} - {"Malicious" if self.is_malicious else "Clean"}>'


class EmailScan(db.Model):
    """Model for email scan results"""
    __tablename__ = 'email_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender_email = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    
    # Authentication checks
    dkim_status = db.Column(db.String(20))  # pass, fail, none
    spf_status = db.Column(db.String(20))   # pass, fail, none
    dmarc_status = db.Column(db.String(20)) # pass, fail, none
    
    # Phishing detection
    phishing_score = db.Column(db.Float)  # 0.0 to 1.0
    is_phishing = db.Column(db.Boolean, default=False)
    suspicious_links = db.Column(db.Integer, default=0)
    
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f'<EmailScan {self.sender_email} - Phishing: {self.is_phishing}>'


class URLScan(db.Model):
    """Model for URL scan results"""
    __tablename__ = 'url_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    url = db.Column(db.String(2000), nullable=False)
    domain = db.Column(db.String(255))
    
    # Threat detection
    is_malicious = db.Column(db.Boolean, default=False)
    threat_type = db.Column(db.String(50))  # phishing, malware, social_engineering
    reputation_score = db.Column(db.Float)  # 0.0 to 1.0
    
    # External API results
    google_safe_browsing = db.Column(db.String(20))
    
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f'<URLScan {self.url[:50]} - {"Malicious" if self.is_malicious else "Safe"}>'


class IPScan(db.Model):
    """Model for IP scan results"""
    __tablename__ = 'ip_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # Supports IPv4 and IPv6
    
    # Threat detection
    is_malicious = db.Column(db.Boolean, default=False)
    abuse_confidence_score = db.Column(db.Integer)  # 0-100
    total_reports = db.Column(db.Integer, default=0)
    
    # Geolocation
    country = db.Column(db.String(100))
    isp = db.Column(db.String(255))
    
    # Usage type
    usage_type = db.Column(db.String(50))  # Data Center, ISP, Hosting, etc.
    
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f'<IPScan {self.ip_address} - Score: {self.abuse_confidence_score}>'
