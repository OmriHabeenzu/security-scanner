from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(UserMixin, db.Model):
    """User model for authentication and scan history"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    file_scans = db.relationship('FileScan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    email_scans = db.relationship('EmailScan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    url_scans = db.relationship('URLScan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    ip_scans = db.relationship('IPScan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def get_total_scans(self):
        """Get total number of scans across all types"""
        return (self.file_scans.count() + 
                self.email_scans.count() + 
                self.url_scans.count() + 
                self.ip_scans.count())
    
    def get_threats_found(self):
        """Get total number of threats found"""
        from app.models.scans import FileScan, EmailScan, URLScan, IPScan
        
        threats = 0
        threats += self.file_scans.filter_by(is_malicious=True).count()
        threats += self.email_scans.filter(EmailScan.phishing_score > 70).count()
        threats += self.url_scans.filter_by(is_malicious=True).count()
        threats += self.ip_scans.filter(IPScan.abuse_confidence_score > 75).count()
        return threats
    
    def __repr__(self):
        return f'<User {self.username}>'
