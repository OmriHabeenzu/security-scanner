"""
API Blueprint for Dashboard Statistics and Analytics
Provides RESTful endpoints for Chart.js visualizations
"""

from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta, date
from sqlalchemy import func
from app.models.scans import FileScan, EmailScan, URLScan, IPScan

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/dashboard/stats')
@login_required
def dashboard_stats():
    """
    Get comprehensive dashboard statistics for Chart.js visualizations
    Returns: JSON with scan counts, threat data, and timeline
    """
    user_id = current_user.id
    
    # Get counts by scan type
    file_count = FileScan.query.filter_by(user_id=user_id).count()
    email_count = EmailScan.query.filter_by(user_id=user_id).count()
    url_count = URLScan.query.filter_by(user_id=user_id).count()
    ip_count = IPScan.query.filter_by(user_id=user_id).count()
    
    # Get threat counts
    file_threats = FileScan.query.filter_by(user_id=user_id, is_malicious=True).count()
    email_threats = EmailScan.query.filter_by(user_id=user_id, is_phishing=True).count()
    
    # URL/IP threats
    url_threats = URLScan.query.filter_by(user_id=user_id, is_malicious=True).count()
    ip_threats = IPScan.query.filter_by(user_id=user_id, is_malicious=True).count()

    # Clean counts
    file_clean = file_count - file_threats
    email_clean = email_count - email_threats
    
    # Timeline data (last 7 days)
    timeline = get_scan_timeline(user_id, days=7)
    
    # Overall percentages
    total_scans = file_count + email_count + url_count + ip_count
    total_threats = file_threats + email_threats + url_threats + ip_threats
    total_clean = total_scans - total_threats
    
    clean_percentage = round((total_clean / total_scans * 100), 1) if total_scans > 0 else 100
    threat_percentage = round((total_threats / total_scans * 100), 1) if total_scans > 0 else 0
    
    return jsonify({
        'success': True,
        'file_scans': file_count,
        'email_scans': email_count,
        'url_scans': url_count,
        'ip_scans': ip_count,
        'threats_by_type': [file_threats, email_threats, url_threats, ip_threats],
        'clean_by_type': [file_clean, email_clean, url_count - url_threats, ip_count - ip_threats],
        'timeline': timeline,
        'clean_percentage': clean_percentage,
        'threat_percentage': threat_percentage,
        'total_scans': total_scans,
        'total_threats': total_threats
    })


def get_scan_timeline(user_id, days=7):
    """
    Get scan activity for last N days
    Returns dict with labels, scans data, and threats data
    """
    end_date = date.today()
    start_date = end_date - timedelta(days=days-1)
    
    labels = []
    scans_data = []
    threats_data = []
    
    for i in range(days):
        current_date = start_date + timedelta(days=i)
        next_date = current_date + timedelta(days=1)
        
        # Get scans for this day
        day_file_scans = FileScan.query.filter(
            FileScan.user_id == user_id,
            FileScan.scan_timestamp >= current_date,
            FileScan.scan_timestamp < next_date
        ).count()
        
        day_email_scans = EmailScan.query.filter(
            EmailScan.user_id == user_id,
            EmailScan.scan_timestamp >= current_date,
            EmailScan.scan_timestamp < next_date
        ).count()
        
        day_url_scans = URLScan.query.filter(
            URLScan.user_id == user_id,
            URLScan.scan_timestamp >= current_date,
            URLScan.scan_timestamp < next_date
        ).count()
        
        day_ip_scans = IPScan.query.filter(
            IPScan.user_id == user_id,
            IPScan.scan_timestamp >= current_date,
            IPScan.scan_timestamp < next_date
        ).count()
        
        total_day_scans = day_file_scans + day_email_scans + day_url_scans + day_ip_scans
        
        # Get threats for this day
        day_file_threats = FileScan.query.filter(
            FileScan.user_id == user_id,
            FileScan.is_malicious == True,
            FileScan.scan_timestamp >= current_date,
            FileScan.scan_timestamp < next_date
        ).count()
        
        day_email_threats = EmailScan.query.filter(
            EmailScan.user_id == user_id,
            EmailScan.is_phishing == True,
            EmailScan.scan_timestamp >= current_date,
            EmailScan.scan_timestamp < next_date
        ).count()
        
        total_day_threats = day_file_threats + day_email_threats
        
        # Format label
        labels.append(current_date.strftime('%a'))  # Mon, Tue, Wed, etc.
        scans_data.append(total_day_scans)
        threats_data.append(total_day_threats)
    
    return {
        'labels': labels,
        'scans': scans_data,
        'threats': threats_data
    }


@api_bp.route('/user/summary')
@login_required
def user_summary():
    """
    Get daily summary for email reports
    Returns: JSON with today's scan statistics
    """
    user_id = current_user.id
    today = date.today()
    
    # Today's scans
    file_scans_today = FileScan.query.filter(
        FileScan.user_id == user_id,
        func.date(FileScan.scan_timestamp) == today
    ).count()
    
    email_scans_today = EmailScan.query.filter(
        EmailScan.user_id == user_id,
        func.date(EmailScan.scan_timestamp) == today
    ).count()
    
    url_scans_today = URLScan.query.filter(
        URLScan.user_id == user_id,
        func.date(URLScan.scan_timestamp) == today
    ).count()
    
    ip_scans_today = IPScan.query.filter(
        IPScan.user_id == user_id,
        func.date(IPScan.scan_timestamp) == today
    ).count()
    
    # Today's threats
    file_threats_today = FileScan.query.filter(
        FileScan.user_id == user_id,
        FileScan.is_malicious == True,
        func.date(FileScan.scan_timestamp) == today
    ).count()
    
    email_threats_today = EmailScan.query.filter(
        EmailScan.user_id == user_id,
        EmailScan.is_phishing == True,
        func.date(EmailScan.scan_timestamp) == today
    ).count()
    
    total_today = file_scans_today + email_scans_today + url_scans_today + ip_scans_today
    threats_today = file_threats_today + email_threats_today
    clean_today = total_today - threats_today
    
    return jsonify({
        'success': True,
        'total_scans': total_today,
        'threats_found': threats_today,
        'clean_scans': clean_today,
        'file_scans': file_scans_today,
        'email_scans': email_scans_today,
        'url_scans': url_scans_today,
        'ip_scans': ip_scans_today
    })


@api_bp.route('/ml/performance')
def ml_performance():
    """
    Get ML model performance metrics
    Returns: JSON with model accuracy data
    """
    return jsonify({
        'success': True,
        'models': {
            'random_forest': {
                'accuracy': 77.31,
                'precision': 0.8351,
                'recall': 0.7731,
                'f1_score': 0.7701
            },
            'decision_tree': {
                'accuracy': 79.36,
                'precision': 0.8448,
                'recall': 0.7936,
                'f1_score': 0.7920
            },
            'svm': {
                'accuracy': 77.81,
                'precision': 0.8391,
                'recall': 0.7781,
                'f1_score': 0.7754
            }
        },
        'best_model': 'decision_tree',
        'ensemble_accuracy': 78.92
    })
