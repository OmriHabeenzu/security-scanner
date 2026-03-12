from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import current_user, login_required
from app import db
from app.models.scans import FileScan, EmailScan, URLScan, IPScan
from app.utils.file_scanner import scan_file, scan_multiple_files
from app.utils.email_scanner import scan_email
from app.utils.url_scanner import scan_url
from app.utils.ip_scanner import scan_ip
from app.utils.email_reporter import send_scan_report

bp = Blueprint('scanner', __name__, url_prefix='/scan')

@bp.route('/dashboard')
def guest_dashboard():
    """Guest dashboard - quick scan options"""
    return render_template('scanner/guest_dashboard.html')


@bp.route('/user-dashboard')
@login_required
def user_dashboard():
    """Authenticated user dashboard with history and stats"""
    # Get user statistics
    total_scans = current_user.get_total_scans()
    threats_found = current_user.get_threats_found()
    
    # Get recent scans (last 5 of each type)
    recent_file_scans = current_user.file_scans.order_by(FileScan.scan_timestamp.desc()).limit(5).all()
    recent_email_scans = current_user.email_scans.order_by(EmailScan.scan_timestamp.desc()).limit(5).all()
    recent_url_scans = current_user.url_scans.order_by(URLScan.scan_timestamp.desc()).limit(5).all()
    recent_ip_scans = current_user.ip_scans.order_by(IPScan.scan_timestamp.desc()).limit(5).all()
    
    return render_template('scanner/user_dashboard.html',
                         total_scans=total_scans,
                         threats_found=threats_found,
                         recent_file_scans=recent_file_scans,
                         recent_email_scans=recent_email_scans,
                         recent_url_scans=recent_url_scans,
                         recent_ip_scans=recent_ip_scans)


@bp.route('/file/batch', methods=['GET', 'POST'])
def file_batch_scan():
    """Batch file scanning - up to 10 files"""
    if request.method == 'POST':
        if 'files' not in request.files:
            flash('No files uploaded', 'danger')
            return redirect(url_for('scanner.file_batch_scan'))
        
        files = request.files.getlist('files')
        files = [f for f in files if f and f.filename != '']
        
        if not files:
            flash('No files selected', 'danger')
            return redirect(url_for('scanner.file_batch_scan'))
        
        if len(files) > 10:
            flash('Maximum 10 files per batch. Processing first 10 files.', 'warning')
            files = files[:10]
        
        # Scan all files
        results = []
        for file in files:
            result = scan_file(file, current_user if current_user.is_authenticated else None)
            results.append(result)
        
        # Calculate summary
        summary = {
            'total': len(results),
            'malicious': sum(1 for r in results if r.get('success') and r.get('is_malicious')),
            'clean': sum(1 for r in results if r.get('success') and not r.get('is_malicious')),
            'errors': sum(1 for r in results if not r.get('success'))
        }
        summary['threat_rate'] = round((summary['malicious'] / summary['total'] * 100), 2) if summary['total'] > 0 else 0
        
        return render_template('scanner/file_batch_results.html', results=results, summary=summary)
    
    return render_template('scanner/file_batch_scan.html')


@bp.route('/download-pdf/<scan_type>/<int:scan_id>')
@login_required
def download_pdf(scan_type, scan_id):
    """Download PDF report for a scan"""
    from flask import send_file
    from app.utils.pdf_generator import generate_scan_report_pdf
    
    # Fetch scan based on type
    if scan_type == 'file':
        scan = FileScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
        data = {
            'filename': scan.filename,
            'file_size': scan.file_size,
            'file_type': scan.file_type,
            'file_hash': scan.file_hash,
            'is_malicious': scan.is_malicious,
            'threat_level': scan.threat_level,
            'malware_type': scan.malware_type,
            'confidence_score': scan.confidence_score,
            'rf_prediction': getattr(scan, 'rf_prediction', 'N/A'),
            'dt_prediction': getattr(scan, 'dt_prediction', 'N/A'),
            'svm_prediction': getattr(scan, 'svm_prediction', 'N/A')
        }
    elif scan_type == 'email':
        scan = EmailScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
        data = {
            'sender_email': scan.sender_email,
            'subject': scan.subject,
            'is_phishing': scan.is_phishing,
            'phishing_score': scan.phishing_score,
            'dkim_status': scan.dkim_status,
            'spf_status': scan.spf_status,
            'dmarc_status': scan.dmarc_status,
            'suspicious_links': scan.suspicious_links
        }
    elif scan_type == 'url':
        scan = URLScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
        data = {
            'url': scan.url,
            'threat_score': getattr(scan, 'threat_score', 0),
            'https': getattr(scan, 'is_https', False)
        }
    elif scan_type == 'ip':
        scan = IPScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
        data = {
            'ip_address': scan.ip_address,
            'abuse_score': getattr(scan, 'abuse_score', 0),
            'country': getattr(scan, 'country', 'Unknown'),
            'isp': getattr(scan, 'isp', 'Unknown')
        }
    else:
        flash('Invalid scan type', 'danger')
        return redirect(url_for('scanner.user_dashboard'))
    
    try:
        pdf_buffer = generate_scan_report_pdf(data, scan_type)
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'securecheck_{scan_type}_report_{scan_id}.pdf'
        )
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'danger')
        return redirect(url_for('scanner.user_dashboard'))


@bp.route('/history')
@login_required
def scan_history():
    """View all scan history"""
    file_scans = current_user.file_scans.order_by(FileScan.scan_timestamp.desc()).all()
    email_scans = current_user.email_scans.order_by(EmailScan.scan_timestamp.desc()).all()
    url_scans = current_user.url_scans.order_by(URLScan.scan_timestamp.desc()).all()
    ip_scans = current_user.ip_scans.order_by(IPScan.scan_timestamp.desc()).all()
    
    return render_template('scanner/history.html',
                         file_scans=file_scans,
                         email_scans=email_scans,
                         url_scans=url_scans,
                         ip_scans=ip_scans)


@bp.route('/analytics')
@login_required
def analytics_dashboard():
    """Analytics dashboard with Chart.js visualizations"""
    return render_template('dashboard/analytics.html')


@bp.route('/file', methods=['GET', 'POST'])
def file_scan():
    """File scanning - available to both guests and users"""
    if request.method == 'POST':
        # Check if files were uploaded
        if 'file' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(url_for('scanner.file_scan'))
        
        files = request.files.getlist('file')
        
        if not files or files[0].filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('scanner.file_scan'))
        
        # Limit for guest users
        if not current_user.is_authenticated and len(files) > 1:
            flash('Guest users can only scan 1 file at a time. Please register for batch scanning.', 'warning')
            files = files[:1]
        
        # Scan files
        user = current_user if current_user.is_authenticated else None
        
        if len(files) == 1:
            result = scan_file(files[0], user)
        else:
            results = scan_multiple_files(files, user)
            return render_template('scanner/file_results.html', results=results, multiple=True)
        
        if result['success']:
            return render_template('scanner/file_results.html', result=result, multiple=False)
        else:
            flash(f"Error: {result.get('error', 'Unknown error')}", 'danger')
            return redirect(url_for('scanner.file_scan'))
    
    return render_template('scanner/file_scan.html')


@bp.route('/email', methods=['GET', 'POST'])
def email_scan():
    """Email header scanning - available to both guests and users"""
    if request.method == 'POST':
        email_text = request.form.get('email_text', '').strip()
        
        if not email_text:
            flash('Please paste email headers', 'danger')
            return redirect(url_for('scanner.email_scan'))
        
        # Scan email
        user = current_user if current_user.is_authenticated else None
        result = scan_email(email_text, user)
        
        if result['success']:
            return render_template('scanner/email_results.html', result=result)
        else:
            flash(f"Error: {result.get('error', 'Unknown error')}", 'danger')
            return redirect(url_for('scanner.email_scan'))
    
    return render_template('scanner/email_scan.html')


@bp.route('/url', methods=['GET', 'POST'])
def url_scan():
    """URL scanning - available to both guests and users"""
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        
        if not url:
            flash('Please enter a URL', 'danger')
            return redirect(url_for('scanner.url_scan'))
        
        # Scan URL
        user = current_user if current_user.is_authenticated else None
        result = scan_url(url, user)
        
        if result['success']:
            return render_template('scanner/url_results.html', result=result)
        else:
            flash(f"Error: {result.get('error', 'Unknown error')}", 'danger')
            return redirect(url_for('scanner.url_scan'))
    
    return render_template('scanner/url_scan.html')


@bp.route('/ip', methods=['GET', 'POST'])
def ip_scan():
    """IP address scanning - available to both guests and users"""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address', '').strip()
        
        if not ip_address:
            flash('Please enter an IP address', 'danger')
            return redirect(url_for('scanner.ip_scan'))
        
        # Scan IP
        user = current_user if current_user.is_authenticated else None
        result = scan_ip(ip_address, user)
        
        if result['success']:
            return render_template('scanner/ip_results.html', result=result)
        else:
            flash(f"Error: {result.get('error', 'Unknown error')}", 'danger')
            return redirect(url_for('scanner.ip_scan'))
    
    return render_template('scanner/ip_scan.html')


@bp.route('/send-email-report/<scan_type>/<int:scan_id>', methods=['POST'])
@login_required
def send_email_report(scan_type, scan_id):
    """Send a scan report to the user's email via smtplib."""
    recipient = request.form.get('recipient_email', '').strip()
    if not recipient:
        recipient = current_user.email

    # Fetch scan record and build data dict
    try:
        if scan_type == 'file':
            scan = FileScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
            data = {
                'filename': scan.filename,
                'file_size': scan.file_size,
                'file_type': scan.file_type,
                'file_hash': scan.file_hash,
                'is_malicious': scan.is_malicious,
                'threat_level': scan.threat_level,
                'malware_type': scan.malware_type,
                'confidence_score': round((scan.confidence_score or 0) * 100, 1),
                'rf_prediction': scan.rf_prediction or 'N/A',
                'dt_prediction': scan.dt_prediction or 'N/A',
                'svm_prediction': scan.svm_prediction or 'N/A',
            }
        elif scan_type == 'email':
            scan = EmailScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
            data = {
                'sender_email': scan.sender_email,
                'subject': scan.subject,
                'is_phishing': scan.is_phishing,
                'phishing_score': scan.phishing_score,
                'dkim_status': scan.dkim_status,
                'spf_status': scan.spf_status,
                'dmarc_status': scan.dmarc_status,
                'suspicious_links': scan.suspicious_links,
            }
        elif scan_type == 'url':
            scan = URLScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
            data = {
                'url': scan.url,
                'domain': scan.domain,
                'threat_score': round((scan.reputation_score or 0) * 100, 1),
                'uses_https': scan.url.startswith('https://'),
                'api_status': scan.google_safe_browsing or 'N/A',
            }
        elif scan_type == 'ip':
            scan = IPScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
            data = {
                'ip_address': scan.ip_address,
                'abuse_score': scan.abuse_confidence_score or 0,
                'total_reports': scan.total_reports or 0,
                'country': scan.country or 'Unknown',
                'isp': scan.isp or 'Unknown',
                'usage_type': scan.usage_type or 'Unknown',
                'last_reported': 'N/A',
            }
        else:
            flash('Invalid scan type', 'danger')
            return redirect(url_for('scanner.user_dashboard'))

        # Optionally attach PDF
        pdf_buffer = None
        if request.form.get('attach_pdf') == '1':
            from app.utils.pdf_generator import generate_scan_report_pdf
            pdf_buffer = generate_scan_report_pdf(data, scan_type)

        result = send_scan_report(recipient, data, scan_type, pdf_buffer)

        if result['success']:
            flash(f'Report sent to {recipient}', 'success')
        else:
            flash(f'Failed to send report: {result["error"]}', 'warning')

    except Exception as e:
        flash(f'Error sending report: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('scanner.user_dashboard'))
