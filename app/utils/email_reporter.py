"""
Email report sending via smtplib.
Sends scan results to a recipient email address.
"""
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime
from flask import current_app


def _mail_configured():
    """Return True only if mail credentials are present."""
    return bool(
        current_app.config.get('MAIL_USERNAME') and
        current_app.config.get('MAIL_PASSWORD') and
        current_app.config.get('MAIL_SERVER')
    )


def _build_file_html(data):
    status_color = '#dc2626' if data.get('is_malicious') else '#16a34a'
    status_text  = f"MALICIOUS — {data.get('threat_level', 'HIGH')}" if data.get('is_malicious') else 'CLEAN'
    return f"""
        <h2 style="color:{status_color};">{status_text}</h2>
        <table style="border-collapse:collapse;width:100%;">
          <tr><td style="padding:6px;font-weight:bold;">Filename</td><td style="padding:6px;">{data.get('filename','N/A')}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">SHA-256</td><td style="padding:6px;font-family:monospace;font-size:12px;">{data.get('file_hash','N/A')}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">File Size</td><td style="padding:6px;">{data.get('file_size','N/A')}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">File Type</td><td style="padding:6px;">{data.get('file_type','N/A')}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">Confidence</td><td style="padding:6px;">{data.get('confidence_score',0)}%</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">RF Model</td><td style="padding:6px;">{data.get('rf_prediction','N/A')}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">DT Model</td><td style="padding:6px;">{data.get('dt_prediction','N/A')}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">SVM Model</td><td style="padding:6px;">{data.get('svm_prediction','N/A')}</td></tr>
        </table>"""


def _build_email_html(data):
    status_color = '#dc2626' if data.get('is_phishing') else '#16a34a'
    status_text  = f"PHISHING ({data.get('phishing_score',0)}%)" if data.get('is_phishing') else 'SAFE'

    def badge(v):
        c = '#16a34a' if v == 'pass' else ('#dc2626' if v == 'fail' else '#6b7280')
        return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;">{v.upper()}</span>'

    return f"""
        <h2 style="color:{status_color};">{status_text}</h2>
        <table style="border-collapse:collapse;width:100%;">
          <tr><td style="padding:6px;font-weight:bold;">From</td><td style="padding:6px;">{data.get('sender_email','N/A')}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">Subject</td><td style="padding:6px;">{data.get('subject','N/A')}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">Phishing Score</td><td style="padding:6px;">{data.get('phishing_score',0)}%</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">DKIM</td><td style="padding:6px;">{badge(data.get('dkim_status','none'))}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">SPF</td><td style="padding:6px;">{badge(data.get('spf_status','none'))}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">DMARC</td><td style="padding:6px;">{badge(data.get('dmarc_status','none'))}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">Suspicious Links</td><td style="padding:6px;">{data.get('suspicious_links',0)}</td></tr>
        </table>"""


def _build_url_html(data):
    score = data.get('threat_score', 0)
    status_color = '#dc2626' if score > 70 else '#16a34a'
    status_text  = f"SUSPICIOUS ({score}%)" if score > 70 else f"SAFE ({score}%)"
    return f"""
        <h2 style="color:{status_color};">{status_text}</h2>
        <table style="border-collapse:collapse;width:100%;">
          <tr><td style="padding:6px;font-weight:bold;">URL</td><td style="padding:6px;word-break:break-all;">{data.get('url','N/A')}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">Domain</td><td style="padding:6px;">{data.get('domain','N/A')}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">Threat Score</td><td style="padding:6px;">{score}%</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">HTTPS</td><td style="padding:6px;">{'Yes' if data.get('uses_https') else 'No'}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">API Status</td><td style="padding:6px;">{data.get('api_status','N/A')}</td></tr>
        </table>"""


def _build_ip_html(data):
    score = data.get('abuse_score', 0)
    status_color = '#dc2626' if score > 75 else ('#f59e0b' if score > 50 else '#16a34a')
    status_text  = f"HIGH RISK ({score}/100)" if score > 75 else (f"MEDIUM RISK ({score}/100)" if score > 50 else f"LOW RISK ({score}/100)")
    return f"""
        <h2 style="color:{status_color};">{status_text}</h2>
        <table style="border-collapse:collapse;width:100%;">
          <tr><td style="padding:6px;font-weight:bold;">IP Address</td><td style="padding:6px;font-family:monospace;">{data.get('ip_address','N/A')}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">Abuse Score</td><td style="padding:6px;">{score}/100</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">Total Reports</td><td style="padding:6px;">{data.get('total_reports',0)}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">Country</td><td style="padding:6px;">{data.get('country','Unknown')}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">ISP</td><td style="padding:6px;">{data.get('isp','Unknown')}</td></tr>
          <tr style="background:#f3f4f6;"><td style="padding:6px;font-weight:bold;">Usage Type</td><td style="padding:6px;">{data.get('usage_type','Unknown')}</td></tr>
          <tr><td style="padding:6px;font-weight:bold;">Last Reported</td><td style="padding:6px;">{data.get('last_reported','Never')}</td></tr>
        </table>"""


def _build_html_body(scan_data, scan_type):
    type_labels = {'file': 'File Malware Scan', 'email': 'Email Phishing Analysis',
                   'url': 'URL Security Check', 'ip': 'IP Reputation Check'}
    label = type_labels.get(scan_type, scan_type.upper())

    section_map = {'file': _build_file_html, 'email': _build_email_html,
                   'url': _build_url_html, 'ip': _build_ip_html}
    section_fn = section_map.get(scan_type)
    section_html = section_fn(scan_data) if section_fn else '<p>No details available.</p>'

    return f"""
    <html><body style="font-family:Arial,sans-serif;max-width:700px;margin:0 auto;padding:20px;">
      <div style="background:#2563eb;color:white;padding:20px;border-radius:8px 8px 0 0;">
        <h1 style="margin:0;">SecureCheck Security Report</h1>
        <p style="margin:4px 0 0 0;">{label}</p>
      </div>
      <div style="border:1px solid #e5e7eb;border-top:none;padding:24px;border-radius:0 0 8px 8px;">
        <p style="color:#6b7280;margin-top:0;">
          Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </p>
        {section_html}
        <hr style="margin:24px 0;border-color:#e5e7eb;">
        <p style="color:#9ca3af;font-size:12px;text-align:center;margin:0;">
          This report was automatically generated by SecureCheck AI-Powered Security Scanner.
        </p>
      </div>
    </body></html>"""


def send_scan_report(recipient_email, scan_data, scan_type, pdf_buffer=None):
    """
    Send a scan report to recipient_email via smtplib.

    Args:
        recipient_email: destination address
        scan_data:       dict of scan results (same structure as scan result dicts)
        scan_type:       'file' | 'email' | 'url' | 'ip'
        pdf_buffer:      optional BytesIO with PDF attachment

    Returns:
        {'success': True} or {'success': False, 'error': str}
    """
    if not _mail_configured():
        return {
            'success': False,
            'error': 'Email is not configured. Set MAIL_USERNAME and MAIL_PASSWORD in your .env file.'
        }

    sender    = current_app.config['MAIL_USERNAME']
    password  = current_app.config['MAIL_PASSWORD']
    server    = current_app.config['MAIL_SERVER']
    port      = current_app.config['MAIL_PORT']
    use_tls   = current_app.config['MAIL_USE_TLS']

    type_labels = {'file': 'File Malware', 'email': 'Email Phishing',
                   'url': 'URL Security', 'ip': 'IP Reputation'}
    subject = f"SecureCheck Report — {type_labels.get(scan_type, scan_type.upper())} Scan"

    msg = MIMEMultipart('mixed')
    msg['From']    = sender
    msg['To']      = recipient_email
    msg['Subject'] = subject

    html_body = _build_html_body(scan_data, scan_type)
    msg.attach(MIMEText(html_body, 'html'))

    if pdf_buffer:
        pdf_buffer.seek(0)
        attachment = MIMEApplication(pdf_buffer.read(), _subtype='pdf')
        attachment.add_header('Content-Disposition', 'attachment',
                               filename=f'securecheck_{scan_type}_report.pdf')
        msg.attach(attachment)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(server, port) as smtp:
            if use_tls:
                smtp.starttls(context=context)
            smtp.login(sender, password)
            smtp.sendmail(sender, recipient_email, msg.as_string())
        return {'success': True}
    except smtplib.SMTPAuthenticationError:
        return {'success': False, 'error': 'SMTP authentication failed. Check MAIL_USERNAME and MAIL_PASSWORD.'}
    except smtplib.SMTPException as e:
        return {'success': False, 'error': f'SMTP error: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Failed to send email: {str(e)}'}
