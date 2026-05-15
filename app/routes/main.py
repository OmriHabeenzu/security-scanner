import hmac
import hashlib
import subprocess
import os
from flask import Blueprint, render_template, redirect, url_for, jsonify, request, current_app
from flask_login import current_user

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/about')
def about():
    return render_template('about.html')

@bp.route('/health')
def health():
    return jsonify({'status': 'ok'}), 200

@bp.route('/deploy', methods=['POST'])
def deploy():
    secret = current_app.config.get('DEPLOY_SECRET', '')
    if not secret:
        return jsonify({'error': 'deploy not configured'}), 500

    sig_header = request.headers.get('X-Hub-Signature-256', '')
    expected = 'sha256=' + hmac.new(
        secret.encode(), request.data, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, sig_header):
        return jsonify({'error': 'invalid signature'}), 403

    app_dir = os.path.dirname(current_app.root_path)
    try:
        subprocess.check_output(
            ['git', 'fetch', 'origin', 'main'],
            cwd=app_dir, stderr=subprocess.STDOUT, timeout=60,
        )
        out = subprocess.check_output(
            ['git', 'reset', '--hard', 'origin/main'],
            cwd=app_dir, stderr=subprocess.STDOUT, timeout=30,
        ).decode()
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output.decode()}), 500

    # Signal Passenger to restart the app
    restart_file = os.path.join(app_dir, 'tmp', 'restart.txt')
    os.makedirs(os.path.dirname(restart_file), exist_ok=True)
    open(restart_file, 'w').close()

    return jsonify({'status': 'deployed', 'output': out}), 200


@bp.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        return redirect(url_for('scanner.user_dashboard'))
    else:
        return redirect(url_for('scanner.guest_dashboard'))
