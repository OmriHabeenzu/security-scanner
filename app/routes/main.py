from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@bp.route('/dashboard')
def dashboard():
    """Redirect to appropriate dashboard"""
    if current_user.is_authenticated:
        return redirect(url_for('scanner.user_dashboard'))
    else:
        return redirect(url_for('scanner.guest_dashboard'))
