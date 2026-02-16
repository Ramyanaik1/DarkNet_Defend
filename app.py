from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, MonitoredCredential, Alert, SecurityLog, DataLeakReport, DataLeakDetection, NotificationPreference, MonitoredAsset
from config import Config
from datetime import datetime
from notification_service import notification_service
from leak_detection import leak_detector
from browser_scanner import browser_scanner
import re
import hashlib
import random

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize notification service and leak detector
notification_service.init_app(app)
leak_detector.init_app(app, db, notification_service)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# SQL Injection Prevention Middleware
@app.before_request
def detect_sql_injection():
    """Detect potential SQL injection attempts in request parameters"""
    # Skip static files
    if request.endpoint == 'static':
        return None
    
    sql_patterns = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bor\b\s*['\"]?\s*['\"]?\s*=\s*['\"]?)",
        r"(\band\b\s*['\"]?\s*['\"]?\s*=\s*['\"]?)",
        r"(--\s*$)",
        r"(;\s*drop\b)",
        r"(;\s*delete\b)",
        r"(;\s*update\b)",
        r"(\bexec\b.*\()",
        r"(\binsert\b.*\binto\b)",
    ]
    
    # Check all request parameters
    for key, value in request.values.items():
        if isinstance(value, str) and len(value) > 0:
            for pattern in sql_patterns:
                if re.search(pattern, value.lower()):
                    # Log the attempt
                    try:
                        log = SecurityLog(
                            log_type='sql_injection_attempt',
                            ip_address=request.remote_addr,
                            user_agent=request.headers.get('User-Agent', 'Unknown')[:255],
                            details=f"Blocked: {key}={value[:100]}",
                            severity='high',
                            blocked=True
                        )
                        db.session.add(log)
                        
                        # Create alert for logged-in users
                        if current_user.is_authenticated:
                            alert = Alert(
                                user_id=current_user.id,
                                alert_type='sql_injection',
                                severity='high',
                                title='SQL Injection Attack Blocked',
                                description=f'Malicious SQL input detected and blocked: "{value[:50]}..."',
                                source=f'IP: {request.remote_addr}'
                            )
                            db.session.add(alert)
                        
                        db.session.commit()
                    except Exception as e:
                        print(f"Error logging SQL injection: {e}")
                        db.session.rollback()
                    
                    # Flash message and redirect
                    flash(f'🛡️ SQL INJECTION BLOCKED! Detected malicious pattern in your input. This attempt has been logged.', 'danger')
                    return redirect(url_for('dashboard'))
    
    return None


# Simulated Dark Web Monitoring Function
def check_dark_web_leaks(credential_value):
    """
    Simulated dark web check - In production, this would connect to
    threat intelligence APIs or dark web monitoring services
    """
    # Simulate some leaked credentials for demonstration
    known_leaks = [
        'test@example.com',
        'demo@gmail.com',
        '555-0100',
        '4532-1234-5678-9010'
    ]
    
    # Check if in known leaks
    is_leaked = credential_value.lower() in [leak.lower() for leak in known_leaks]
    
    # Add some randomness for demo (30% chance)
    if not is_leaked:
        is_leaked = random.random() < 0.3
    
    return {
        'is_leaked': is_leaked,
        'source': 'Dark Web Forum XYZ' if is_leaked else None,
        'leak_date': datetime.utcnow() if is_leaked else None
    }


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone')
        
        # Validation
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(username=username, email=email, phone=phone)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log successful login
            log = SecurityLog(
                log_type='login_attempt',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown')[:255],
                details=f"Successful login for user: {username}",
                severity='low',
                blocked=False
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Log failed login
            log = SecurityLog(
                log_type='login_attempt',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown')[:255],
                details=f"Failed login attempt for username: {username}",
                severity='medium',
                blocked=True
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Get user statistics
    total_monitored = MonitoredCredential.query.filter_by(user_id=current_user.id).count()
    compromised = MonitoredCredential.query.filter_by(
        user_id=current_user.id, 
        is_compromised=True
    ).count()
    unread_alerts = Alert.query.filter_by(
        user_id=current_user.id, 
        is_read=False
    ).count()
    
    # Recent alerts
    recent_alerts = Alert.query.filter_by(user_id=current_user.id)\
        .order_by(Alert.created_at.desc()).limit(5).all()
    
    # Security logs
    recent_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(10).all()
    
    # SQL injection blocks count
    sql_blocks = SecurityLog.query.filter_by(log_type='sql_injection_attempt').count()
    
    # Data leak detection stats
    leak_detections = DataLeakDetection.query.filter_by(user_id=current_user.id).all()
    leak_detections_count = len(leak_detections)
    leaks_prevented = sum(1 for l in leak_detections if l.is_prevented)
    
    return render_template('dashboard.html',
                         total_monitored=total_monitored,
                         compromised=compromised,
                         unread_alerts=unread_alerts,
                         recent_alerts=recent_alerts,
                         recent_logs=recent_logs,
                         sql_blocks=sql_blocks,
                         leak_detections_count=leak_detections_count,
                         leaks_prevented=leaks_prevented)


@app.route('/monitor/add', methods=['POST'])
@login_required
def add_monitor():
    credential_type = request.form.get('credential_type')
    credential_value = request.form.get('credential_value')
    
    if not credential_type or not credential_value:
        flash('Please provide both credential type and value', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if already monitored
    existing = MonitoredCredential.query.filter_by(
        user_id=current_user.id,
        credential_value=credential_value
    ).first()
    
    if existing:
        flash('This credential is already being monitored', 'warning')
        return redirect(url_for('dashboard'))
    
    # Check for leaks
    leak_result = check_dark_web_leaks(credential_value)
    
    # Add to monitoring
    credential = MonitoredCredential(
        user_id=current_user.id,
        credential_type=credential_type,
        credential_value=credential_value,
        is_compromised=leak_result['is_leaked']
    )
    db.session.add(credential)
    
    # Create alert if leaked
    if leak_result['is_leaked']:
        alert = Alert(
            user_id=current_user.id,
            alert_type='credential_leak',
            severity='critical',
            title=f'{credential_type.title()} Found in Data Breach',
            description=f'Your {credential_type} ({credential_value}) was found in a data breach on {leak_result["source"]}. Please change your password immediately!',
            source=leak_result['source']
        )
        db.session.add(alert)
        flash(f'⚠️ WARNING! This {credential_type} has been found in a data breach!', 'danger')
    else:
        flash(f'✅ {credential_type.title()} added to monitoring. No breaches detected.', 'success')
    
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/alerts')
@login_required
def alerts():
    all_alerts = Alert.query.filter_by(user_id=current_user.id)\
        .order_by(Alert.created_at.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)


@app.route('/alerts/<int:alert_id>/read', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if alert.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    alert.is_read = True
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard statistics"""
    # Alert statistics
    alerts_by_severity = db.session.query(
        Alert.severity, db.func.count(Alert.id)
    ).filter_by(user_id=current_user.id).group_by(Alert.severity).all()
    
    # Security logs by type
    logs_by_type = db.session.query(
        SecurityLog.log_type, db.func.count(SecurityLog.id)
    ).group_by(SecurityLog.log_type).limit(5).all()
    
    return jsonify({
        'alerts_by_severity': dict(alerts_by_severity),
        'logs_by_type': dict(logs_by_type)
    })


# ============================================
# Data Leak Monitoring Routes
# ============================================

@app.route('/leak-monitor')
@login_required
def leak_monitor():
    """Data leak monitoring dashboard"""
    # Get user's leak detections
    leak_detections = DataLeakDetection.query.filter_by(user_id=current_user.id)\
        .order_by(DataLeakDetection.detected_at.desc()).all()
    
    # Get monitored assets
    monitored_assets = MonitoredAsset.query.filter_by(user_id=current_user.id, is_active=True).all()
    
    # Statistics
    total_leaks = len(leak_detections)
    prevented_leaks = sum(1 for l in leak_detections if l.is_prevented)
    critical_leaks = sum(1 for l in leak_detections if l.severity == 'critical')
    
    # Group by data type
    leak_by_type = {}
    for leak in leak_detections:
        leak_by_type[leak.data_type] = leak_by_type.get(leak.data_type, 0) + 1
    
    return render_template('leak_monitor.html',
                         leak_detections=leak_detections,
                         monitored_assets=monitored_assets,
                         total_leaks=total_leaks,
                         prevented_leaks=prevented_leaks,
                         critical_leaks=critical_leaks,
                         leak_by_type=leak_by_type)


@app.route('/leak-monitor/add-asset', methods=['POST'])
@login_required
def add_monitored_asset():
    """Add a new asset to monitor for leaks"""
    asset_type = request.form.get('asset_type')
    asset_value = request.form.get('asset_value')
    asset_name = request.form.get('asset_name', '')
    
    if not asset_type or not asset_value:
        flash('Please provide asset type and value', 'error')
        return redirect(url_for('leak_monitor'))
    
    # Check if already exists
    existing = MonitoredAsset.query.filter_by(
        user_id=current_user.id,
        asset_identifier=asset_value
    ).first()
    
    if existing:
        flash('This asset is already being monitored', 'warning')
        return redirect(url_for('leak_monitor'))
    
    # Generate hash for file-type assets
    asset_hash = None
    if asset_type in ['image', 'video', 'document']:
        asset_hash = hashlib.sha256(asset_value.encode()).hexdigest()
    
    # Create the asset
    asset = MonitoredAsset(
        user_id=current_user.id,
        asset_type=asset_type,
        asset_identifier=asset_value,
        asset_name=asset_name or asset_value,
        asset_hash=asset_hash
    )
    
    db.session.add(asset)
    db.session.commit()
    
    # Immediately check for leaks
    leak_result = leak_detector.check_for_leaks(asset_type, asset_value, current_user.id)
    
    if leak_result['is_leaked']:
        # Record the leak
        leak = DataLeakDetection(
            user_id=current_user.id,
            data_type=leak_result['leak_type'],
            data_description=leak_result['data_description'],
            source=leak_result['source'],
            severity=leak_result['severity'],
            detected_at=datetime.utcnow()
        )
        
        # Attempt prevention
        prevention = leak_detector.prevent_leak(leak)
        leak.is_prevented = prevention['success']
        leak.prevention_action = prevention['action_taken']
        leak.prevention_timestamp = datetime.utcnow()
        
        db.session.add(leak)
        
        # Update asset status
        asset.is_compromised = True
        asset.last_leak_detected = datetime.utcnow()
        asset.total_leaks_found = 1
        
        db.session.commit()
        
        # Send notifications
        leak_detector._send_notifications(current_user, leak)
        
        flash(f'⚠️ ALERT! Leak detected for {asset_type}: {asset_value[:30]}... Notifications sent!', 'danger')
    else:
        flash(f'✅ {asset_type.title()} added to monitoring. No leaks detected currently.', 'success')
    
    return redirect(url_for('leak_monitor'))


@app.route('/leak-monitor/remove-asset/<int:asset_id>', methods=['POST'])
@login_required
def remove_monitored_asset(asset_id):
    """Remove an asset from monitoring"""
    asset = MonitoredAsset.query.get_or_404(asset_id)
    
    if asset.user_id != current_user.id:
        flash('Unauthorized', 'error')
        return redirect(url_for('leak_monitor'))
    
    db.session.delete(asset)
    db.session.commit()
    
    flash('Asset removed from monitoring', 'success')
    return redirect(url_for('leak_monitor'))


@app.route('/leak-monitor/scan', methods=['POST'])
@login_required
def manual_leak_scan():
    """Manually trigger a leak scan for the current user"""
    try:
        detected = leak_detector.scan_user_assets(current_user)
        
        if detected:
            flash(f'🚨 Scan complete! {len(detected)} potential leaks detected. Check your email/SMS for details.', 'warning')
        else:
            flash('✅ Scan complete! No new leaks detected.', 'success')
    except Exception as e:
        flash(f'Error during scan: {str(e)}', 'error')
    
    return redirect(url_for('leak_monitor'))


@app.route('/leak-monitor/simulate', methods=['POST'])
@login_required
def simulate_leak():
    """Simulate a data leak for testing notifications"""
    data_type = request.form.get('data_type', 'image')
    description = request.form.get('description', f'Test {data_type} leak simulation')
    
    try:
        leak = leak_detector.simulate_leak_detection(
            current_user.id,
            data_type,
            description
        )
        
        if leak:
            flash(f'🔔 Simulated {data_type} leak created! Check your email and SMS for notifications.', 'info')
        else:
            flash('Failed to simulate leak', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('leak_monitor'))


# ============================================
# Notification Settings Routes
# ============================================

@app.route('/notification-settings', methods=['GET', 'POST'])
@login_required
def notification_settings():
    """Manage notification preferences"""
    # Get or create preferences
    prefs = NotificationPreference.query.filter_by(user_id=current_user.id).first()
    
    if not prefs:
        prefs = NotificationPreference(user_id=current_user.id)
        db.session.add(prefs)
        db.session.commit()
    
    if request.method == 'POST':
        # Update preferences
        prefs.email_enabled = 'email_enabled' in request.form
        prefs.email_on_leak_detected = 'email_on_leak_detected' in request.form
        prefs.email_on_prevention = 'email_on_prevention' in request.form
        prefs.email_daily_summary = 'email_daily_summary' in request.form
        
        prefs.sms_enabled = 'sms_enabled' in request.form
        prefs.sms_on_critical_only = 'sms_on_critical_only' in request.form
        prefs.sms_on_leak_detected = 'sms_on_leak_detected' in request.form
        
        prefs.monitor_email = 'monitor_email' in request.form
        prefs.monitor_phone = 'monitor_phone' in request.form
        prefs.monitor_images = 'monitor_images' in request.form
        prefs.monitor_documents = 'monitor_documents' in request.form
        prefs.monitor_credentials = 'monitor_credentials' in request.form
        
        # Update phone if provided - ensure it has country code
        new_phone = request.form.get('phone', '').strip()
        if new_phone:
            # Add +91 if no country code present
            if not new_phone.startswith('+'):
                new_phone = '+91' + new_phone.lstrip('0')
            if new_phone != current_user.phone:
                current_user.phone = new_phone
        
        db.session.commit()
        flash('✅ Notification settings updated successfully!', 'success')
        return redirect(url_for('notification_settings'))
    
    return render_template('notification_settings.html', prefs=prefs)


@app.route('/notification-settings/test-email', methods=['POST'])
@login_required
def test_email_notification():
    """Send a test email notification"""
    result = notification_service.send_email(
        current_user.email,
        '🧪 Test Notification - DarkNet Defend',
        '''
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h1 style="color: #0d6efd;">✅ Email Notifications Working!</h1>
            <p>This is a test email from DarkNet Defend.</p>
            <p>Your email notifications are properly configured.</p>
            <hr>
            <p style="color: #6c757d; font-size: 12px;">
                If you received this email, your notification settings are working correctly.
            </p>
        </body>
        </html>
        '''
    )
    
    if result['success']:
        flash(f'📧 Test email sent to {current_user.email}!', 'success')
    else:
        flash(f'❌ Failed to send test email: {result["message"]}', 'error')
    
    return redirect(url_for('notification_settings'))


@app.route('/notification-settings/test-sms', methods=['POST'])
@login_required
def test_sms_notification():
    """Send a test SMS notification"""
    if not current_user.phone:
        flash('Please add a phone number first', 'error')
        return redirect(url_for('notification_settings'))
    
    # Format phone number - add +91 for India if not present
    phone = current_user.phone.strip()
    if not phone.startswith('+'):
        # Assume India country code if no + prefix
        phone = '+91' + phone.lstrip('0')
    
    result = notification_service.send_sms(
        phone,
        '🧪 DarkNet Defend Test\n\nThis is a test SMS. Your notifications are working!'
    )
    
    if result['success']:
        if result.get('demo_mode') or result.get('trial_limitation'):
            flash(f'📱 SMS logged for {phone}. {result["message"]}', 'warning')
        else:
            flash(f'📱 Test SMS sent to {phone}!', 'success')
    else:
        flash(f'❌ Failed to send test SMS: {result["message"]}', 'error')
    
    return redirect(url_for('notification_settings'))


# ============================================
# API Endpoints for Leak Detection
# ============================================

@app.route('/api/leaks')
@login_required
def api_leaks():
    """Get user's leak detections as JSON"""
    leaks = DataLeakDetection.query.filter_by(user_id=current_user.id)\
        .order_by(DataLeakDetection.detected_at.desc()).limit(50).all()
    
    return jsonify({
        'leaks': [leak.to_dict() for leak in leaks],
        'total': len(leaks)
    })


@app.route('/api/leaks/stats')
@login_required
def api_leak_stats():
    """Get leak statistics for dashboard"""
    leaks = DataLeakDetection.query.filter_by(user_id=current_user.id).all()
    
    stats = {
        'total_leaks': len(leaks),
        'prevented': sum(1 for l in leaks if l.is_prevented),
        'by_type': {},
        'by_severity': {},
        'notifications_sent': {
            'email': sum(1 for l in leaks if l.email_notified),
            'sms': sum(1 for l in leaks if l.sms_notified)
        }
    }
    
    for leak in leaks:
        stats['by_type'][leak.data_type] = stats['by_type'].get(leak.data_type, 0) + 1
        stats['by_severity'][leak.severity] = stats['by_severity'].get(leak.severity, 0) + 1
    
    return jsonify(stats)


# ============================================
# Real-Time Browser Security Scanning Routes
# ============================================

@app.route('/security/scan', methods=['GET'])
@login_required
def security_scan_page():
    """Real-time browser security scanner page"""
    return render_template('security_scan.html')


@app.route('/security/start-scan', methods=['POST'])
@login_required
def start_security_scan():
    """Start a real-time browser security scan"""
    # Get browser data from request
    scan_data = {
        'current_url': request.form.get('current_url', ''),
        'browsing_history': request.form.getlist('history[]'),
        'page_content': request.form.get('page_content', ''),
        'cookies': [],
        'downloads': [],
        'client_ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'referrer': request.headers.get('Referer', ''),
        'outgoing_requests': []
    }
    
    # Parse cookies if provided
    try:
        import json
        cookies_json = request.form.get('cookies', '[]')
        scan_data['cookies'] = json.loads(cookies_json) if cookies_json else []
    except:
        pass
    
    # Initialize browser scanner with notification service
    browser_scanner.notification_service = notification_service
    
    # Perform the scan
    result = browser_scanner.perform_scan(current_user, scan_data)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(result)
    
    if result['threats_found'] > 0:
        flash(f"🚨 ALERT: {result['threats_found']} threat(s) detected! Check your email for details.", 'danger')
    else:
        flash('✅ Scan complete! No threats detected. Your browser is secure.', 'success')
    
    return redirect(url_for('security_scan_page'))


@app.route('/security/simulate-scan', methods=['POST'])
@login_required
def simulate_security_scan():
    """Simulate a browser scan for testing"""
    browser_scanner.notification_service = notification_service
    result = browser_scanner.simulate_browser_scan(current_user)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(result)
    
    flash(f"🔍 Simulated scan complete! {result['threats_found']} threat(s) detected for testing.", 'warning')
    return redirect(url_for('security_scan_page'))


@app.route('/security/take-action', methods=['GET', 'POST'])
@login_required
def take_security_action():
    """Take action on a detected threat"""
    threat_id = request.args.get('threat_id') or request.form.get('threat_id')
    action_type = request.args.get('action') or request.form.get('action', 'block_url')
    target = request.args.get('target') or request.form.get('target', '')
    
    if not target:
        flash('No target specified for action', 'error')
        return redirect(url_for('security_scan_page'))
    
    browser_scanner.notification_service = notification_service
    result = browser_scanner.take_action(current_user, threat_id, action_type, target)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(result)
    
    if result['success']:
        flash(f"✅ {result['message']}", 'success')
    else:
        flash(f"❌ Action failed: {result['message']}", 'error')
    
    return redirect(url_for('security_scan_page'))


@app.route('/security/take-all-actions', methods=['GET', 'POST'])
@login_required
def take_all_security_actions():
    """Block all threats from a scan"""
    scan_id = request.args.get('scan_id') or request.form.get('scan_id')
    
    if scan_id and scan_id in browser_scanner.active_scans:
        scan = browser_scanner.active_scans[scan_id]
        actions_taken = 0
        
        browser_scanner.notification_service = notification_service
        
        for threat in scan.get('threats_found', []):
            if threat.get('action_available'):
                result = browser_scanner.take_action(
                    current_user,
                    None,
                    threat.get('suggested_action', 'block_url'),
                    threat.get('source', '')
                )
                if result['success']:
                    actions_taken += 1
        
        flash(f"✅ {actions_taken} threat(s) blocked successfully!", 'success')
    else:
        flash('Scan not found or expired', 'error')
    
    return redirect(url_for('security_scan_page'))


@app.route('/security/blocked-items', methods=['GET'])
@login_required
def view_blocked_items():
    """View all blocked URLs and IPs"""
    return jsonify({
        'blocked_urls': list(browser_scanner.blocked_urls),
        'blocked_ips': list(browser_scanner.blocked_ips)
    })


@app.route('/security/unblock', methods=['POST'])
@login_required
def unblock_item():
    """Unblock a URL or IP"""
    item_type = request.form.get('type')  # 'url' or 'ip'
    item = request.form.get('item')
    
    if item_type == 'url' and item in browser_scanner.blocked_urls:
        browser_scanner.blocked_urls.remove(item)
        flash(f'✅ URL unblocked: {item}', 'success')
    elif item_type == 'ip' and item in browser_scanner.blocked_ips:
        browser_scanner.blocked_ips.remove(item)
        flash(f'✅ IP unblocked: {item}', 'success')
    else:
        flash('Item not found in blocked list', 'error')
    
    return redirect(url_for('security_scan_page'))


@app.route('/api/security/quick-scan', methods=['POST'])
@login_required
def api_quick_scan():
    """API endpoint for quick browser scan from JavaScript"""
    try:
        import json
        data = request.get_json() or {}
        
        scan_data = {
            'current_url': data.get('url', ''),
            'browsing_history': data.get('history', []),
            'page_content': data.get('content', ''),
            'cookies': data.get('cookies', []),
            'downloads': data.get('downloads', []),
            'client_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'outgoing_requests': data.get('requests', [])
        }
        
        browser_scanner.notification_service = notification_service
        result = browser_scanner.perform_scan(current_user, scan_data)
        
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# Initialize database
with app.app_context():
    db.create_all()
    print("✅ Database initialized successfully!")


if __name__ == '__main__':
    # Run on 0.0.0.0 to allow external access
    app.run(debug=True, host='0.0.0.0', port=5000)