from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    monitored_credentials = db.relationship('MonitoredCredential', backref='user', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class MonitoredCredential(db.Model):
    __tablename__ = 'monitored_credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    credential_type = db.Column(db.String(50), nullable=False)  # email, phone, credit_card
    credential_value = db.Column(db.String(255), nullable=False)
    is_compromised = db.Column(db.Boolean, default=False)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<MonitoredCredential {self.credential_type}>'


class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)  # credential_leak, sql_injection, data_breach
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Alert {self.title}>'


class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    log_type = db.Column(db.String(50), nullable=False)  # sql_injection_attempt, login_attempt, suspicious_activity
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    details = db.Column(db.Text)
    severity = db.Column(db.String(20))
    blocked = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<SecurityLog {self.log_type} at {self.timestamp}>'


class DataLeakReport(db.Model):
    __tablename__ = 'data_leak_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(200), nullable=False)
    leak_type = db.Column(db.String(100))
    records_affected = db.Column(db.Integer)
    date_discovered = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    
    def __repr__(self):
        return f'<DataLeakReport {self.source}>'


class DataLeakDetection(db.Model):
    """Tracks individual data leak detections for users"""
    __tablename__ = 'data_leak_detections'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # What type of data was leaked
    data_type = db.Column(db.String(50), nullable=False)  # image, video, text, document, audio, credentials, financial, personal
    data_description = db.Column(db.Text)
    
    # Where the leak was detected
    source = db.Column(db.String(255), nullable=False)  # website, dark web forum, paste site, etc.
    source_url = db.Column(db.String(500))
    
    # Leak details
    severity = db.Column(db.String(20), nullable=False, default='high')  # low, medium, high, critical
    leak_hash = db.Column(db.String(64))  # Hash of leaked data for identification
    
    # Prevention status
    is_prevented = db.Column(db.Boolean, default=False)
    prevention_action = db.Column(db.String(255))  # e.g., "Blocked", "Takedown requested", "User notified"
    prevention_timestamp = db.Column(db.DateTime)
    
    # Notification status
    email_notified = db.Column(db.Boolean, default=False)
    sms_notified = db.Column(db.Boolean, default=False)
    notification_timestamp = db.Column(db.DateTime)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('leak_detections', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<DataLeakDetection {self.data_type} for user {self.user_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'data_type': self.data_type,
            'data_description': self.data_description,
            'source': self.source,
            'severity': self.severity,
            'is_prevented': self.is_prevented,
            'prevention_action': self.prevention_action,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'email_notified': self.email_notified,
            'sms_notified': self.sms_notified
        }


class NotificationPreference(db.Model):
    """User notification preferences"""
    __tablename__ = 'notification_preferences'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # Email preferences
    email_enabled = db.Column(db.Boolean, default=True)
    email_on_leak_detected = db.Column(db.Boolean, default=True)
    email_on_prevention = db.Column(db.Boolean, default=True)
    email_daily_summary = db.Column(db.Boolean, default=False)
    
    # SMS preferences
    sms_enabled = db.Column(db.Boolean, default=True)
    sms_on_critical_only = db.Column(db.Boolean, default=False)  # Only send SMS for critical leaks
    sms_on_leak_detected = db.Column(db.Boolean, default=True)
    
    # Monitoring preferences
    monitor_email = db.Column(db.Boolean, default=True)
    monitor_phone = db.Column(db.Boolean, default=True)
    monitor_images = db.Column(db.Boolean, default=True)
    monitor_documents = db.Column(db.Boolean, default=True)
    monitor_credentials = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('notification_preferences', uselist=False, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<NotificationPreference for user {self.user_id}>'


class MonitoredAsset(db.Model):
    """Assets being monitored for data leaks (emails, phones, images, documents)"""
    __tablename__ = 'monitored_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Asset details
    asset_type = db.Column(db.String(50), nullable=False)  # email, phone, image, document, video, text
    asset_identifier = db.Column(db.String(255), nullable=False)  # email address, phone, file hash, etc.
    asset_name = db.Column(db.String(200))  # Friendly name like "Personal Email"
    asset_hash = db.Column(db.String(64))  # SHA256 hash for file assets
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_compromised = db.Column(db.Boolean, default=False)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    last_leak_detected = db.Column(db.DateTime)
    total_leaks_found = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('monitored_assets', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<MonitoredAsset {self.asset_type}: {self.asset_identifier[:20]}>'