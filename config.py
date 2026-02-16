import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Security Settings
    SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Dark Web Monitoring Settings
    MONITORING_INTERVAL_MINUTES = 30
    ALERT_RETENTION_DAYS = 90
    
    # ============================================
    # Email Notification Settings (SMTP)
    # ============================================
    # For Gmail: Use App Password (https://myaccount.google.com/apppasswords)
    # For other providers: Use appropriate SMTP settings
    SMTP_SERVER = os.environ.get('SMTP_SERVER') or 'smtp.gmail.com'
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME') or 'your-email@gmail.com'
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD') or 'your-app-password'
    EMAIL_FROM = os.environ.get('EMAIL_FROM') or 'DarkNet Defend <your-email@gmail.com>'
    
    # ============================================
    # SMS Notification Settings (Twilio)
    # ============================================
    # Sign up at https://www.twilio.com/ for credentials
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID') or 'your-twilio-account-sid'
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN') or 'your-twilio-auth-token'
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER') or '+1234567890'
    
    # ============================================
    # Data Leak Detection Settings
    # ============================================
    LEAK_CHECK_INTERVAL_MINUTES = 15  # How often to check for leaks
    LEAK_SOURCES = [
        'dark_web_forums',
        'paste_sites',
        'data_breach_databases',
        'social_media',
        'file_sharing_sites'
    ]
    
    # Types of data to monitor
    MONITORED_DATA_TYPES = [
        'image',
        'video',
        'text',
        'document',
        'audio',
        'credentials',
        'financial',
        'personal',
        'location',
        'contact'
    ]
    
    # Prevention settings
    AUTO_PREVENTION_ENABLED = True
    TAKEDOWN_REQUEST_ENABLED = True