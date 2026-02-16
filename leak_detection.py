"""
DarkNet Defend - Data Leak Detection Service
Monitors for data leaks and triggers notifications
"""

import hashlib
import random
from datetime import datetime, timedelta
from threading import Thread
import time

class DataLeakDetector:
    """
    Monitors registered user assets for data leaks across various sources.
    Simulates dark web and data breach monitoring in demo mode.
    """
    
    # Simulated leak sources for demonstration
    LEAK_SOURCES = [
        {'name': 'Dark Web Forum Alpha', 'type': 'dark_web_forum'},
        {'name': 'Underground Marketplace', 'type': 'marketplace'},
        {'name': 'Paste Site XYZ', 'type': 'paste_site'},
        {'name': 'Data Breach Database', 'type': 'breach_database'},
        {'name': 'Telegram Channel', 'type': 'messaging_platform'},
        {'name': 'Hacker Forum Beta', 'type': 'hacker_forum'},
        {'name': 'Leaked Database Collection', 'type': 'data_dump'},
        {'name': 'File Sharing Network', 'type': 'file_sharing'},
    ]
    
    # Simulated compromised data patterns
    KNOWN_COMPROMISED = {
        'emails': ['test@example.com', 'demo@gmail.com', 'leaked@test.com', 'victim@breach.com'],
        'phones': ['+1555010012', '555-0100', '+919876543210'],
        'documents': ['financial_report_2024.pdf', 'passport_scan.jpg', 'id_card.png'],
    }
    
    def __init__(self, app=None, db=None, notification_service=None):
        self.app = app
        self.db = db
        self.notification_service = notification_service
        self._monitoring_thread = None
        self._stop_monitoring = False
    
    def init_app(self, app, db, notification_service):
        """Initialize with Flask app"""
        self.app = app
        self.db = db
        self.notification_service = notification_service
    
    def check_for_leaks(self, asset_type, asset_value, user_id=None):
        """
        Check if an asset has been leaked.
        
        In production, this would connect to:
        - Have I Been Pwned API
        - Dark web monitoring services
        - Threat intelligence feeds
        - Image recognition services for photo leaks
        
        Args:
            asset_type: Type of asset (email, phone, image, document, etc.)
            asset_value: The value to check (email address, phone, file hash, etc.)
            user_id: Optional user ID for logging
        
        Returns:
            dict with leak information
        """
        result = {
            'is_leaked': False,
            'leak_type': asset_type,
            'source': None,
            'severity': 'low',
            'data_description': '',
            'detected_at': datetime.utcnow(),
            'prevention_possible': True,
            'prevention_action': None
        }
        
        # Simulated leak detection logic
        is_leaked = False
        
        # Check against known compromised data
        if asset_type == 'email' and asset_value.lower() in [e.lower() for e in self.KNOWN_COMPROMISED['emails']]:
            is_leaked = True
        elif asset_type == 'phone' and asset_value in self.KNOWN_COMPROMISED['phones']:
            is_leaked = True
        elif asset_type in ['document', 'image'] and asset_value in self.KNOWN_COMPROMISED['documents']:
            is_leaked = True
        
        # Add some randomness for demo (15% chance for new assets)
        if not is_leaked and random.random() < 0.15:
            is_leaked = True
        
        if is_leaked:
            source = random.choice(self.LEAK_SOURCES)
            result.update({
                'is_leaked': True,
                'source': source['name'],
                'source_type': source['type'],
                'severity': self._calculate_severity(asset_type, source['type']),
                'data_description': self._generate_description(asset_type, asset_value),
                'prevention_possible': True
            })
        
        return result
    
    def _calculate_severity(self, asset_type, source_type):
        """Calculate severity based on data type and source"""
        high_risk_types = ['credentials', 'financial', 'image', 'video', 'document']
        critical_sources = ['marketplace', 'hacker_forum', 'data_dump']
        
        if asset_type in high_risk_types and source_type in critical_sources:
            return 'critical'
        elif asset_type in high_risk_types:
            return 'high'
        elif source_type in critical_sources:
            return 'high'
        else:
            return 'medium'
    
    def _generate_description(self, asset_type, asset_value):
        """Generate description for the leaked data"""
        descriptions = {
            'email': f'Email address "{asset_value}" found in data breach',
            'phone': f'Phone number "{asset_value}" exposed in leak',
            'image': f'Image file detected in unauthorized sharing',
            'video': f'Video content found on file sharing platform',
            'document': f'Document "{asset_value}" leaked to unauthorized site',
            'text': f'Text content containing personal information exposed',
            'credentials': f'Login credentials potentially compromised',
            'financial': f'Financial information detected in data breach',
            'personal': f'Personal information found in leaked database',
            'location': f'Location data exposed in privacy breach',
            'contact': f'Contact information leaked to third parties'
        }
        return descriptions.get(asset_type, f'{asset_type} data potentially exposed')
    
    def prevent_leak(self, leak_detection):
        """
        Attempt to prevent/mitigate a detected leak.
        
        In production, this could:
        - Request content takedown
        - Block access to leaked data
        - Notify affected services
        - Initiate legal action
        
        Args:
            leak_detection: DataLeakDetection model instance
        
        Returns:
            dict with prevention result
        """
        prevention_actions = [
            'Takedown request submitted to hosting provider',
            'Content flagged for removal',
            'Access blocked at network level',
            'Affected services notified',
            'Data encryption enabled for future protection',
            'Monitoring increased for similar leaks',
            'DMCA takedown notice sent'
        ]
        
        action = random.choice(prevention_actions)
        
        return {
            'success': True,
            'action_taken': action,
            'timestamp': datetime.utcnow(),
            'additional_steps': [
                'Changed associated passwords',
                'Enabled 2FA on linked accounts',
                'Added to enhanced monitoring list'
            ]
        }
    
    def scan_user_assets(self, user):
        """
        Scan all monitored assets for a user.
        
        Args:
            user: User model instance
        
        Returns:
            list of detected leaks
        """
        from models import MonitoredAsset, DataLeakDetection, NotificationPreference
        
        detected_leaks = []
        
        with self.app.app_context():
            # Get user's monitored assets
            assets = MonitoredAsset.query.filter_by(
                user_id=user.id,
                is_active=True
            ).all()
            
            # Also check user's email and phone
            assets_to_check = [
                {'type': 'email', 'value': user.email, 'name': 'Primary Email'},
            ]
            if user.phone:
                assets_to_check.append({'type': 'phone', 'value': user.phone, 'name': 'Primary Phone'})
            
            for asset in assets:
                assets_to_check.append({
                    'type': asset.asset_type,
                    'value': asset.asset_identifier,
                    'name': asset.asset_name or asset.asset_identifier
                })
            
            # Check each asset
            for asset_info in assets_to_check:
                leak_result = self.check_for_leaks(
                    asset_info['type'],
                    asset_info['value'],
                    user.id
                )
                
                if leak_result['is_leaked']:
                    # Create leak detection record
                    leak = DataLeakDetection(
                        user_id=user.id,
                        data_type=leak_result['leak_type'],
                        data_description=leak_result['data_description'],
                        source=leak_result['source'],
                        severity=leak_result['severity'],
                        detected_at=leak_result['detected_at']
                    )
                    
                    # Attempt prevention
                    prevention = self.prevent_leak(leak)
                    if prevention['success']:
                        leak.is_prevented = True
                        leak.prevention_action = prevention['action_taken']
                        leak.prevention_timestamp = prevention['timestamp']
                    
                    self.db.session.add(leak)
                    self.db.session.commit()
                    
                    # Send notifications
                    self._send_notifications(user, leak)
                    
                    detected_leaks.append(leak)
        
        return detected_leaks
    
    def _send_notifications(self, user, leak_detection):
        """Send email and SMS notifications for a detected leak"""
        from models import NotificationPreference
        
        # Get user preferences
        prefs = NotificationPreference.query.filter_by(user_id=user.id).first()
        
        # Default to sending if no preferences set
        send_email = True
        send_sms = True
        
        if prefs:
            send_email = prefs.email_enabled and prefs.email_on_leak_detected
            send_sms = prefs.sms_enabled and prefs.sms_on_leak_detected
            
            # Check if SMS is critical-only
            if prefs.sms_on_critical_only and leak_detection.severity not in ['critical', 'high']:
                send_sms = False
        
        leak_info = {
            'leak_type': leak_detection.data_type,
            'data_description': leak_detection.data_description,
            'source': leak_detection.source,
            'severity': leak_detection.severity,
            'prevention_action': leak_detection.prevention_action or 'Under investigation',
            'detected_at': leak_detection.detected_at
        }
        
        if self.notification_service:
            # Create a modified user object with only the needed contact info
            class NotifyUser:
                def __init__(self, email, phone):
                    self.email = email if send_email else None
                    self.phone = phone if send_sms else None
            
            notify_user = NotifyUser(user.email, user.phone)
            results = self.notification_service.send_data_leak_alert(notify_user, leak_info)
            
            # Update notification status
            if results.get('email', {}).get('success'):
                leak_detection.email_notified = True
            if results.get('sms', {}).get('success'):
                leak_detection.sms_notified = True
            leak_detection.notification_timestamp = datetime.utcnow()
            
            self.db.session.commit()
    
    def start_background_monitoring(self, interval_minutes=15):
        """Start background monitoring thread"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return  # Already running
        
        self._stop_monitoring = False
        self._monitoring_thread = Thread(target=self._monitoring_loop, args=(interval_minutes,))
        self._monitoring_thread.daemon = True
        self._monitoring_thread.start()
        print(f"🔍 Background leak monitoring started (interval: {interval_minutes} min)")
    
    def stop_background_monitoring(self):
        """Stop background monitoring"""
        self._stop_monitoring = True
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        print("🛑 Background leak monitoring stopped")
    
    def _monitoring_loop(self, interval_minutes):
        """Background monitoring loop"""
        from models import User
        
        while not self._stop_monitoring:
            try:
                with self.app.app_context():
                    users = User.query.all()
                    for user in users:
                        try:
                            self.scan_user_assets(user)
                        except Exception as e:
                            print(f"Error scanning user {user.id}: {e}")
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
            
            # Sleep for the interval
            for _ in range(interval_minutes * 60):
                if self._stop_monitoring:
                    break
                time.sleep(1)
    
    def simulate_leak_detection(self, user_id, data_type, description=None):
        """
        Manually simulate a leak detection for testing.
        
        Args:
            user_id: ID of the user
            data_type: Type of data leaked
            description: Optional description
        
        Returns:
            DataLeakDetection instance
        """
        from models import User, DataLeakDetection
        
        with self.app.app_context():
            user = User.query.get(user_id)
            if not user:
                return None
            
            source = random.choice(self.LEAK_SOURCES)
            
            leak = DataLeakDetection(
                user_id=user_id,
                data_type=data_type,
                data_description=description or self._generate_description(data_type, 'test_asset'),
                source=source['name'],
                severity=self._calculate_severity(data_type, source['type']),
                detected_at=datetime.utcnow()
            )
            
            # Attempt prevention
            prevention = self.prevent_leak(leak)
            leak.is_prevented = prevention['success']
            leak.prevention_action = prevention['action_taken']
            leak.prevention_timestamp = datetime.utcnow()
            
            self.db.session.add(leak)
            self.db.session.commit()
            
            # Send notifications
            self._send_notifications(user, leak)
            
            return leak


# Global detector instance
leak_detector = DataLeakDetector()
