"""
DarkNet Defend - Notification Service
Handles Email and SMS notifications for data leak alerts
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os

class NotificationService:
    """Handles sending notifications via Email and SMS"""
    
    def __init__(self, app=None):
        self.app = app
        self.email_enabled = False
        self.sms_enabled = False
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize notification service with Flask app config"""
        self.app = app
        
        # Email configuration
        self.smtp_server = app.config.get('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = app.config.get('SMTP_PORT', 587)
        self.smtp_username = app.config.get('SMTP_USERNAME', '')
        self.smtp_password = app.config.get('SMTP_PASSWORD', '')
        self.email_from = app.config.get('EMAIL_FROM', 'noreply@darknetdefend.com')
        self.email_enabled = bool(self.smtp_username and self.smtp_password)
        
        # Twilio SMS configuration
        self.twilio_sid = app.config.get('TWILIO_ACCOUNT_SID', '')
        self.twilio_token = app.config.get('TWILIO_AUTH_TOKEN', '')
        self.twilio_phone = app.config.get('TWILIO_PHONE_NUMBER', '')
        self.sms_enabled = bool(self.twilio_sid and self.twilio_token and self.twilio_phone)
    
    def send_email(self, to_email, subject, html_body, text_body=None):
        """
        Send email notification
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_body: HTML content of email
            text_body: Plain text fallback (optional)
        
        Returns:
            dict with success status and message
        """
        print(f"📧 Email Debug: email_enabled={self.email_enabled}, username={self.smtp_username}")
        
        if not self.email_enabled:
            # Demo mode - log the email instead of sending
            print(f"📧 [DEMO] Email notification to {to_email}")
            print(f"   Subject: {subject}")
            return {
                'success': True,
                'message': 'Email logged (demo mode - configure SMTP for real emails)',
                'demo_mode': True
            }
        
        try:
            print(f"📧 Sending real email to {to_email}...")
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.email_from
            msg['To'] = to_email
            
            # Add plain text if provided
            if text_body:
                text_part = MIMEText(text_body, 'plain')
                msg.attach(text_part)
            
            # Add HTML content
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Connect and send
            print(f"📧 Connecting to {self.smtp_server}:{self.smtp_port}...")
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                print(f"📧 Logging in as {self.smtp_username}...")
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.smtp_username, to_email, msg.as_string())
            
            print(f"📧 Email sent successfully to {to_email}!")
            return {'success': True, 'message': 'Email sent successfully'}
            
        except Exception as e:
            print(f"📧 Email Error: {str(e)}")
            return {'success': False, 'message': f'Failed to send email: {str(e)}'}
    
    def send_sms(self, to_phone, message):
        """
        Send SMS notification via Twilio
        
        Args:
            to_phone: Recipient phone number (with country code)
            message: SMS message content
        
        Returns:
            dict with success status and message
        """
        # Format phone number - add +91 for India if no country code present
        formatted_phone = to_phone.strip() if to_phone else ''
        if formatted_phone and not formatted_phone.startswith('+'):
            # Remove any leading zeros
            formatted_phone = formatted_phone.lstrip('0')
            # Add India country code
            formatted_phone = '+91' + formatted_phone
        
        print(f"📱 SMS Debug: sms_enabled={self.sms_enabled}, sid={self.twilio_sid[:10] if self.twilio_sid else 'None'}...")
        print(f"📱 Phone formatted: {to_phone} -> {formatted_phone}")
        
        if not self.sms_enabled:
            # Demo mode - log the SMS instead of sending
            print(f"📱 [DEMO] SMS notification to {formatted_phone}")
            print(f"   Message: {message[:100]}...")
            return {
                'success': True,
                'message': 'SMS logged (demo mode - configure Twilio for real SMS)',
                'demo_mode': True
            }
        
        try:
            from twilio.rest import Client
            import time
            
            print(f"📱 Sending real SMS to {formatted_phone}...")
            client = Client(self.twilio_sid, self.twilio_token)
            
            sms = client.messages.create(
                body=message,
                from_=self.twilio_phone,
                to=formatted_phone
            )
            
            print(f"📱 SMS queued! SID: {sms.sid}, Status: {sms.status}")
            
            # Wait a moment and check delivery status
            time.sleep(2)
            updated_sms = client.messages(sms.sid).fetch()
            print(f"📱 SMS Status after 2s: {updated_sms.status}")
            
            if updated_sms.status in ['delivered', 'sent', 'queued', 'accepted']:
                return {'success': True, 'message': f'SMS {updated_sms.status} (SID: {sms.sid})'}
            elif updated_sms.status == 'failed':
                error_info = f"Error {updated_sms.error_code}: Carrier may be blocking international SMS. Try upgrading Twilio account."
                print(f"📱 SMS Failed: {error_info}")
                return {'success': False, 'message': error_info}
            else:
                return {'success': True, 'message': f'SMS status: {updated_sms.status} (SID: {sms.sid})'}
            
        except ImportError:
            return {'success': False, 'message': 'Twilio library not installed. Run: pip install twilio'}
        except Exception as e:
            error_msg = str(e)
            print(f"📱 SMS Error: {error_msg}")
            return {'success': False, 'message': f'Failed to send SMS: {error_msg}'}
    
    def send_data_leak_alert(self, user, leak_info):
        """
        Send data leak alert to user via both Email and SMS
        
        Args:
            user: User object with email and phone
            leak_info: Dict containing leak details:
                - leak_type: Type of leak (image, video, text, document, etc.)
                - data_description: Description of leaked data
                - source: Where the leak was detected
                - severity: Leak severity (low, medium, high, critical)
                - prevention_action: Action taken to prevent leak
                - detected_at: When leak was detected
        
        Returns:
            dict with email and sms send results
        """
        results = {'email': None, 'sms': None}
        
        leak_type = leak_info.get('leak_type', 'Unknown')
        data_description = leak_info.get('data_description', 'Personal data')
        source = leak_info.get('source', 'Unknown source')
        severity = leak_info.get('severity', 'high')
        prevention_action = leak_info.get('prevention_action', 'Blocked and logged')
        detected_at = leak_info.get('detected_at', datetime.utcnow())
        
        # Severity emoji and color mapping
        severity_map = {
            'low': {'emoji': '⚠️', 'color': '#ffc107'},
            'medium': {'emoji': '🟠', 'color': '#fd7e14'},
            'high': {'emoji': '🔴', 'color': '#dc3545'},
            'critical': {'emoji': '🚨', 'color': '#721c24'}
        }
        sev_info = severity_map.get(severity, severity_map['high'])
        
        # Data type emoji mapping
        type_emoji = {
            'image': '🖼️',
            'video': '🎥',
            'text': '📝',
            'document': '📄',
            'audio': '🔊',
            'credentials': '🔐',
            'financial': '💳',
            'personal': '👤',
            'location': '📍',
            'contact': '📞'
        }
        type_icon = type_emoji.get(leak_type.lower(), '📊')
        
        # Send Email
        if user.email:
            email_subject = f"{sev_info['emoji']} Data Leak Alert: {leak_type} Data Detected - DarkNet Defend"
            
            email_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .alert-box {{ background: {sev_info['color']}20; border-left: 4px solid {sev_info['color']}; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                    .content {{ background: #f8f9fa; padding: 25px; border-radius: 0 0 10px 10px; }}
                    .data-type {{ font-size: 48px; margin-bottom: 10px; }}
                    .info-row {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #dee2e6; }}
                    .label {{ color: #6c757d; font-weight: bold; }}
                    .value {{ color: #212529; }}
                    .prevention {{ background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin-top: 20px; }}
                    .footer {{ text-align: center; margin-top: 20px; color: #6c757d; font-size: 12px; }}
                    .btn {{ display: inline-block; background: #0d6efd; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 15px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="data-type">{type_icon}</div>
                        <h1>Data Leak Detected!</h1>
                        <p>{leak_type.upper()} data potentially exposed</p>
                    </div>
                    <div class="content">
                        <div class="alert-box">
                            <strong>{sev_info['emoji']} {severity.upper()} SEVERITY ALERT</strong><br>
                            We detected a potential data leak associated with your account.
                        </div>
                        
                        <div class="info-row">
                            <span class="label">Data Type:</span>
                            <span class="value">{type_icon} {leak_type}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Description:</span>
                            <span class="value">{data_description}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Source:</span>
                            <span class="value">{source}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Detected At:</span>
                            <span class="value">{detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                        </div>
                        
                        <div class="prevention">
                            <strong>✅ Prevention Action Taken:</strong><br>
                            {prevention_action}
                        </div>
                        
                        <h3>Recommended Actions:</h3>
                        <ul>
                            <li>Review your account security settings</li>
                            <li>Change passwords for affected services</li>
                            <li>Enable two-factor authentication</li>
                            <li>Check for unauthorized access to your accounts</li>
                        </ul>
                        
                        <center>
                            <a href="#" class="btn">View Full Report in Dashboard</a>
                        </center>
                    </div>
                    <div class="footer">
                        <p>This is an automated security alert from DarkNet Defend.<br>
                        You received this because you registered for data leak monitoring.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            email_text = f"""
            DATA LEAK ALERT - DarkNet Defend
            ================================
            
            {sev_info['emoji']} {severity.upper()} SEVERITY
            
            A potential data leak has been detected:
            
            Data Type: {leak_type}
            Description: {data_description}
            Source: {source}
            Detected At: {detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
            
            Prevention Action: {prevention_action}
            
            Please login to your dashboard for more details.
            """
            
            results['email'] = self.send_email(user.email, email_subject, email_html, email_text)
        
        # Send SMS
        if user.phone:
            sms_message = (
                f"🚨 DarkNet Defend Alert\n"
                f"{type_icon} {leak_type.upper()} DATA LEAK DETECTED!\n"
                f"Severity: {severity.upper()}\n"
                f"Source: {source}\n"
                f"Action: {prevention_action}\n"
                f"Login to dashboard for details."
            )
            
            results['sms'] = self.send_sms(user.phone, sms_message)
        
        return results


# Global notification service instance
notification_service = NotificationService()
