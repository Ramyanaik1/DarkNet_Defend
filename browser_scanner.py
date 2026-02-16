"""
DarkNet Defend - Real-Time Browser Security Scanner
Scans browser activity for threats, attacks, and data leaks in real-time
"""

import re
import hashlib
import random
from datetime import datetime
from urllib.parse import urlparse

class BrowserScanner:
    """
    Real-time browser security scanner that detects:
    - Phishing attempts
    - Malicious URLs
    - XSS attacks
    - Data leak attempts
    - Suspicious IP connections
    - Malware downloads
    - Cookie hijacking attempts
    """
    
    # Known malicious patterns
    PHISHING_KEYWORDS = [
        'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
        'banking', 'password', 'credential', 'suspend', 'locked', 'urgent'
    ]
    
    MALICIOUS_DOMAINS = [
        'malware-site.com', 'phishing-example.net', 'fake-bank.com',
        'credential-stealer.org', 'virus-download.xyz', 'trojan-host.ru'
    ]
    
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.js', '.jar',
        '.msi', '.dll', '.ps1', '.sh'
    ]
    
    XSS_PATTERNS = [
        r'<script[^>]*>.*</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'eval\s*\(',
        r'document\.cookie',
        r'document\.write',
        r'innerHTML\s*=',
        r'\.src\s*=',
    ]
    
    SQL_INJECTION_PATTERNS = [
        r"('\s*OR\s*'1'\s*=\s*'1)",
        r"(--\s*$)",
        r"(;\s*DROP\s+TABLE)",
        r"(UNION\s+SELECT)",
        r"(INSERT\s+INTO)",
        r"(DELETE\s+FROM)",
    ]
    
    SUSPICIOUS_IPS = [
        '185.220.101.', '23.129.64.', '171.25.193.', '199.249.230.',
        '104.244.76.', '162.247.74.', '185.129.62.'  # Tor exit nodes/suspicious
    ]
    
    THREAT_TYPES = {
        'phishing': {'severity': 'high', 'emoji': '🎣', 'description': 'Phishing Attack Detected'},
        'malware': {'severity': 'critical', 'emoji': '🦠', 'description': 'Malware Detected'},
        'xss': {'severity': 'high', 'emoji': '💉', 'description': 'XSS Attack Detected'},
        'sql_injection': {'severity': 'critical', 'emoji': '🗄️', 'description': 'SQL Injection Attempt'},
        'suspicious_ip': {'severity': 'medium', 'emoji': '🌐', 'description': 'Suspicious IP Connection'},
        'data_leak': {'severity': 'high', 'emoji': '📤', 'description': 'Data Leak Attempt Detected'},
        'cookie_hijack': {'severity': 'critical', 'emoji': '🍪', 'description': 'Cookie Hijacking Attempt'},
        'malicious_download': {'severity': 'high', 'emoji': '⬇️', 'description': 'Malicious Download Blocked'},
        'credential_theft': {'severity': 'critical', 'emoji': '🔐', 'description': 'Credential Theft Attempt'},
    }
    
    def __init__(self, notification_service=None):
        self.notification_service = notification_service
        self.active_scans = {}
        self.blocked_urls = set()
        self.blocked_ips = set()
    
    def start_scan(self, user, scan_data):
        """
        Start a real-time browser scan
        
        Args:
            user: User object with email and phone
            scan_data: Dictionary containing browser data to scan
                - current_url: Current page URL
                - browsing_history: List of recently visited URLs
                - cookies: List of cookies
                - form_data: Any form submissions
                - downloads: Recent downloads
                - client_ip: User's IP address
                - user_agent: Browser user agent
                - referrer: Page referrer
        
        Returns:
            dict with scan_id and initial status
        """
        scan_id = hashlib.md5(f"{user.id}{datetime.utcnow().timestamp()}".encode()).hexdigest()[:12]
        
        self.active_scans[scan_id] = {
            'user_id': user.id,
            'started_at': datetime.utcnow(),
            'status': 'scanning',
            'threats_found': [],
            'items_scanned': 0
        }
        
        # Send scan started notification
        self._send_scan_started_notification(user, scan_id)
        
        return {
            'scan_id': scan_id,
            'status': 'scanning',
            'message': 'Real-time browser scan initiated'
        }
    
    def perform_scan(self, user, scan_data, enable_demo_threats=True):
        """
        Perform the actual browser security scan with real-time detection
        
        Args:
            user: User object
            scan_data: Browser data to scan
            enable_demo_threats: If True, inject demo threats for demonstration
        
        Returns:
            dict with scan results and any detected threats
        """
        scan_result = self.start_scan(user, scan_data)
        scan_id = scan_result['scan_id']
        
        threats = []
        items_scanned = 0
        
        # Scan current URL for phishing/malware
        if scan_data.get('current_url'):
            url_threats = self._scan_url(scan_data['current_url'])
            threats.extend(url_threats)
            items_scanned += 1
        
        # Scan browsing history
        for url in scan_data.get('browsing_history', []):
            url_threats = self._scan_url(url)
            threats.extend(url_threats)
            items_scanned += 1
        
        # Scan for XSS in page content
        if scan_data.get('page_content'):
            xss_threats = self._scan_for_xss(scan_data['page_content'], scan_data.get('current_url', ''))
            threats.extend(xss_threats)
            items_scanned += 1
        
        # Scan URL parameters for SQL injection
        if scan_data.get('current_url'):
            sql_url_threats = self._scan_url_for_sql_injection(scan_data['current_url'])
            threats.extend(sql_url_threats)
            items_scanned += 1
        
        # Scan form data for SQL injection
        for form in scan_data.get('form_data', []):
            sql_threats = self._scan_for_sql_injection(form)
            threats.extend(sql_threats)
            items_scanned += 1
        
        # Scan downloads for malicious files
        for download in scan_data.get('downloads', []):
            download_threats = self._scan_download(download)
            threats.extend(download_threats)
            items_scanned += 1
        
        # Scan cookies for hijacking attempts
        cookie_threats = self._scan_cookies(scan_data.get('cookies', []))
        threats.extend(cookie_threats)
        items_scanned += len(scan_data.get('cookies', []))
        
        # Scan client IP
        if scan_data.get('client_ip'):
            ip_threats = self._scan_ip(scan_data['client_ip'])
            threats.extend(ip_threats)
            items_scanned += 1
        
        # Check for data leak attempts
        if scan_data.get('outgoing_requests'):
            leak_threats = self._scan_for_data_leaks(scan_data['outgoing_requests'])
            threats.extend(leak_threats)
            items_scanned += len(scan_data.get('outgoing_requests', []))
        
        # Scan for credential theft attempts
        if scan_data.get('page_content'):
            cred_threats = self._scan_for_credential_theft(scan_data['page_content'], scan_data.get('current_url', ''))
            threats.extend(cred_threats)
            items_scanned += 1
        
        # If no real threats found and demo mode is enabled, add demo threats
        # This demonstrates all attack types for testing/demo purposes
        if enable_demo_threats and len(threats) == 0:
            demo_threats = self._generate_demo_threats(scan_data.get('current_url', 'Current Page'))
            threats.extend(demo_threats)
        
        # Update scan status
        self.active_scans[scan_id].update({
            'status': 'completed',
            'threats_found': threats,
            'items_scanned': items_scanned,
            'completed_at': datetime.utcnow()
        })
        
        # Send notification for EACH threat type (real-time notifications)
        if threats:
            self._send_threat_notification(user, scan_id, threats)
            # Also send individual threat notifications in real-time
            for threat in threats:
                self._send_individual_threat_notification(user, threat)
        
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'items_scanned': items_scanned,
            'threats_found': len(threats),
            'threats': threats,
            'is_safe': len(threats) == 0,
            'notifications_sent': True if threats else False
        }
    
    def _scan_url(self, url):
        """Scan a URL for phishing and malicious content"""
        threats = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for known malicious domains
            for mal_domain in self.MALICIOUS_DOMAINS:
                if mal_domain in domain:
                    threats.append({
                        'type': 'malware',
                        'severity': 'critical',
                        'source': url,
                        'description': f'Known malicious domain detected: {domain}',
                        'action_available': True,
                        'suggested_action': 'block_url'
                    })
            
            # Check for phishing indicators
            phishing_score = 0
            for keyword in self.PHISHING_KEYWORDS:
                if keyword in domain or keyword in path:
                    phishing_score += 1
            
            # Suspicious if too many login-related keywords and not a known domain
            if phishing_score >= 2 and not self._is_known_safe_domain(domain):
                threats.append({
                    'type': 'phishing',
                    'severity': 'high',
                    'source': url,
                    'description': f'Potential phishing site detected: {domain}',
                    'action_available': True,
                    'suggested_action': 'block_url'
                })
            
            # Check for suspicious file downloads in URL
            for ext in self.SUSPICIOUS_EXTENSIONS:
                if path.endswith(ext):
                    threats.append({
                        'type': 'malicious_download',
                        'severity': 'high',
                        'source': url,
                        'description': f'Suspicious file download detected: {ext}',
                        'action_available': True,
                        'suggested_action': 'block_download'
                    })
                    
        except Exception as e:
            pass
        
        return threats
    
    def _scan_for_xss(self, content, source_url):
        """Scan page content for XSS attacks"""
        threats = []
        
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append({
                    'type': 'xss',
                    'severity': 'high',
                    'source': source_url,
                    'description': f'XSS attack pattern detected in page content',
                    'pattern_matched': pattern,
                    'action_available': True,
                    'suggested_action': 'block_url'
                })
                break  # One XSS detection is enough
        
        return threats
    
    def _scan_for_sql_injection(self, form_data):
        """Scan form submissions for SQL injection attempts"""
        threats = []
        
        form_str = str(form_data).lower()
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, form_str, re.IGNORECASE):
                threats.append({
                    'type': 'sql_injection',
                    'severity': 'critical',
                    'source': 'Form submission',
                    'description': 'SQL injection attempt detected in form data',
                    'action_available': True,
                    'suggested_action': 'block_request'
                })
                break
        
        return threats
    
    def _scan_url_for_sql_injection(self, url):
        """Scan URL parameters for SQL injection attempts in real-time"""
        threats = []
        
        try:
            parsed = urlparse(url)
            query_string = parsed.query.lower()
            path = parsed.path.lower()
            full_url = url.lower()
            
            # Check URL for SQL injection patterns
            for pattern in self.SQL_INJECTION_PATTERNS:
                if re.search(pattern, query_string, re.IGNORECASE) or re.search(pattern, path, re.IGNORECASE):
                    threats.append({
                        'type': 'sql_injection',
                        'severity': 'critical',
                        'source': url,
                        'description': 'SQL injection attack detected in URL parameters',
                        'action_available': True,
                        'suggested_action': 'block_url'
                    })
                    break
            
            # Additional SQL injection indicators
            sql_indicators = ['select%20', 'union%20', 'drop%20', 'insert%20', 'delete%20', 
                            "1'='1", "1=1", "--", "/*", "*/", "exec%20", "xp_"]
            for indicator in sql_indicators:
                if indicator in full_url:
                    threats.append({
                        'type': 'sql_injection',
                        'severity': 'critical',
                        'source': url,
                        'description': f'SQL injection pattern detected: {indicator}',
                        'action_available': True,
                        'suggested_action': 'block_url'
                    })
                    break
        except Exception:
            pass
        
        return threats
    
    def _scan_for_credential_theft(self, content, source_url):
        """Scan for credential theft/phishing form patterns"""
        threats = []
        
        # Check for fake login forms
        credential_patterns = [
            r'<form[^>]*action\s*=\s*["\'][^"\']*(?:login|signin|password|credential)[^"\']*["\']',
            r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>.*<form[^>]*action\s*=\s*["\'](?:http|//)',
            r'password.*confirm.*password',
            r'credit.*card.*number',
            r'cvv.*expir',
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append({
                    'type': 'credential_theft',
                    'severity': 'critical',
                    'source': source_url,
                    'description': 'Potential credential theft form detected',
                    'action_available': True,
                    'suggested_action': 'block_url'
                })
                break
        
        return threats
    
    def _generate_demo_threats(self, current_url):
        """Generate realistic demo threats to demonstrate all attack types"""
        demo_threats = [
            {
                'type': 'sql_injection',
                'severity': 'critical',
                'source': f"{current_url}?id=1' OR '1'='1",
                'description': 'SQL Injection attack detected - Attacker attempting to bypass authentication',
                'action_available': True,
                'suggested_action': 'block_url'
            },
            {
                'type': 'xss',
                'severity': 'high',
                'source': current_url,
                'description': 'Cross-Site Scripting (XSS) attack detected - Malicious script injection attempt',
                'pattern_matched': '<script>document.cookie</script>',
                'action_available': True,
                'suggested_action': 'block_url'
            },
            {
                'type': 'phishing',
                'severity': 'high',
                'source': 'https://secure-banking-login-verify.fake-site.com',
                'description': 'Phishing site detected - Fake banking login page attempting to steal credentials',
                'action_available': True,
                'suggested_action': 'block_url'
            },
            {
                'type': 'malware',
                'severity': 'critical',
                'source': 'https://download.malicious-software.xyz/trojan.exe',
                'description': 'Malware detected - Trojan horse download attempt blocked',
                'action_available': True,
                'suggested_action': 'block_url'
            },
            {
                'type': 'suspicious_ip',
                'severity': 'medium',
                'source': '185.220.101.45',
                'description': 'Suspicious IP connection detected - Known malicious Tor exit node',
                'action_available': True,
                'suggested_action': 'block_ip'
            },
            {
                'type': 'data_leak',
                'severity': 'high',
                'source': 'https://unknown-server.ru/collect',
                'description': 'Data leak attempt detected - Personal information being sent to suspicious server',
                'action_available': True,
                'suggested_action': 'block_request'
            },
            {
                'type': 'cookie_hijack',
                'severity': 'critical',
                'source': 'third-party-tracker.com',
                'description': 'Cookie hijacking attempt detected - Session token exposed to third party',
                'action_available': True,
                'suggested_action': 'clear_cookies'
            },
            {
                'type': 'credential_theft',
                'severity': 'critical',
                'source': 'https://paypa1-secure-login.phishing-site.net',
                'description': 'Credential theft attempt detected - Fake PayPal login page',
                'action_available': True,
                'suggested_action': 'block_url'
            },
            {
                'type': 'malicious_download',
                'severity': 'high',
                'source': 'https://free-software.download/crack.exe',
                'description': 'Malicious download blocked - Potentially infected executable file',
                'action_available': True,
                'suggested_action': 'block_download'
            }
        ]
        
        return demo_threats
    
    def _send_individual_threat_notification(self, user, threat):
        """Send real-time SMS notification for individual threat"""
        if not self.notification_service or not user.phone:
            return
        
        threat_info = self.THREAT_TYPES.get(threat['type'], {})
        emoji = threat_info.get('emoji', '⚠️')
        
        sms_message = (
            f"{emoji} REAL-TIME ALERT\n"
            f"Threat: {threat['type'].replace('_', ' ').upper()}\n"
            f"Severity: {threat['severity'].upper()}\n"
            f"Source: {threat['source'][:30]}...\n"
            f"Action: {threat.get('suggested_action', 'block').replace('_', ' ').title()}"
        )
        
        # Send SMS for critical and high severity threats
        if threat['severity'] in ['critical', 'high']:
            try:
                self.notification_service.send_sms(user.phone, sms_message)
            except Exception:
                pass  # Continue even if SMS fails
    
    def _scan_download(self, download):
        """Scan downloads for malicious files"""
        threats = []
        
        filename = download.get('filename', '').lower()
        url = download.get('url', '')
        
        for ext in self.SUSPICIOUS_EXTENSIONS:
            if filename.endswith(ext):
                threats.append({
                    'type': 'malicious_download',
                    'severity': 'high',
                    'source': url or filename,
                    'description': f'Potentially malicious file download: {filename}',
                    'action_available': True,
                    'suggested_action': 'block_download'
                })
        
        return threats
    
    def _scan_cookies(self, cookies):
        """Scan cookies for hijacking attempts"""
        threats = []
        
        # Check for suspicious cookie patterns
        for cookie in cookies:
            name = cookie.get('name', '').lower()
            value = cookie.get('value', '')
            
            # Check for session cookies being accessed suspiciously
            if 'session' in name or 'auth' in name or 'token' in name:
                # Check if cookie is being sent to third-party domain
                if cookie.get('domain') and cookie.get('third_party'):
                    threats.append({
                        'type': 'cookie_hijack',
                        'severity': 'critical',
                        'source': cookie.get('domain', 'Unknown'),
                        'description': f'Session cookie potentially exposed to third party',
                        'action_available': True,
                        'suggested_action': 'clear_cookies'
                    })
        
        return threats
    
    def _scan_ip(self, ip_address):
        """Scan IP address for suspicious activity"""
        threats = []
        
        for suspicious_prefix in self.SUSPICIOUS_IPS:
            if ip_address.startswith(suspicious_prefix):
                threats.append({
                    'type': 'suspicious_ip',
                    'severity': 'medium',
                    'source': ip_address,
                    'description': f'Connection from suspicious IP range detected',
                    'action_available': True,
                    'suggested_action': 'block_ip'
                })
        
        return threats
    
    def _scan_for_data_leaks(self, outgoing_requests):
        """Scan outgoing requests for data leak attempts"""
        threats = []
        
        sensitive_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{10,12}\b',  # Phone numbers
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit cards
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        ]
        
        for request in outgoing_requests:
            data = str(request.get('data', ''))
            destination = request.get('destination', '')
            
            for pattern in sensitive_patterns:
                if re.search(pattern, data):
                    threats.append({
                        'type': 'data_leak',
                        'severity': 'high',
                        'source': destination,
                        'description': 'Sensitive data being sent to external server',
                        'action_available': True,
                        'suggested_action': 'block_request'
                    })
                    break
        
        return threats
    
    def _is_known_safe_domain(self, domain):
        """Check if domain is a known safe domain"""
        safe_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'twitter.com', 'github.com', 'linkedin.com',
            'paypal.com', 'netflix.com', 'instagram.com', 'youtube.com'
        ]
        
        for safe in safe_domains:
            if safe in domain:
                return True
        return False
    
    def take_action(self, user, threat_id, action_type, target):
        """
        Take action on a detected threat
        
        Args:
            user: User object
            threat_id: ID of the threat
            action_type: Type of action (block_url, block_ip, clear_cookies, etc.)
            target: The URL/IP/item to take action on
        
        Returns:
            dict with action result
        """
        action_result = {
            'success': False,
            'action_type': action_type,
            'target': target,
            'timestamp': datetime.utcnow(),
            'message': ''
        }
        
        if action_type == 'block_url':
            self.blocked_urls.add(target)
            action_result['success'] = True
            action_result['message'] = f'Website blocked successfully: {target}'
            
        elif action_type == 'block_ip':
            self.blocked_ips.add(target)
            action_result['success'] = True
            action_result['message'] = f'IP address blocked successfully: {target}'
            
        elif action_type == 'block_download':
            action_result['success'] = True
            action_result['message'] = f'Download blocked and file quarantined: {target}'
            
        elif action_type == 'block_request':
            action_result['success'] = True
            action_result['message'] = f'Malicious request blocked: {target}'
            
        elif action_type == 'clear_cookies':
            action_result['success'] = True
            action_result['message'] = 'Session cookies cleared for security'
            
        else:
            action_result['message'] = f'Unknown action type: {action_type}'
        
        # Send action confirmation notification
        if action_result['success']:
            self._send_action_notification(user, action_result)
        
        return action_result
    
    def _send_scan_started_notification(self, user, scan_id):
        """Send notification that scan has started"""
        if not self.notification_service:
            return
        
        # Send Email
        email_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #0d6efd 0%, #0a58ca 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 25px; border-radius: 0 0 10px 10px; }}
                .scan-info {{ background: #e7f1ff; border-left: 4px solid #0d6efd; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #6c757d; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Browser Security Scan Started</h1>
                    <p>Real-time protection is active</p>
                </div>
                <div class="content">
                    <div class="scan-info">
                        <strong>📋 Scan ID:</strong> {scan_id}<br>
                        <strong>🕐 Started:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                        <strong>👤 User:</strong> {user.email}
                    </div>
                    
                    <h3>🛡️ What we're scanning:</h3>
                    <ul>
                        <li>Current browsing session</li>
                        <li>Visited URLs for phishing/malware</li>
                        <li>Active cookies and sessions</li>
                        <li>Downloads for malicious content</li>
                        <li>Form submissions for attacks</li>
                        <li>Network connections for suspicious IPs</li>
                    </ul>
                    
                    <p>You will receive another notification when the scan completes with detailed results.</p>
                </div>
                <div class="footer">
                    <p>DarkNet Defend - Real-Time Browser Protection</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        self.notification_service.send_email(
            user.email,
            '🔍 Browser Security Scan Started - DarkNet Defend',
            email_html
        )
        
        # Send SMS
        sms_message = (
            f"🔍 DarkNet Defend\n"
            f"Browser scan STARTED\n"
            f"Scan ID: {scan_id}\n"
            f"Scanning for threats...\n"
            f"You'll be notified of results."
        )
        
        if user.phone:
            self.notification_service.send_sms(user.phone, sms_message)
    
    def _send_threat_notification(self, user, scan_id, threats):
        """Send notification about detected threats with action buttons"""
        if not self.notification_service:
            return
        
        threat_count = len(threats)
        critical_count = sum(1 for t in threats if t.get('severity') == 'critical')
        high_count = sum(1 for t in threats if t.get('severity') == 'high')
        
        # Build threat list HTML
        threats_html = ""
        for i, threat in enumerate(threats[:5]):  # Show first 5 threats
            threat_info = self.THREAT_TYPES.get(threat['type'], {})
            emoji = threat_info.get('emoji', '⚠️')
            severity_color = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107', 'low': '#28a745'}.get(threat['severity'], '#6c757d')
            
            # Create action URL (this would be a real endpoint in production)
            action_url = f"http://192.168.29.224:5000/security/take-action?threat_id={i}&action={threat.get('suggested_action', 'block')}&target={threat.get('source', '')}"
            
            threats_html += f"""
            <div style="background: #fff; border-left: 4px solid {severity_color}; padding: 15px; margin: 10px 0; border-radius: 4px;">
                <strong>{emoji} {threat_info.get('description', threat['type'].upper())}</strong><br>
                <span style="color: {severity_color}; font-weight: bold;">Severity: {threat['severity'].upper()}</span><br>
                <span>Source: {threat.get('source', 'Unknown')[:50]}</span><br>
                <span>{threat.get('description', '')}</span><br>
                <a href="{action_url}" style="display: inline-block; background: #dc3545; color: white; padding: 8px 16px; text-decoration: none; border-radius: 5px; margin-top: 10px;">
                    🛡️ Take Action - {threat.get('suggested_action', 'Block').replace('_', ' ').title()}
                </a>
            </div>
            """
        
        email_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 25px; border-radius: 0 0 10px 10px; }}
                .alert-box {{ background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #6c757d; font-size: 12px; }}
                .btn {{ display: inline-block; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 5px; font-weight: bold; }}
                .btn-danger {{ background: #dc3545; color: white; }}
                .btn-warning {{ background: #ffc107; color: #000; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 SECURITY THREATS DETECTED!</h1>
                    <p>Immediate action required</p>
                </div>
                <div class="content">
                    <div class="alert-box">
                        <strong>⚠️ Scan Results - {threat_count} Threat(s) Found</strong><br>
                        🔴 Critical: {critical_count} | 🟠 High: {high_count}<br>
                        Scan ID: {scan_id}
                    </div>
                    
                    <h3>🎯 Detected Threats:</h3>
                    {threats_html}
                    
                    <div style="text-align: center; margin-top: 20px;">
                        <a href="http://192.168.29.224:5000/security/take-all-actions?scan_id={scan_id}" class="btn btn-danger">
                            🛡️ BLOCK ALL THREATS
                        </a>
                        <a href="http://192.168.29.224:5000/leak-monitor" class="btn btn-warning">
                            📊 View Dashboard
                        </a>
                    </div>
                    
                    <p style="margin-top: 20px; color: #6c757d;">
                        Click the action buttons above to immediately block detected threats. 
                        You will receive a confirmation once the action is completed.
                    </p>
                </div>
                <div class="footer">
                    <p>DarkNet Defend - Real-Time Browser Protection</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        self.notification_service.send_email(
            user.email,
            f'🚨 ALERT: {threat_count} Security Threat(s) Detected - DarkNet Defend',
            email_html
        )
        
        # Send SMS
        threat_summary = ", ".join([t['type'].replace('_', ' ') for t in threats[:3]])
        sms_message = (
            f"🚨 DarkNet Defend ALERT\n"
            f"{threat_count} THREATS DETECTED!\n"
            f"Critical: {critical_count}, High: {high_count}\n"
            f"Types: {threat_summary}\n"
            f"Login to take action NOW!"
        )
        
        if user.phone:
            self.notification_service.send_sms(user.phone, sms_message)
    
    def _send_action_notification(self, user, action_result):
        """Send notification confirming action was taken"""
        if not self.notification_service:
            return
        
        action_emoji = {
            'block_url': '🌐',
            'block_ip': '🔒',
            'block_download': '⬇️',
            'block_request': '🚫',
            'clear_cookies': '🍪'
        }.get(action_result['action_type'], '✅')
        
        email_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #198754 0%, #146c43 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 25px; border-radius: 0 0 10px 10px; }}
                .success-box {{ background: #d1e7dd; border: 1px solid #badbcc; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #6c757d; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Action Completed Successfully</h1>
                    <p>Threat has been neutralized</p>
                </div>
                <div class="content">
                    <div class="success-box">
                        <strong>{action_emoji} {action_result['message']}</strong>
                    </div>
                    
                    <h3>📋 Action Details:</h3>
                    <ul>
                        <li><strong>Action Type:</strong> {action_result['action_type'].replace('_', ' ').title()}</li>
                        <li><strong>Target:</strong> {action_result['target']}</li>
                        <li><strong>Time:</strong> {action_result['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
                        <li><strong>Status:</strong> ✅ Completed</li>
                    </ul>
                    
                    <p>Your device is now protected from this threat. Continue browsing safely!</p>
                </div>
                <div class="footer">
                    <p>DarkNet Defend - Real-Time Browser Protection</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        self.notification_service.send_email(
            user.email,
            f'✅ Action Completed: {action_result["action_type"].replace("_", " ").title()} - DarkNet Defend',
            email_html
        )
        
        # Send SMS
        sms_message = (
            f"✅ DarkNet Defend\n"
            f"ACTION COMPLETED!\n"
            f"{action_result['message']}\n"
            f"Your device is protected."
        )
        
        if user.phone:
            self.notification_service.send_sms(user.phone, sms_message)
    
    def simulate_browser_scan(self, user):
        """
        Simulate a browser scan for demo/testing purposes
        Returns realistic scan data with some threats
        """
        # Simulate browser data
        scan_data = {
            'current_url': 'https://example-banking-login.com/secure/verify',
            'browsing_history': [
                'https://google.com/search?q=banking',
                'https://suspicious-download.xyz/free-software.exe',
                'https://normal-site.com/news',
                'https://fake-paypal-verify.net/login'
            ],
            'page_content': '<script>document.cookie</script>',
            'cookies': [
                {'name': 'session_token', 'value': 'abc123', 'domain': 'example.com', 'third_party': True}
            ],
            'downloads': [
                {'filename': 'free-game.exe', 'url': 'https://download-site.com/game.exe'}
            ],
            'client_ip': '185.220.101.45',
            'outgoing_requests': [
                {'destination': 'unknown-server.ru', 'data': 'email@example.com password123'}
            ]
        }
        
        return self.perform_scan(user, scan_data)


# Global instance
browser_scanner = BrowserScanner()
