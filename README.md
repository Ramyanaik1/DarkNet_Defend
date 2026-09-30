# 🛡️ DarkNet Defend - Real-Time Browser Security Monitor

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.0-green.svg)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

A comprehensive real-time browser security monitoring system that detects cyber threats, data leaks, and attacks with instant email & SMS notifications.

![DarkNet Defend Dashboard](https://img.shields.io/badge/Status-Active-success)

## 🚀 Features

### 🔍 Real-Time Browser Security Scanner
- **SQL Injection Detection** - Real-time scanning of URLs and form data for SQL injection attacks
- **XSS (Cross-Site Scripting) Detection** - Identifies malicious script injection attempts
- **Phishing Protection** - Detects fake login pages and credential harvesting sites
- **Malware Detection** - Blocks known malicious domains and downloads
- **Suspicious IP Monitoring** - Alerts on connections from malicious IP ranges (Tor exit nodes, etc.)
- **Data Leak Prevention** - Monitors for sensitive data being sent to external servers
- **Cookie Hijacking Detection** - Identifies session token exposure attempts
- **Credential Theft Protection** - Detects fake credential capture forms
- **Malicious Download Blocking** - Blocks suspicious file downloads (.exe, .bat, .scr, etc.)

### 📧 Instant Notifications
- **Email Alerts** - Detailed HTML emails with threat information and action buttons
- **SMS Notifications** - Real-time SMS alerts via Twilio for critical threats
- **Action Buttons** - One-click threat blocking directly from notifications

### 📊 Dashboard & Monitoring
- **Live Leak Monitor** - Real-time data leak detection and tracking
- **Security Scan History** - View past scans and detected threats
- **Blocked Items Management** - Manage blocked URLs and IP addresses
- **User-friendly Dark Theme UI** - Modern Bootstrap 5 interface

## 🛠️ Technologies Used

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.12+ | Core programming language |
| **Flask** | 2.3.0 | Web framework |
| **Flask-SQLAlchemy** | 3.0.3 | Database ORM |
| **Flask-Login** | 0.6.2 | User authentication |
| **Flask-Bcrypt** | 1.0.1 | Password hashing |
| **SQLite** | 3.x | Database |
| **Twilio** | 8.x | SMS notifications |

### Frontend
| Technology | Version | Purpose |
|------------|---------|---------|
| **Bootstrap** | 5.3 | UI framework |
| **Bootstrap Icons** | 1.11 | Icon library |
| **JavaScript (ES6)** | - | Client-side functionality |
| **HTML5/CSS3** | - | Markup and styling |

### Security & Scanning
| Feature | Technology |
|---------|------------|
| Regex Pattern Matching | Python `re` module |
| URL Parsing | `urllib.parse` |
| Hash Generation | `hashlib` |
| Real-time Detection | Custom threat engine |

## 📁 Project Structure

```
MajorProject/
├── app.py                    # Main Flask application
├── models.py                 # Database models
├── config.py                 # Configuration settings
├── browser_scanner.py        # Real-time security scanner
├── notification_service.py   # Email & SMS notification service
├── leak_detection.py         # Data leak detection module
├── requirements.txt          # Python dependencies
├── setup_and_run.py          # Setup script
├── inspect_database.py       # Database inspection utility
│
├── instance/
│   └── darknet.db            # SQLite database
│
├── static/
│   ├── css/
│   │   └── style.css         # Custom styles
│   └── js/
│       └── main.js           # JavaScript functionality
│
└── templates/
    ├── base.html             # Base template with navbar
    ├── index.html            # Home page
    ├── login.html            # Login page
    ├── register.html         # Registration page
    ├── dashboard.html        # User dashboard
    ├── alerts.html           # Alerts page
    ├── security_scan.html    # Security scanner page
    ├── notification_settings.html  # Notification settings
    └── sql_test.html         # SQL testing page
```

## 🔧 Installation & Setup

### Prerequisites
- Python 3.12 or higher
- pip (Python package manager)
- Git

### Step 1: Clone the Repository
```bash
git clone https://github.com/Ramyanaik1/DarkNet_Defend.git
cd DarkNet_Defend
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables (Optional)
Create a `.env` file or update `config.py` with your credentials:

```python
# Email Configuration (Gmail)
MAIL_USERNAME = 'your-email@gmail.com'
MAIL_PASSWORD = 'your-app-password'  # Use Gmail App Password

# Twilio SMS Configuration
TWILIO_ACCOUNT_SID = 'your-account-sid'
TWILIO_AUTH_TOKEN = 'your-auth-token'
TWILIO_PHONE_NUMBER = '+1234567890'
```

### Step 5: Run the Application
```bash
python app.py
```

The application will be available at:
- Local: `http://127.0.0.1:5000`
- Network: `http://your-ip:5000`

## 📱 How to Use

### 1. Register an Account
- Navigate to the Register page
- Enter your email, phone number (with country code), and password
- Verify your account

### 2. Login
- Use your registered credentials to login
- You'll be redirected to the Dashboard

### 3. Run Security Scan
- Click on **"Security Scan"** in the navigation bar
- Click **"Start Real-Time Scan"** to begin scanning
- Watch as the scanner checks for all 9 types of attacks
- View detected threats with severity levels
- Click **"Block"** to take action on individual threats
- Click **"Block All Threats"** to protect against all detected threats

### 4. Monitor for Data Leaks
- Navigate to **"Leak Monitor"** 
- View any detected data leaks or breaches
- Take action on suspicious activities

### 5. Configure Notifications
- Go to **"Settings"** from the navbar
- Enable/disable email notifications
- Enable/disable SMS notifications
- Test your notification settings

## 🔒 Security Features Explained

### SQL Injection Detection
```
Detects patterns like:
- ' OR '1'='1
- UNION SELECT
- DROP TABLE
- INSERT INTO
- DELETE FROM
```

### XSS Attack Detection
```
Scans for:
- <script> tags
- javascript: URLs
- Event handlers (onclick, onerror)
- eval() calls
- document.cookie access
```

### Phishing Detection
```
Identifies:
- Suspicious login/signin URLs
- Fake banking sites
- Credential harvesting pages
- Lookalike domains
```

## 📧 Email & SMS Notification Setup

### Gmail Setup
1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account → Security → App Passwords
   - Generate a new password for "Mail"
3. Use this password in the configuration

### Twilio SMS Setup
1. Create a Twilio account at https://www.twilio.com
2. Get your Account SID and Auth Token from the console
3. Get a Twilio phone number
4. Add verified recipient numbers (for trial accounts)

## 🖥️ Screenshots

### Dashboard
- Modern dark-themed interface
- Quick access to all security features
- Real-time threat statistics

### Security Scanner
- Visual progress indicator
- Real-time attack detection
- One-click threat blocking

### Threat Alerts
- Detailed threat information
- Severity levels (Critical, High, Medium, Low)
- Action buttons for immediate response

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🙋 My Contribution (Ramya Umesh Naik)

- Built SQL injection and abnormal-access detection by monitoring database activity and requests
- Designed real-time alerting on top of database logs to flag unauthorized access for review
- Worked on backend monitoring and analysis to improve data integrity and query performance
- Tested the scanner against SQL injection patterns (for example `' OR '1'='1` and `UNION SELECT`)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Team

This was a team project built as our final-year major project.

- **Ramya Umesh Naik** ([@Ramyanaik1](https://github.com/Ramyanaik1)) – Backend & database security monitoring: SQL injection and abnormal-access detection, database activity/log monitoring, and real-time alerting
- **Rakesh Kumar** ([@Rakeshbjp](https://github.com/Rakeshbjp)) – Co-developer

Original team repository: https://github.com/Rakeshbjp/Darknet-defend

## 🙏 Acknowledgments

- Flask documentation and community
- Bootstrap for the amazing UI framework
- Twilio for SMS services

---

<p align="center">
  Made with ❤️ for a safer internet
</p>
