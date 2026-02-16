"""
DarkNet Defend - Quick Setup and Run Script
Run this file to set up everything automatically!
"""

import os
import sys
import subprocess

def print_header(text):
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60 + "\n")

def install_dependencies():
    """Install required packages"""
    print_header("📦 Installing Dependencies")
    
    packages = [
        'Flask==2.3.0',
        'Flask-Login==0.6.2',
        'Flask-SQLAlchemy==3.0.5',
        'Werkzeug==2.3.0',
        'APScheduler==3.10.1',
        'email-validator==2.0.0',
        'python-dotenv==1.0.0'
    ]
    
    for package in packages:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package, '--quiet'])
    
    print("✅ All dependencies installed successfully!\n")

def create_directories():
    """Create necessary directories"""
    print_header("📁 Creating Directory Structure")
    
    directories = [
        'templates',
        'static',
        'static/css',
        'static/js'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created: {directory}")
    
    print()

def check_files():
    """Check if all required files exist"""
    print_header("🔍 Checking Project Files")
    
    required_files = {
        'app.py': 'Main application file',
        'models.py': 'Database models',
        'config.py': 'Configuration',
        'templates/base.html': 'Base template',
        'templates/index.html': 'Landing page',
        'templates/login.html': 'Login page',
        'templates/register.html': 'Register page',
        'templates/dashboard.html': 'Dashboard',
        'templates/alerts.html': 'Alerts page',
        'static/css/style.css': 'CSS styles',
        'static/js/main.js': 'JavaScript'
    }
    
    missing_files = []
    
    for file_path, description in required_files.items():
        if os.path.exists(file_path):
            print(f"✅ {description}: {file_path}")
        else:
            print(f"❌ MISSING {description}: {file_path}")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️  WARNING: {len(missing_files)} files are missing!")
        print("Please make sure you have created all the files from the artifacts.")
        return False
    else:
        print("\n✅ All required files found!")
        return True

def create_database():
    """Initialize the database"""
    print_header("🗄️  Initializing Database")
    
    try:
        from app import app, db
        
        with app.app_context():
            db.create_all()
            print("✅ Database created successfully: database.db")
            
            # Check tables
            from models import User, MonitoredCredential, Alert, SecurityLog, DataLeakReport
            tables = [User, MonitoredCredential, Alert, SecurityLog, DataLeakReport]
            
            print("\n📊 Database Tables Created:")
            for table in tables:
                print(f"   ✅ {table.__tablename__}")
        
        return True
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False

def create_demo_data():
    """Create demo user and data"""
    print_header("👤 Creating Demo Account")
    
    try:
        from app import app, db
        from models import User
        
        with app.app_context():
            # Check if demo user exists
            demo_user = User.query.filter_by(username='demo').first()
            
            if not demo_user:
                demo_user = User(
                    username='demo',
                    email='demo@darknetdefend.com',
                    phone='+1234567890'
                )
                demo_user.set_password('demo123')
                
                db.session.add(demo_user)
                db.session.commit()
                
                print("✅ Demo account created successfully!")
                print("\n📋 Demo Login Credentials:")
                print("   Username: demo")
                print("   Password: demo123")
            else:
                print("ℹ️  Demo account already exists")
                print("\n📋 Demo Login Credentials:")
                print("   Username: demo")
                print("   Password: demo123")
        
        return True
    except Exception as e:
        print(f"❌ Error creating demo data: {e}")
        return False

def run_application():
    """Start the Flask application"""
    print_header("🚀 Starting DarkNet Defend")
    
    print("Server starting at: http://localhost:5000")
    print("\nPress CTRL+C to stop the server\n")
    print("="*60)
    
    try:
        from app import app
        app.run(debug=True, port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped. Goodbye!")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")

def main():
    """Main setup and run function"""
    print("\n" + "🛡️ "*20)
    print("    DARKNET DEFEND - QUICK SETUP & RUN")
    print("🛡️ "*20)
    
    try:
        # Step 1: Create directories
        create_directories()
        
        # Step 2: Check files
        files_ok = check_files()
        if not files_ok:
            print("\n⚠️  Please create the missing files first!")
            print("Refer to the artifacts provided in the chat.")
            return
        
        # Step 3: Install dependencies
        try:
            import flask
            import flask_login
            import flask_sqlalchemy
            print_header("📦 Dependencies Already Installed")
            print("✅ All required packages are already installed!")
        except ImportError:
            install_dependencies()
        
        # Step 4: Initialize database
        db_ok = create_database()
        if not db_ok:
            print("\n❌ Database setup failed. Please check app.py and models.py")
            return
        
        # Step 5: Create demo data
        create_demo_data()
        
        # Step 6: Show quick start guide
        print_header("🎯 Quick Start Guide")
        print("1. Open browser: http://localhost:5000")
        print("2. Click 'Register' or use demo account")
        print("3. Login with credentials above")
        print("4. Add monitoring: test@example.com (will show as leaked)")
        print("5. Try SQL injection: ' OR '1'='1 (will be blocked)")
        print("\n📚 For more info, check README.md and QUICKSTART.md\n")
        
        # Step 7: Run the application
        input("Press ENTER to start the server...")
        run_application()
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()