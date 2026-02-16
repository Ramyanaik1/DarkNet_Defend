"""
Database Inspector - Check your DarkNet Defend database
Run this to see what's in your database!
"""

import os
import sqlite3
from datetime import datetime

def print_section(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def check_database_exists():
    """Check if database file exists"""
    if os.path.exists('database.db'):
        size = os.path.getsize('database.db')
        print(f"✅ Database found: database.db ({size} bytes)")
        return True
    else:
        print("❌ Database not found: database.db")
        print("Run 'python app.py' first to create the database")
        return False

def inspect_database():
    """Inspect database contents"""
    
    if not check_database_exists():
        return
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Get all tables
    print_section("📊 DATABASE TABLES")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    if not tables:
        print("❌ No tables found. Run 'python app.py' to initialize database.")
        return
    
    print(f"Found {len(tables)} tables:\n")
    for table in tables:
        print(f"  ✅ {table[0]}")
    
    # Inspect each table
    for table in tables:
        table_name = table[0]
        print_section(f"📋 TABLE: {table_name}")
        
        # Get table schema
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        
        print("Columns:")
        for col in columns:
            col_id, col_name, col_type, not_null, default, pk = col
            pk_marker = " (PRIMARY KEY)" if pk else ""
            null_marker = " NOT NULL" if not_null else ""
            print(f"  • {col_name}: {col_type}{pk_marker}{null_marker}")
        
        # Get row count
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        print(f"\nRows: {count}")
        
        # Show sample data if exists
        if count > 0:
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 3")
            rows = cursor.fetchall()
            
            print("\nSample Data:")
            col_names = [col[1] for col in columns]
            
            for i, row in enumerate(rows, 1):
                print(f"\n  Row {i}:")
                for col_name, value in zip(col_names, row):
                    # Format datetime values
                    if isinstance(value, str) and len(value) > 15 and '-' in value:
                        try:
                            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                            value = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    # Truncate long values
                    if isinstance(value, str) and len(value) > 50:
                        value = value[:50] + "..."
                    
                    print(f"    {col_name}: {value}")
    
    conn.close()

def show_statistics():
    """Show database statistics"""
    
    if not check_database_exists():
        return
    
    print_section("📈 DATABASE STATISTICS")
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    try:
        # Users
        cursor.execute("SELECT COUNT(*) FROM users")
        users_count = cursor.fetchone()[0]
        print(f"👥 Total Users: {users_count}")
        
        # Monitored Credentials
        cursor.execute("SELECT COUNT(*) FROM monitored_credentials")
        credentials_count = cursor.fetchone()[0]
        print(f"🔍 Monitored Credentials: {credentials_count}")
        
        cursor.execute("SELECT COUNT(*) FROM monitored_credentials WHERE is_compromised = 1")
        compromised_count = cursor.fetchone()[0]
        print(f"⚠️  Compromised Credentials: {compromised_count}")
        
        # Alerts
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts_count = cursor.fetchone()[0]
        print(f"🔔 Total Alerts: {alerts_count}")
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE is_read = 0")
        unread_count = cursor.fetchone()[0]
        print(f"📬 Unread Alerts: {unread_count}")
        
        # Security Logs
        cursor.execute("SELECT COUNT(*) FROM security_logs")
        logs_count = cursor.fetchone()[0]
        print(f"📝 Security Logs: {logs_count}")
        
        cursor.execute("SELECT COUNT(*) FROM security_logs WHERE blocked = 1")
        blocked_count = cursor.fetchone()[0]
        print(f"🚫 Blocked Attempts: {blocked_count}")
        
        # Data Leak Reports
        cursor.execute("SELECT COUNT(*) FROM data_leak_reports")
        leaks_count = cursor.fetchone()[0]
        print(f"💧 Data Leak Reports: {leaks_count}")
        
        print("\n" + "-"*70)
        
        # Recent activity
        print("\n🕒 Recent Activity:")
        
        cursor.execute("""
            SELECT username, datetime(last_login) as last_login 
            FROM users 
            WHERE last_login IS NOT NULL 
            ORDER BY last_login DESC 
            LIMIT 3
        """)
        recent_logins = cursor.fetchall()
        
        if recent_logins:
            print("\nRecent Logins:")
            for username, last_login in recent_logins:
                print(f"  • {username}: {last_login}")
        
        cursor.execute("""
            SELECT log_type, COUNT(*) as count 
            FROM security_logs 
            GROUP BY log_type 
            ORDER BY count DESC
        """)
        log_types = cursor.fetchall()
        
        if log_types:
            print("\nSecurity Events by Type:")
            for log_type, count in log_types:
                print(f"  • {log_type.replace('_', ' ').title()}: {count}")
        
    except Exception as e:
        print(f"❌ Error getting statistics: {e}")
    
    conn.close()

def verify_demo_account():
    """Check if demo account exists"""
    
    if not check_database_exists():
        return
    
    print_section("👤 DEMO ACCOUNT CHECK")
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT username, email, phone FROM users WHERE username = 'demo'")
        demo = cursor.fetchone()
        
        if demo:
            print("✅ Demo account exists!")
            print(f"\n   Username: {demo[0]}")
            print(f"   Email: {demo[1]}")
            print(f"   Phone: {demo[2]}")
            print(f"   Password: demo123")
        else:
            print("❌ Demo account not found")
            print("\nYou can create it by running:")
            print("   python setup_and_run.py")
    except Exception as e:
        print(f"❌ Error checking demo account: {e}")
    
    conn.close()

def main():
    """Main inspection function"""
    
    print("\n" + "🔍 "*30)
    print("    DARKNET DEFEND - DATABASE INSPECTOR")
    print("🔍 "*30)
    
    try:
        # Check and inspect database
        inspect_database()
        
        # Show statistics
        show_statistics()
        
        # Check demo account
        verify_demo_account()
        
        print_section("✅ INSPECTION COMPLETE")
        print("\nYour database is ready to use!")
        print("\nNext steps:")
        print("  1. Run: python app.py")
        print("  2. Open: http://localhost:5000")
        print("  3. Login with demo account or register new user")
        
    except Exception as e:
        print(f"\n❌ Inspection failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()