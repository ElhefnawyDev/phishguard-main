#!/usr/bin/env python3
"""
Database Setup Script for PhishGuard v3.1
Creates and initializes MySQL database with all required tables
"""

import sys
import os
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import pymysql
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Database configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_root", "")
DB_NAME = os.getenv("DB_NAME", "phishguard")

def test_mysql_connection():
    """Test MySQL connection"""
    try:
        connection = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            charset='utf8mb4'
        )
        connection.close()
        logger.info("✅ MySQL connection successful")
        return True
    except Exception as e:
        logger.error(f"❌ MySQL connection failed: {e}")
        logger.error("Please ensure:")
        logger.error("  1. XAMPP is running")
        logger.error("  2. MySQL service is started")
        logger.error("  3. Port 3306 is available")
        return False

def create_database():
    """Create database if it doesn't exist"""
    try:
        # Connect without specifying database
        if DB_PASSWORD:
            temp_url = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}"
        else:
            temp_url = f"mysql+pymysql://{DB_USER}@{DB_HOST}:{DB_PORT}"
        
        temp_engine = create_engine(temp_url)
        
        with temp_engine.connect() as conn:
            # Check if database exists
            result = conn.execute(text(f"SHOW DATABASES LIKE '{DB_NAME}'"))
            if not result.fetchone():
                # Create database
                conn.execute(text(f"CREATE DATABASE {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
                logger.info(f"✅ Database '{DB_NAME}' created successfully")
            else:
                logger.info(f"✅ Database '{DB_NAME}' already exists")
        
        temp_engine.dispose()
        return True
        
    except Exception as e:
        logger.error(f"❌ Error creating database: {e}")
        return False

def create_tables():
    """Create all database tables"""
    try:
        # Import models after database creation
        from models import Base
        from database import engine
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables created successfully")
        
        # Verify tables were created
        with engine.connect() as conn:
            result = conn.execute(text("SHOW TABLES"))
            tables = [row[0] for row in result.fetchall()]
            logger.info(f"✅ Created tables: {', '.join(tables)}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error creating tables: {e}")
        return False

def create_demo_data():
    """Create demo user and sample data"""
    try:
        from sqlalchemy.orm import sessionmaker
        from database import engine
        from models import User, ScanHistory, UserPreferences
        from auth import create_user
        import json
        from datetime import datetime, timedelta
        
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        # Check if demo user already exists
        existing_user = db.query(User).filter(User.username == "demo").first()
        if existing_user:
            logger.info("✅ Demo user already exists")
            db.close()
            return True
        
        # Create demo user
        demo_data = {
            "username": "demo",
            "email": "demo@phishguard.com",
            "password": "demo123",
            "full_name": "Demo User"
        }
        
        demo_user = create_user(db, demo_data)
        demo_user.phone = "+1-555-0123"
        demo_user.company = "PhishGuard Demo"
        demo_user.scan_count = 5
        
        # Create demo preferences
        preferences = UserPreferences(
            user_id=demo_user.id,
            dark_mode=False,
            language="en",
            timezone="UTC",
            scan_sensitivity="medium",
            theme_color="#667eea"
        )
        db.add(preferences)
        
        # Create sample scan history
        sample_scans = [
            {
                "url": "https://suspicious-bank-login.com",
                "label": "Phishing",
                "confidence": 87.5,
                "risk_score": 87,
                "features": json.dumps({
                    "URL_Length": 35,
                    "Special_Chars": 3,
                    "Suspicious_Keywords": 2,
                    "Has_HTTPS": 1,
                    "Num_Subdomains": 2
                }),
                "prediction_time": 0.15,
                "scan_date": datetime.utcnow() - timedelta(days=1)
            },
            {
                "url": "https://google.com",
                "label": "Safe",
                "confidence": 95.2,
                "risk_score": 5,
                "features": json.dumps({
                    "URL_Length": 18,
                    "Special_Chars": 1,
                    "Suspicious_Keywords": 0,
                    "Has_HTTPS": 1,
                    "Num_Subdomains": 0
                }),
                "prediction_time": 0.12,
                "scan_date": datetime.utcnow() - timedelta(hours=6)
            },
            {
                "url": "https://paypal-secure-login.suspicious.com",
                "label": "Phishing",
                "confidence": 92.3,
                "risk_score": 92,
                "features": json.dumps({
                    "URL_Length": 45,
                    "Special_Chars": 4,
                    "Suspicious_Keywords": 3,
                    "Has_HTTPS": 1,
                    "Num_Subdomains": 3
                }),
                "prediction_time": 0.18,
                "scan_date": datetime.utcnow() - timedelta(hours=12)
            },
            {
                "url": "https://github.com",
                "label": "Safe",
                "confidence": 98.1,
                "risk_score": 2,
                "features": json.dumps({
                    "URL_Length": 18,
                    "Special_Chars": 1,
                    "Suspicious_Keywords": 0,
                    "Has_HTTPS": 1,
                    "Num_Subdomains": 0
                }),
                "prediction_time": 0.09,
                "scan_date": datetime.utcnow() - timedelta(days=2)
            },
            {
                "url": "https://amazon-security-alert.fake.com",
                "label": "Phishing",
                "confidence": 89.7,
                "risk_score": 90,
                "features": json.dumps({
                    "URL_Length": 40,
                    "Special_Chars": 4,
                    "Suspicious_Keywords": 2,
                    "Has_HTTPS": 1,
                    "Num_Subdomains": 2
                }),
                "prediction_time": 0.14,
                "scan_date": datetime.utcnow() - timedelta(days=3)
            }
        ]
        
        for scan_data in sample_scans:
            scan = ScanHistory(
                user_id=demo_user.id,
                **scan_data
            )
            db.add(scan)
        
        db.commit()
        db.close()
        
        logger.info("✅ Demo user and sample data created successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error creating demo data: {e}")
        return False

def verify_database():
    """Verify database setup"""
    try:
        from sqlalchemy.orm import sessionmaker
        from database import engine
        from models import User, ScanHistory, UserPreferences
        
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        # Count records
        user_count = db.query(User).count()
        scan_count = db.query(ScanHistory).count()
        pref_count = db.query(UserPreferences).count()
        
        logger.info(f"✅ Database verification:")
        logger.info(f"   Users: {user_count}")
        logger.info(f"   Scans: {scan_count}")
        logger.info(f"   Preferences: {pref_count}")
        
        # Test demo user login
        demo_user = db.query(User).filter(User.username == "demo").first()
        if demo_user and demo_user.verify_password("demo123"):
            logger.info("✅ Demo user authentication works")
        else:
            logger.warning("⚠️ Demo user authentication failed")
        
        db.close()
        return True
        
    except Exception as e:
        logger.error(f"❌ Database verification failed: {e}")
        return False

def main():
    """Main database setup function"""
    print("🗄️ PhishGuard Database Setup v3.1")
    print("=" * 50)
    
    # Test MySQL connection
    if not test_mysql_connection():
        print("\n❌ Setup failed: Cannot connect to MySQL")
        print("Please start XAMPP and ensure MySQL is running")
        return False
    
    # Create database
    if not create_database():
        print("\n❌ Setup failed: Cannot create database")
        return False
    
    # Create tables
    if not create_tables():
        print("\n❌ Setup failed: Cannot create tables")
        return False
    
    # Create demo data
    if not create_demo_data():
        print("\n❌ Setup failed: Cannot create demo data")
        return False
    
    # Verify setup
    if not verify_database():
        print("\n❌ Setup failed: Database verification failed")
        return False
    
    print("\n🎉 Database setup completed successfully!")
    print("=" * 50)
    print("✅ MySQL database created")
    print("✅ All tables created")
    print("✅ Demo user created (demo/demo123)")
    print("✅ Sample data added")
    print("✅ Database ready for use")
    print("\n🔗 Access phpMyAdmin:")
    print("   http://localhost/phpmyadmin")
    print("   Database: phishguard")
    print("\n🚀 Now you can run: python main.py")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        sys.exit(1)