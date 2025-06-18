#!/usr/bin/env python3
"""
PhishGuard Stats API Runner
Run this script to start the real-time statistics API for your project
"""

import sys
import os
import logging
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = [
        'fastapi',
        'uvicorn',
        'sqlalchemy',
        'pymysql',
        'dotenv'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.error("❌ Missing required packages:")
        for package in missing_packages:
            logger.error(f"   - {package}")
        logger.error("\nPlease install them using:")
        logger.error("pip install -r requirements.txt")
        return False
    
    logger.info("✅ All dependencies are installed")
    return True

def check_database_connection():
    """Check if database connection is working"""
    try:
        from database import test_connection, get_database_info
        
        if test_connection():
            logger.info("✅ Database connection successful")
            
            # Get database info
            db_info = get_database_info()
            if db_info:
                logger.info(f"✅ Database: {db_info['current_database']}")
                logger.info(f"✅ Tables: {db_info['table_count']}")
                logger.info(f"✅ MySQL Version: {db_info['mysql_version']}")
            
            return True
        else:
            logger.error("❌ Database connection failed")
            logger.error("Please ensure:")
            logger.error("  1. XAMPP is running")
            logger.error("  2. MySQL service is started")
            logger.error("  3. Database 'phishguard' exists")
            return False
            
    except Exception as e:
        logger.error(f"❌ Database check failed: {e}")
        return False

def start_api():
    """Start the FastAPI stats server"""
    try:
        import uvicorn
        from stats_api import app
        
        logger.info("🚀 Starting PhishGuard Stats API...")
        logger.info("📊 Real-time statistics will be available at:")
        logger.info("   🔗 http://localhost:8001/api/stats")
        logger.info("   🔗 http://localhost:8001/api/health")
        logger.info("   🔗 http://localhost:8001/api/recent-activity")
        logger.info("   📖 http://localhost:8001/docs (API Documentation)")
        logger.info("")
        logger.info("💡 Your HTML page should use: http://localhost:8001/api/stats")
        logger.info("🛑 Press Ctrl+C to stop the server")
        logger.info("=" * 60)
        
        # Start the server
        uvicorn.run(
            "stats_api:app",
            host="0.0.0.0",
            port=8001,
            reload=True,
            log_level="info",
            access_log=True
        )
        
    except KeyboardInterrupt:
        logger.info("\n🛑 Stats API stopped by user")
    except Exception as e:
        logger.error(f"❌ Failed to start API: {e}")

def main():
    """Main function to run the stats API with checks"""
    logger.info("🔍 PhishGuard Stats API - Starting checks...")
    logger.info("=" * 60)
    
    # Check 1: Dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check 2: Database connection
    if not check_database_connection():
        logger.warning("⚠️ Database connection failed, but API will still start")
        logger.warning("   The API will return empty data until database is available")
    
    # Start the API
    start_api()

if __name__ == "__main__":
    main()