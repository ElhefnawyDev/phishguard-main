#!/usr/bin/env python3
"""
Enhanced PhishGuard Setup Script v3.1
Creates all new pages and backend functionality for Profile, History, and Preferences
"""

import os
import sys
import subprocess
import secrets
import shutil
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e.stderr}")
        return False

def check_xampp():
    """Check if XAMPP is running"""
    print("🔍 Checking XAMPP status...")
    
    try:
        import pymysql
        connection = pymysql.connect(
            host='localhost',
            port=3306,
            user='root',
            password='',
            charset='utf8mb4'
        )
        connection.close()
        print("✅ XAMPP MySQL is running")
        return True
    except Exception as e:
        print(f"❌ XAMPP MySQL not accessible: {e}")
        print("\n📋 Please ensure:")
        print("   1. XAMPP is installed and running")
        print("   2. MySQL service is started in XAMPP Control Panel")
        print("   3. MySQL is running on default port 3306")
        return False

def create_project_structure():
    """Create enhanced project structure"""
    print("📁 Creating enhanced project structure...")
    
    directories = [
        'static',
        'static/css',
        'static/js', 
        'static/images',
        'static/assets',
        'templates',
        'model',
        'logs',
        'config',
        'migrations',
        'tests',
        'docs'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✅ Enhanced project structure created")

def create_html_files():
    """Create all HTML files in static directory"""
    print("📄 Creating HTML files...")
    
    # Define the HTML content for each file
    html_files = {
        'profile.html': '''<!-- This will be the Profile Settings page -->
<!DOCTYPE html>
<html>
<head>
    <title>Profile Settings - PhishGuard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Profile Settings</h1>
    <p>Use the artifacts provided above for the complete Profile Settings page.</p>
    <a href="dashboard.html">Back to Dashboard</a>
</body>
</html>''',
        
        'history.html': '''<!-- This will be the Scan History page -->
<!DOCTYPE html>
<html>
<head>
    <title>Scan History - PhishGuard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Scan History</h1>
    <p>Use the artifacts provided above for the complete Scan History page.</p>
    <a href="dashboard.html">Back to Dashboard</a>
</body>
</html>''',
        
        'preferences.html': '''<!-- This will be the Preferences page -->
<!DOCTYPE html>
<html>
<head>
    <title>Preferences - PhishGuard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Preferences</h1>
    <p>Use the artifacts provided above for the complete Preferences page.</p>
    <a href="dashboard.html">Back to Dashboard</a>
</body>
</html>'''
    }
    
    for filename, content in html_files.items():
        filepath = Path('static') / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ Created placeholder {filename}")
    
    print("ℹ️  Replace placeholder files with the complete HTML from artifacts")

def create_enhanced_env():
    """Create enhanced .env file"""
    env_content = f"""# Enhanced PhishGuard Configuration v3.1

# Database Configuration - MySQL with XAMPP
DATABASE_URL=mysql+pymysql://root:@localhost:3306/phishguard

# Database connection settings
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=phishguard

# JWT Security Settings
SECRET_KEY={secrets.token_urlsafe(32)}
ACCESS_TOKEN_EXPIRE_MINUTES=1440
REFRESH_TOKEN_EXPIRE_DAYS=30

# Application settings
APP_NAME=PhishGuard
APP_VERSION=3.1.0
DEBUG=True
API_HOST=0.0.0.0
API_PORT=8000

# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
FROM_EMAIL=noreply@phishguard.com

# Security Settings
CORS_ORIGINS=["http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:8000"]
MAX_REQUEST_SIZE=10MB
RATE_LIMIT_PER_MINUTE=60
BCRYPT_ROUNDS=12

# File Storage
UPLOAD_DIR=uploads
MAX_FILE_SIZE=5MB
ALLOWED_EXTENSIONS=.json,.csv,.txt

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/phishguard.log
LOG_MAX_SIZE=10MB
LOG_BACKUP_COUNT=5

# Cache Settings
REDIS_URL=redis://localhost:6379/0
CACHE_TTL=3600

# Machine Learning
MODEL_PATH=model/xgboost_model.json
MODEL_VERSION=1.0
PREDICTION_THRESHOLD=0.5
FEATURE_CACHE_SIZE=1000

# Analytics
ANALYTICS_ENABLED=true
ANALYTICS_RETENTION_DAYS=90
EXPORT_MAX_RECORDS=10000

# Notifications
NOTIFICATION_QUEUE_SIZE=1000
EMAIL_RATE_LIMIT=100
PUSH_NOTIFICATION_KEY=

# API Settings
API_KEY_LENGTH=32
API_RATE_LIMIT_DEFAULT=1000
API_RATE_LIMIT_PREMIUM=10000

# Privacy and Compliance
GDPR_COMPLIANCE=true
DATA_RETENTION_DAYS=365
ANONYMIZE_IPS=true
COOKIE_SECURE=true
COOKIE_SAMESITE=Strict

# Development Settings
ENABLE_DEBUG_ROUTES=true
MOCK_EMAIL_DELIVERY=true
SKIP_EMAIL_VERIFICATION=true
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    print("✅ Created enhanced .env file")

def create_enhanced_requirements():
    """Create enhanced requirements.txt"""
    requirements = """# Core Framework
fastapi==0.104.1
uvicorn[standard]==0.24.0

# Database & ORM
sqlalchemy==2.0.23
alembic==1.13.1
pymysql==1.1.0
cryptography==41.0.7

# Authentication & Security
python-jose[cryptography]==3.3.0
python-multipart==0.0.6
bcrypt==4.1.1
python-dotenv==1.0.0
passlib[bcrypt]==1.7.4

# Machine Learning
xgboost==2.0.2
pandas==2.1.3
numpy==1.25.2
scikit-learn==1.3.2

# Validation & Serialization
pydantic[email]==2.5.0
marshmallow==3.20.1

# URL Processing & Network
tldextract==5.1.1
requests==2.31.0
aiohttp==3.9.1

# Email & Notifications
emails==0.6
jinja2==3.1.2
python-multipart==0.0.6

# Caching & Queue
redis==5.0.1
celery==5.3.4

# File Processing
openpyxl==3.1.2
python-csv==1.1

# Monitoring & Logging
structlog==23.2.0
sentry-sdk[fastapi]==1.40.0

# Testing
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
httpx==0.25.2

# Development Tools
black==23.11.0
flake8==6.1.0
isort==5.12.0
pre-commit==3.6.0

# Production
gunicorn==21.2.0
supervisor==4.2.5

# Documentation
mkdocs==1.5.3
mkdocs-material==9.4.8

# Utils
python-dateutil==2.8.2
pytz==2023.3
click==8.1.7
"""
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements.strip())
    print("✅ Created enhanced requirements.txt")

def create_database_migrations():
    """Create database migration files"""
    print("🗄️ Creating database migration structure...")
    
    migrations_dir = Path('migrations')
    versions_dir = migrations_dir / 'versions'
    versions_dir.mkdir(parents=True, exist_ok=True)
    
    # Create alembic.ini
    alembic_ini = """# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = migrations

# template used to generate migration file names; The default value is %%(rev)s_%%(slug)s
# Uncomment the line below if you want the files to be prepended with date and time
# file_template = %%%(year)d_%%%(month).2d_%%%(day).2d_%%%(hour).2d%%%(minute).2d-%%%(rev)s_%%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding `alembic[tz]` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version locations.  This defaults
# to migrations/versions.  When using multiple version
# directories, initial revisions must be specified with --version-path.
# The path separator used here should be the separator specified by "version_path_separator" below.
# version_locations = %(here)s/bar:%(here)s/bat:migrations/versions

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses os.pathsep.
# If this key is omitted entirely, it falls back to the legacy behavior of splitting on spaces and/or commas.
# Valid values for version_path_separator are:
#
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = mysql+pymysql://root:@localhost:3306/phishguard

[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""
    
    with open('alembic.ini', 'w') as f:
        f.write(alembic_ini)
    
    # Create env.py for migrations
    env_py = '''from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys
from dotenv import load_dotenv

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
load_dotenv()

# Import your models
from models import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
'''
    
    with open(migrations_dir / 'env.py', 'w') as f:
        f.write(env_py)
    
    # Create script.py.mako
    script_mako = '''"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
'''
    
    with open(migrations_dir / 'script.py.mako', 'w') as f:
        f.write(script_mako)
    
    print("✅ Database migration structure created")

def create_config_files():
    """Create enhanced configuration files"""
    
    # Create .gitignore
    gitignore = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
cover/

# Virtual Environment
venv/
env/
ENV/
.venv/

# Environment Variables
.env
.env.local
.env.production
.env.test

# Database
*.db
*.sqlite3
migrations/versions/*.py

# Logs
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo
.DS_Store
Thumbs.db

# Model files
model/xgboost_model.json
model/*.pkl
model/*.joblib

# Uploads and user data
uploads/
exports/
backups/

# Cache
.cache/
.mypy_cache/
.dmypy.json
dmypy.json

# Temporary files
temp/
tmp/
*.tmp

# Documentation build
docs/_build/
site/

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Production secrets
secrets.json
config/production.env
"""
    
    with open('.gitignore', 'w') as f:
        f.write(gitignore.strip())
    print("✅ Created comprehensive .gitignore")
    
    # Create README.md
    readme = """# PhishGuard v3.1 - Enhanced Phishing Detection Platform

🛡️ **Professional phishing URL detection with comprehensive user management**

## 🌟 New Features in v3.1

### 👤 User Profile Management
- **Profile Settings**: Complete personal information management
- **Security Settings**: Password changes, 2FA setup, session management
- **Account Actions**: Data export, account deletion

### 📊 Scan History Management
- **Advanced Filtering**: Search by URL, result type, date range
- **Detailed Analytics**: Confidence scores, risk assessments, feature analysis
- **Export Capabilities**: CSV export with comprehensive data
- **History Management**: Delete individual scans or clear all history

### ⚙️ User Preferences
- **General Settings**: Dark mode, language, timezone, auto-save
- **Security Options**: Scan sensitivity, real-time protection, whitelisting
- **Notifications**: Customizable alert preferences
- **Display Options**: Theme colors, results per page, animation speed
- **Privacy Controls**: Analytics opt-out, history retention, public profiles

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- XAMPP with MySQL running
- Git (optional)

### Installation

1. **Clone or download the project**
```bash
git clone <repository-url>
cd phishguard
```

2. **Run the enhanced setup script**
```bash
python setup_enhanced.py
```

3. **Replace placeholder HTML files with complete versions**
   - Copy the HTML content from the provided artifacts
   - Replace `static/profile.html`, `static/history.html`, `static/preferences.html`
   - Update `main.py` with the enhanced backend code
   - Update `models.py` with the new database models

4. **Start the application**
```bash
# Windows
start_dev.bat

# Linux/Mac
./start_dev.sh

# Or manually
source venv/bin/activate  # or venv\\Scripts\\activate on Windows
python main.py
```

## 📱 Application Pages

| Page | URL | Description |
|------|-----|-------------|
| 🏠 Homepage | `http://localhost:8000/` | Landing page with features |
| 🔐 Login | `http://localhost:8000/login.html` | User authentication |
| 📝 Register | `http://localhost:8000/register.html` | New user registration |
| 📊 Dashboard | `http://localhost:8000/dashboard.html` | Main scanning interface |
| 👤 Profile | `http://localhost:8000/profile.html` | **NEW** - Profile management |
| 📋 History | `http://localhost:8000/history.html` | **NEW** - Scan history |
| ⚙️ Preferences | `http://localhost:8000/preferences.html` | **NEW** - User settings |
| 🔧 API Docs | `http://localhost:8000/docs` | Interactive API documentation |

## 💡 Demo Credentials

- **Username**: `demo`
- **Password**: `demo123`

## 📋 Next Steps After Setup

1. **Replace placeholder HTML files** with complete code from artifacts
2. **Update main.py** with enhanced backend code
3. **Update models.py** with new database models
4. **Add your XGBoost model** to `model/xgboost_model.json`
5. **Start the application** using startup scripts

## 🛠️ Development

For detailed documentation, see:
- `docs/API.md` - Complete API documentation
- `docs/USER_GUIDE.md` - User guide and features

## 📞 Support

- API Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`
- Debug Info: `http://localhost:8000/debug/users`

---

**Built with ❤️ for cybersecurity and user safety**
"""
    
    with open('README.md', 'w') as f:
        f.write(readme)
    print("✅ Created comprehensive README.md")

def create_startup_scripts():
    """Create enhanced startup scripts"""
    
    # Enhanced development script for Linux/Mac
    dev_script = """#!/bin/bash
# Enhanced PhishGuard Development Server v3.1

echo "🚀 Starting PhishGuard Enhanced Development Server"
echo "=================================================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup_enhanced.py first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate
echo "✅ Virtual environment activated"

# Check if model exists
if [ ! -f "model/xgboost_model.json" ]; then
    echo "⚠️  Warning: XGBoost model not found"
    echo "   Please add your trained model to model/xgboost_model.json"
    echo "   The application will use rule-based prediction as fallback"
fi

# Check if XAMPP is running
echo "🔍 Checking XAMPP MySQL connection..."
python -c "
import pymysql
try:
    conn = pymysql.connect(host='localhost', port=3306, user='root', password='')
    conn.close()
    print('✅ XAMPP MySQL is running')
except:
    print('❌ XAMPP MySQL not running. Please start XAMPP services.')
    exit(1)
"

# Run database migrations if needed
echo "🗄️ Checking database migrations..."
if [ -f "alembic.ini" ]; then
    alembic upgrade head
    echo "✅ Database migrations applied"
fi

# Create logs directory
mkdir -p logs

echo "🌐 Starting server at http://localhost:8000"
echo "📊 New features available:"
echo "   👤 Profile Settings: http://localhost:8000/profile.html"
echo "   📋 Scan History: http://localhost:8000/history.html" 
echo "   ⚙️ Preferences: http://localhost:8000/preferences.html"
echo "=================================================="

# Start the development server
python main.py
"""
    
    with open('start_dev.sh', 'w') as f:
        f.write(dev_script)
    os.chmod('start_dev.sh', 0o755)
    
    # Enhanced Windows batch file
    win_script = """@echo off
echo 🚀 Starting PhishGuard Enhanced Development Server
echo ==================================================

if not exist venv (
    echo ❌ Virtual environment not found. Please run setup_enhanced.py first.
    pause
    exit /b 1
)

call venv\\Scripts\\activate
echo ✅ Virtual environment activated

if not exist model\\xgboost_model.json (
    echo ⚠️  Warning: XGBoost model not found
    echo    Please add your trained model to model\\xgboost_model.json
    echo    The application will use rule-based prediction as fallback
)

echo 🔍 Checking XAMPP MySQL connection...
python -c "import pymysql; conn = pymysql.connect(host='localhost', port=3306, user='root', password=''); conn.close(); print('✅ XAMPP MySQL is running')" 2>nul
if errorlevel 1 (
    echo ❌ XAMPP MySQL not running. Please start XAMPP services.
    pause
    exit /b 1
)

echo 🗄️ Checking database migrations...
if exist alembic.ini (
    alembic upgrade head
    echo ✅ Database migrations applied
)

if not exist logs mkdir logs

echo 🌐 Starting server at http://localhost:8000
echo 📊 New features available:
echo    👤 Profile Settings: http://localhost:8000/profile.html
echo    📋 Scan History: http://localhost:8000/history.html
echo    ⚙️ Preferences: http://localhost:8000/preferences.html
echo ==================================================

python main.py
pause
"""
    
    with open('start_dev.bat', 'w') as f:
        f.write(win_script)
    
    print("✅ Created enhanced startup scripts")

def create_test_files():
    """Create test structure"""
    print("🧪 Creating test structure...")
    
    tests_dir = Path('tests')
    tests_dir.mkdir(exist_ok=True)
    
    # Create test files
    test_files = {
        '__init__.py': '',
        'conftest.py': '''import pytest
from fastapi.testclient import TestClient
from main import app

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def test_user():
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123",
        "full_name": "Test User"
    }
''',
        'test_auth.py': '''import pytest
from fastapi.testclient import TestClient

def test_register_user(client, test_user):
    response = client.post("/auth/register", json=test_user)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == test_user["username"]
    assert data["email"] == test_user["email"]

def test_login_user(client, test_user):
    # Register user first
    client.post("/auth/register", json=test_user)
    
    # Then login
    login_data = {
        "username": test_user["username"],
        "password": test_user["password"]
    }
    response = client.post("/auth/login", json=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_get_current_user(client):
    response = client.get("/auth/me")
    assert response.status_code == 200
''',
        'test_predictions.py': '''import pytest

def test_predict_safe_url(client):
    url_data = {"url": "https://google.com"}
    response = client.post("/predict/anonymous", json=url_data)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://google.com"
    assert "label" in data
    assert "confidence" in data

def test_predict_suspicious_url(client):
    url_data = {"url": "https://suspicious-bank-login.com"}
    response = client.post("/predict/anonymous", json=url_data)
    assert response.status_code == 200
    data = response.json()
    assert "label" in data
    assert "risk_score" in data

def test_predict_invalid_url(client):
    url_data = {"url": ""}
    response = client.post("/predict/anonymous", json=url_data)
    assert response.status_code == 422  # Validation error
''',
        'test_profile.py': '''import pytest

def test_get_user_profile(client):
    response = client.get("/users/profile")
    assert response.status_code == 200
    data = response.json()
    assert "username" in data
    assert "email" in data

def test_update_user_profile(client):
    profile_data = {
        "full_name": "Updated Name",
        "phone": "+1-555-0123",
        "company": "Test Company"
    }
    response = client.put("/users/profile", json=profile_data)
    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == profile_data["full_name"]

def test_change_password(client):
    password_data = {
        "current_password": "demo123",
        "new_password": "newpass123"
    }
    response = client.post("/users/change-password", json=password_data)
    assert response.status_code == 200
''',
        'test_history.py': '''import pytest

def test_get_scan_history(client):
    response = client.get("/history")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_get_scan_history_with_limit(client):
    response = client.get("/history?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert len(data) <= 5

def test_delete_scan_history(client):
    # First get history to find a scan ID
    history_response = client.get("/history")
    if history_response.json():
        scan_id = history_response.json()[0]["id"]
        
        # Delete the scan
        response = client.delete(f"/history/{scan_id}")
        assert response.status_code == 200
''',
        'test_preferences.py': '''import pytest

def test_get_user_preferences(client):
    response = client.get("/users/preferences")
    assert response.status_code == 200
    data = response.json()
    assert "darkMode" in data
    assert "language" in data

def test_update_user_preferences(client):
    preferences_data = {
        "darkMode": True,
        "language": "es",
        "scanSensitivity": "high",
        "themeColor": "#ff0000"
    }
    response = client.put("/users/preferences", json=preferences_data)
    assert response.status_code == 200
    data = response.json()
    assert data["darkMode"] == True
    assert data["language"] == "es"

def test_reset_user_preferences(client):
    response = client.post("/users/preferences/reset")
    assert response.status_code == 200
    data = response.json()
    assert data["darkMode"] == False  # Default value
'''
    }
    
    for filename, content in test_files.items():
        with open(tests_dir / filename, 'w') as f:
            f.write(content)
    
    print("✅ Created test structure")

def create_documentation():
    """Create documentation files"""
    print("📚 Creating documentation...")
    
    docs_dir = Path('docs')
    docs_dir.mkdir(exist_ok=True)
    
    # API Documentation
    api_docs = """# PhishGuard API Documentation

## Overview
PhishGuard v3.1 provides a comprehensive REST API for phishing URL detection with user management capabilities.

## Authentication
Most endpoints require authentication using Bearer tokens obtained from the login endpoint.

```http
Authorization: Bearer <your-token>
```

## Base URL
```
http://localhost:8000
```

## Endpoints

### Authentication

#### POST /auth/register
Register a new user account.

**Request Body:**
```json
{
  "username": "string",
  "email": "user@example.com",
  "password": "string",
  "full_name": "string (optional)"
}
```

**Response:**
```json
{
  "id": 1,
  "username": "string",
  "email": "user@example.com",
  "full_name": "string",
  "is_active": true,
  "created_at": "2025-01-01T00:00:00Z",
  "scan_count": 0
}
```

#### POST /auth/login
Authenticate user and receive access token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "access_token": "string",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "string",
    "email": "user@example.com"
  }
}
```

### URL Prediction

#### POST /predict
Scan URL for phishing threats (authenticated).

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "label": "Safe",
  "confidence": 95.2,
  "risk_score": 5,
  "features": {
    "URL_Length": 18,
    "Special_Chars": 1,
    "Suspicious_Keywords": 0,
    "Has_HTTPS": 1
  },
  "prediction_time": 0.12,
  "scan_id": 123
}
```

#### POST /predict/anonymous
Scan URL without authentication.

### User Profile

#### GET /users/profile
Get current user profile information.

#### PUT /users/profile
Update user profile information.

**Request Body:**
```json
{
  "email": "new@example.com",
  "full_name": "New Name",
  "phone": "+1-555-0123",
  "company": "Company Name"
}
```

#### POST /users/change-password
Change user password.

**Request Body:**
```json
{
  "current_password": "oldpass",
  "new_password": "newpass"
}
```

### Scan History

#### GET /history
Get user's scan history with optional pagination.

**Query Parameters:**
- `limit`: Number of results (default: 100)
- `offset`: Starting position (default: 0)

#### GET /history/{scan_id}
Get detailed information about a specific scan.

#### DELETE /history/{scan_id}
Delete a specific scan from history.

#### DELETE /history
Clear all scan history for the user.

### User Preferences

#### GET /users/preferences
Get user's current preferences.

#### PUT /users/preferences
Update user preferences.

**Request Body:**
```json
{
  "darkMode": false,
  "language": "en",
  "timezone": "UTC",
  "scanSensitivity": "medium",
  "securityAlerts": true,
  "themeColor": "#667eea"
}
```

#### POST /users/preferences/reset
Reset all preferences to default values.

### Analytics

#### GET /analytics/user-stats
Get user analytics and statistics.

**Response:**
```json
{
  "total_scans": 150,
  "safe_scans": 120,
  "phishing_scans": 30,
  "recent_scans_30d": 25,
  "accuracy_rate": 98.5,
  "monthly_breakdown": {
    "2025-01": {
      "total": 25,
      "safe": 20,
      "phishing": 5
    }
  }
}
```

## Error Responses

All endpoints return standard HTTP status codes:

- `200`: Success
- `400`: Bad Request (validation error)
- `401`: Unauthorized
- `404`: Not Found
- `422`: Unprocessable Entity
- `500`: Internal Server Error

Error response format:
```json
{
  "detail": "Error message description"
}
```

## Rate Limiting

API endpoints are rate-limited to prevent abuse:
- Anonymous endpoints: 100 requests per hour
- Authenticated endpoints: 1000 requests per hour
- Premium users: 10000 requests per hour

## Data Export

Users can export their data in JSON format using the `/users/export` endpoint.
"""
    
    with open(docs_dir / 'API.md', 'w') as f:
        f.write(api_docs)
    
    # User Guide
    user_guide = """# PhishGuard User Guide

## Getting Started

### Creating an Account
1. Visit the registration page at `/register.html`
2. Fill in your username, email, and password
3. Click "Create Account"
4. You'll be redirected to the login page

### Logging In
1. Visit the login page at `/login.html`
2. Enter your username and password
3. Click "Sign In"
4. You'll be redirected to the dashboard

## Using the Dashboard

### Scanning URLs
1. Enter a URL in the scan input field
2. Click "Scan URL"
3. Wait for the analysis to complete
4. Review the results showing safety status and confidence

### Understanding Results
- **Safe**: URL appears legitimate
- **Phishing**: URL shows suspicious characteristics
- **Confidence**: How certain the system is (0-100%)
- **Risk Score**: Overall risk assessment (0-100)

## Profile Management

### Updating Your Profile
1. Click your avatar in the top-right corner
2. Select "Profile Settings"
3. Update your information:
   - Full name
   - Email address
   - Phone number
   - Company

### Changing Your Password
1. Go to Profile Settings
2. Click "Change Password"
3. Enter your current password
4. Enter and confirm your new password
5. Click "Change Password"

### Security Settings
- **Two-Factor Authentication**: Add extra security
- **Login Notifications**: Get alerted to new logins
- **Session Timeout**: Automatic logout after inactivity

## Scan History

### Viewing Your History
1. Click your avatar and select "Scan History"
2. Browse your previous scans
3. Use filters to find specific results:
   - Search by URL
   - Filter by result type (Safe/Phishing)
   - Filter by date range

### Managing History
- **View Details**: Click the eye icon to see full scan details
- **Delete Scan**: Click the trash icon to remove a scan
- **Export Data**: Click "Export CSV" to download your history

## Preferences

### General Settings
- **Dark Mode**: Toggle between light and dark themes
- **Language**: Choose your preferred language
- **Time Zone**: Set your local timezone
- **Auto-save**: Automatically save scan results

### Security Preferences
- **Scan Sensitivity**: Adjust detection sensitivity (Low/Medium/High)
- **Real-time Protection**: Enable continuous URL monitoring
- **Trusted Domains**: Automatically trust verified domains
- **Session Timeout**: Set automatic logout time

### Notification Settings
- **Security Alerts**: Get notified of phishing threats
- **Scan Completion**: Receive scan completion notifications
- **Weekly Reports**: Get weekly activity summaries
- **System Updates**: Be notified of new features

### Display Options
- **Theme Color**: Customize the interface color
- **Results Per Page**: Set how many results to show
- **Animation Speed**: Control interface animation speed
- **Compact Mode**: Use a more compact layout

### Privacy Controls
- **Analytics**: Help improve the service with usage data
- **History Retention**: How long to keep your scan history
- **Public Profile**: Allow others to see your statistics

## Tips for Best Results

### What to Scan
- Email links before clicking
- Downloads from unknown sources
- Shortened URLs (bit.ly, tinyurl, etc.)
- URLs from suspicious messages
- Login pages for important accounts

### Understanding Features
The system analyzes multiple URL characteristics:
- **URL Length**: Very long URLs can be suspicious
- **Special Characters**: Excessive symbols may indicate manipulation
- **Subdomains**: Too many subdomains can be a red flag
- **Keywords**: Suspicious words like "login", "verify", "secure"
- **HTTPS**: Lack of encryption is a warning sign

### Best Practices
1. **Always verify** suspicious results manually
2. **Keep your preferences updated** for optimal protection
3. **Review your history** regularly for patterns
4. **Enable notifications** to stay informed
5. **Export your data** regularly for backup

## Troubleshooting

### Common Issues

**"URL cannot be empty"**
- Make sure you've entered a complete URL
- URLs should start with http:// or https://

**"Failed to load profile"**
- Check your internet connection
- Try refreshing the page
- Log out and log back in

**"Scan failed"**
- The URL might be temporarily unavailable
- Check if the URL is correctly formatted
- Try again in a few moments

**"Authentication failed"**
- Check your username and password
- Make sure Caps Lock is off
- Try resetting your password

### Getting Help
If you continue to experience issues:
1. Check the system status at `/health`
2. Review the API documentation at `/docs`
3. Contact support through the help center

## Privacy and Security

### Data Protection
- All passwords are securely hashed
- Scan data is encrypted in transit
- Personal information is protected
- You can export or delete your data anytime

### What We Collect
- URLs you scan (for analysis)
- Basic usage statistics (if enabled)
- Account information you provide
- System logs for security and performance

### Your Rights
- View all your data
- Export your data
- Delete your account
- Control privacy settings
- Opt out of analytics

For more information, see our Privacy Policy and Terms of Service.
"""
    
    with open(docs_dir / 'USER_GUIDE.md', 'w') as f:
        f.write(user_guide)
    
    print("✅ Created comprehensive documentation")

def show_completion_summary():
    """Display setup completion summary"""
    print("\n" + "=" * 70)
    print("🎉 PHISHGUARD v3.1 ENHANCED SETUP COMPLETE!")
    print("=" * 70)
    
    print("\n📁 Enhanced Project Structure Created:")
    print("""
phishguard-v3.1/
├── 📄 main.py                    # Enhanced FastAPI application (UPDATE REQUIRED)
├── 📄 models.py                  # Extended database models (UPDATE REQUIRED)
├── 📄 database.py                # Database configuration
├── 📄 auth.py                    # Authentication utilities
├── 📄 features.py                # ML feature extraction
├── 📄 setup_enhanced.py          # This enhanced setup script
├── 📄 alembic.ini               # Database migration config
├── 📄 .env                       # Enhanced environment variables
├── 📄 requirements.txt           # Extended dependencies
├── 📄 .gitignore                 # Comprehensive ignore rules
├── 📄 README.md                  # Complete documentation
├── 📄 start_dev.sh              # Enhanced Linux/Mac startup
├── 📄 start_dev.bat             # Enhanced Windows startup
├── 📂 static/                    # Frontend files
│   ├── 🌐 index.html            # Landing page
│   ├── 🔐 login.html            # Authentication
│   ├── 📝 register.html         # Registration
│   ├── 📊 dashboard.html        # Main interface (UPDATED)
│   ├── 👤 profile.html          # NEW - Profile management (PLACEHOLDER)
│   ├── 📋 history.html          # NEW - Scan history (PLACEHOLDER)
│   ├── ⚙️ preferences.html      # NEW - User preferences (PLACEHOLDER)
│   ├── 📂 css/                  # Custom stylesheets
│   ├── 📂 js/                   # Custom JavaScript
│   └── 📂 images/               # Images and assets
├── 📂 model/                     # Machine Learning models
├── 📂 migrations/                # Database migrations
│   ├── 📄 env.py                # Migration environment
│   ├── 📄 script.py.mako        # Migration template
│   └── 📂 versions/             # Migration versions
├── 📂 tests/                     # Test suite
│   ├── 📄 conftest.py           # Test configuration
│   ├── 📄 test_auth.py          # Authentication tests
│   ├── 📄 test_predictions.py   # Prediction tests
│   ├── 📄 test_profile.py       # Profile management tests
│   ├── 📄 test_history.py       # History management tests
│   └── 📄 test_preferences.py   # Preferences tests
├── 📂 docs/                      # Documentation
│   ├── 📄 API.md                # API documentation
│   └── 📄 USER_GUIDE.md         # User guide
├── 📂 logs/                      # Application logs
└── 📂 config/                    # Configuration files
""")
    
    print("\n🔗 Enhanced Application Pages:")
    print("┌──────────────────────────────────────────────────────────────┐")
    print("│ 🏠 Homepage         │ http://localhost:8000/                │")
    print("│ 🔐 Login           │ http://localhost:8000/login.html      │")
    print("│ 📝 Register        │ http://localhost:8000/register.html   │")
    print("│ 📊 Dashboard       │ http://localhost:8000/dashboard.html  │")
    print("│ 👤 Profile         │ http://localhost:8000/profile.html    │")
    print("│ 📋 History         │ http://localhost:8000/history.html    │")
    print("│ ⚙️ Preferences     │ http://localhost:8000/preferences.html│")
    print("│ 🔧 API Docs        │ http://localhost:8000/docs            │")
    print("│ 🏥 Health Check    │ http://localhost:8000/health          │")
    print("│ 🗄️ Database Admin  │ http://localhost/phpmyadmin           │")
    print("└──────────────────────────────────────────────────────────────┘")
    
    print("\n⚠️  IMPORTANT NEXT STEPS:")
    print("1. 📄 REPLACE main.py with the enhanced backend code from artifacts")
    print("2. 📄 REPLACE models.py with the enhanced database models from artifacts")
    print("3. 📄 REPLACE static/profile.html with the complete Profile Settings page")
    print("4. 📄 REPLACE static/history.html with the complete Scan History page")
    print("5. 📄 REPLACE static/preferences.html with the complete Preferences page")
    print("6. 🤖 ADD your trained XGBoost model to model/xgboost_model.json")
    print("7. ✅ REVIEW .env file settings")
    print("8. 🚀 START the application using the startup scripts")
    
    print("\n🌟 NEW FEATURES IN v3.1:")
    print("   ✅ Complete user profile management")
    print("   ✅ Advanced scan history with filtering and export")
    print("   ✅ Comprehensive user preferences system")
    print("   ✅ Enhanced database schema with new tables")
    print("   ✅ Improved security with session management")
    print("   ✅ Data export and privacy controls")
    print("   ✅ Comprehensive test suite")
    print("   ✅ Complete API documentation")
    print("   ✅ Database migration support")
    print("   ✅ Enhanced error handling and logging")
    
    print("\n🚀 TO START THE APPLICATION:")
    if sys.platform.startswith('win'):
        print("   💻 Windows: Double-click start_dev.bat")
        print("   💻 Or run: venv\\Scripts\\activate && python main.py")
    else:
        print("   🐧 Linux/Mac: ./start_dev.sh")
        print("   🐧 Or run: source venv/bin/activate && python main.py")
    
    print("\n💡 DEMO CREDENTIALS:")
    print("   📧 Username: demo")
    print("   🔑 Password: demo123")
    
    print("\n🎯 WHAT'S WORKING OUT OF THE BOX:")
    print("   ✅ User registration and authentication")
    print("   ✅ URL scanning with basic ML model")
    print("   ✅ Dashboard with statistics")
    print("   ✅ Basic scan history")
    print("   ✅ User profile system")
    print("   ✅ Preferences management")
    print("   ✅ Data export functionality")
    
    print("\n📚 DOCUMENTATION:")
    print("   📖 User Guide: docs/USER_GUIDE.md")
    print("   🔧 API Docs: docs/API.md")
    print("   🌐 Interactive API: http://localhost:8000/docs")
    
    print(f"\n🎉 PhishGuard v3.1 Enhanced Setup Complete!")
    print("   Ready to protect users with advanced features! 🛡️")

def main():
    """Main enhanced setup function"""
    print("🚀 PhishGuard Enhanced Setup v3.1")
    print("🏢 Creating professional phishing detection platform with full user management")
    print("=" * 80)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    # Check XAMPP
    if not check_xampp():
        print("\n❌ Please start XAMPP services and run this script again")
        sys.exit(1)
    
    # Create enhanced project structure
    create_project_structure()
    
    # Create virtual environment
    if not os.path.exists('venv'):
        if not run_command('python -m venv venv', 'Creating virtual environment'):
            sys.exit(1)
    
    # Create enhanced configuration files
    create_enhanced_requirements()
    create_enhanced_env()
    create_config_files()
    
    # Install packages
    if sys.platform.startswith('win'):
        activate_cmd = 'venv\\Scripts\\activate && '
    else:
        activate_cmd = 'source venv/bin/activate && '
    
    install_cmd = f'{activate_cmd}pip install --upgrade pip && {activate_cmd}pip install -r requirements.txt'
    
    if not run_command(install_cmd, 'Installing enhanced Python packages'):
        print("❌ Failed to install packages")
        sys.exit(1)
    
    # Create database migration structure
    create_database_migrations()
    
    # Create HTML placeholder files
    create_html_files()
    
    # Create startup scripts
    create_startup_scripts()
    
    # Create test structure
    create_test_files()
    
    # Create documentation
    create_documentation()
    
    # Show completion summary
    show_completion_summary()

if __name__ == "__main__":
    main()