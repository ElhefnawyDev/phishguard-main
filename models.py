from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import bcrypt
import json

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    company = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    scan_count = Column(Integer, default=0)
    
    # Relationships
    scan_history = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")
    preferences = relationship("UserPreferences", back_populates="user", uselist=False, cascade="all, delete-orphan")
    session_tokens = relationship("SessionToken", back_populates="user", cascade="all, delete-orphan")
    
    def verify_password(self, password: str) -> bool:
        """Verify password against hashed password"""
        return bcrypt.checkpw(password.encode('utf-8'), self.hashed_password.encode('utf-8'))
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
    
    def increment_scan_count(self):
        """Increment user's scan count"""
        self.scan_count += 1
    
    def to_dict(self):
        """Convert user to dictionary for API responses"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "phone": self.phone,
            "company": self.company,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "scan_count": self.scan_count
        }

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    url = Column(Text, nullable=False)
    label = Column(String(50), nullable=False)  # "Safe", "Phishing", etc.
    confidence = Column(Float, nullable=False)
    risk_score = Column(Integer, nullable=False)
    features = Column(Text, nullable=True)  # JSON string of extracted features
    prediction_time = Column(Float, nullable=True)
    model_version = Column(String(20), nullable=True)
    ip_address = Column(String(45), nullable=True)  # Support IPv4 and IPv6
    user_agent = Column(Text, nullable=True)
    scan_date = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationship with user
    user = relationship("User", back_populates="scan_history")
    
    def get_features_dict(self):
        """Parse features JSON string to dictionary"""
        if self.features:
            try:
                return json.loads(self.features)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_features_dict(self, features_dict):
        """Set features from dictionary"""
        self.features = json.dumps(features_dict)
    
    def to_dict(self):
        """Convert scan to dictionary for API responses"""
        return {
            "id": self.id,
            "url": self.url,
            "label": self.label,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "features": self.get_features_dict(),
            "prediction_time": self.prediction_time,
            "model_version": self.model_version,
            "scan_date": self.scan_date
        }

class UserPreferences(Base):
    __tablename__ = "user_preferences"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    
    # General Settings
    dark_mode = Column(Boolean, default=False)
    language = Column(String(10), default="en")
    timezone = Column(String(50), default="UTC")
    auto_save = Column(Boolean, default=True)
    
    # Security Settings
    scan_sensitivity = Column(String(20), default="medium")  # low, medium, high
    realtime_protection = Column(Boolean, default=True)
    whitelist_domains = Column(Boolean, default=True)
    session_timeout = Column(Integer, default=60)  # minutes
    two_factor_enabled = Column(Boolean, default=False)
    
    # Notification Settings
    security_alerts = Column(Boolean, default=True)
    scan_completion = Column(Boolean, default=False)
    weekly_reports = Column(Boolean, default=False)
    system_updates = Column(Boolean, default=True)
    email_notifications = Column(Boolean, default=True)
    
    # Display Settings
    theme_color = Column(String(7), default="#667eea")  # Hex color
    results_per_page = Column(Integer, default=10)
    animation_speed = Column(Float, default=1.0)
    compact_mode = Column(Boolean, default=False)
    
    # Privacy Settings
    analytics = Column(Boolean, default=True)
    history_retention = Column(Integer, default=365)  # days
    public_profile = Column(Boolean, default=False)
    share_statistics = Column(Boolean, default=False)
    
    # Advanced Settings
    api_rate_limit = Column(Integer, default=100)  # requests per hour
    export_format = Column(String(10), default="json")  # json, csv, xml
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship with user
    user = relationship("User", back_populates="preferences")
    
    def to_dict(self):
        """Convert preferences to dictionary for API responses"""
        return {
            "darkMode": self.dark_mode,
            "language": self.language,
            "timezone": self.timezone,
            "autoSave": self.auto_save,
            "scanSensitivity": self.scan_sensitivity,
            "realtimeProtection": self.realtime_protection,
            "whitelistDomains": self.whitelist_domains,
            "sessionTimeout": self.session_timeout,
            "twoFactorEnabled": self.two_factor_enabled,
            "securityAlerts": self.security_alerts,
            "scanCompletion": self.scan_completion,
            "weeklyReports": self.weekly_reports,
            "systemUpdates": self.system_updates,
            "emailNotifications": self.email_notifications,
            "themeColor": self.theme_color,
            "resultsPerPage": self.results_per_page,
            "animationSpeed": self.animation_speed,
            "compactMode": self.compact_mode,
            "analytics": self.analytics,
            "historyRetention": self.history_retention,
            "publicProfile": self.public_profile,
            "shareStatistics": self.share_statistics,
            "apiRateLimit": self.api_rate_limit,
            "exportFormat": self.export_format
        }
    
    def update_from_dict(self, preferences_dict):
        """Update preferences from dictionary"""
        field_mapping = {
            "darkMode": "dark_mode",
            "language": "language",
            "timezone": "timezone",
            "autoSave": "auto_save",
            "scanSensitivity": "scan_sensitivity",
            "realtimeProtection": "realtime_protection",
            "whitelistDomains": "whitelist_domains",
            "sessionTimeout": "session_timeout",
            "twoFactorEnabled": "two_factor_enabled",
            "securityAlerts": "security_alerts",
            "scanCompletion": "scan_completion",
            "weeklyReports": "weekly_reports",
            "systemUpdates": "system_updates",
            "emailNotifications": "email_notifications",
            "themeColor": "theme_color",
            "resultsPerPage": "results_per_page",
            "animationSpeed": "animation_speed",
            "compactMode": "compact_mode",
            "analytics": "analytics",
            "historyRetention": "history_retention",
            "publicProfile": "public_profile",
            "shareStatistics": "share_statistics",
            "apiRateLimit": "api_rate_limit",
            "exportFormat": "export_format"
        }
        
        for frontend_key, db_key in field_mapping.items():
            if frontend_key in preferences_dict:
                setattr(self, db_key, preferences_dict[frontend_key])
        
        self.updated_at = datetime.utcnow()

class SessionToken(Base):
    __tablename__ = "session_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationship with user
    user = relationship("User", back_populates="session_tokens")
    
    def is_expired(self):
        """Check if token is expired"""
        return datetime.utcnow() > self.expires_at
    
    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used = datetime.utcnow()

class ApiKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)  # User-defined name for the API key
    key_hash = Column(String(255), unique=True, index=True, nullable=False)
    key_prefix = Column(String(10), nullable=False)  # First few characters for display
    permissions = Column(Text, nullable=True)  # JSON string of permissions
    rate_limit = Column(Integer, default=1000)  # requests per hour
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationship with user
    user = relationship("User", foreign_keys=[user_id])
    
    def get_permissions_list(self):
        """Parse permissions JSON string to list"""
        if self.permissions:
            try:
                return json.loads(self.permissions)
            except json.JSONDecodeError:
                return []
        return ["scan"]  # Default permission
    
    def set_permissions_list(self, permissions_list):
        """Set permissions from list"""
        self.permissions = json.dumps(permissions_list)
    
    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used = datetime.utcnow()
    
    def is_expired(self):
        """Check if API key is expired"""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False

class BlacklistedDomain(Base):
    __tablename__ = "blacklisted_domains"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    category = Column(String(50), nullable=False)  # malware, phishing, spam, adult, custom
    added_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_global = Column(Boolean, default=False)  # Global vs user-specific
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    blocked_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    added_by_user = relationship("User", foreign_keys=[added_by])
    
    def increment_blocked_count(self):
        """Increment blocked count when domain is accessed"""
        self.blocked_count += 1

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)  # login, logout, scan, profile_update, etc.
    resource = Column(String(100), nullable=True)  # What was acted upon
    resource_id = Column(String(100), nullable=True)  # ID of the resource
    details = Column(Text, nullable=True)  # Additional details as JSON
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationship
    user = relationship("User", foreign_keys=[user_id])
    
    def get_details_dict(self):
        """Parse details JSON string to dictionary"""
        if self.details:
            try:
                return json.loads(self.details)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_details_dict(self, details_dict):
        """Set details from dictionary"""
        self.details = json.dumps(details_dict)

class SystemSettings(Base):
    __tablename__ = "system_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=True)
    data_type = Column(String(20), default="string")  # string, integer, boolean, json
    description = Column(Text, nullable=True)
    is_public = Column(Boolean, default=False)  # Can be accessed by API
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_typed_value(self):
        """Get value with proper type casting"""
        if self.data_type == "integer":
            return int(self.value) if self.value else 0
        elif self.data_type == "boolean":
            return self.value.lower() in ('true', '1', 'yes') if self.value else False
        elif self.data_type == "json":
            try:
                return json.loads(self.value) if self.value else {}
            except json.JSONDecodeError:
                return {}
        else:
            return self.value or ""