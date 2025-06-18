from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
from typing import Optional, Dict, Any, List

# ========== USER SCHEMAS ==========
class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must contain only letters, numbers, underscores, and hyphens')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    phone: Optional[str] = None
    company: Optional[str] = None
    is_active: bool
    created_at: datetime
    scan_count: Optional[int] = 0
    
    class Config:
        from_attributes = True

class UserProfile(UserResponse):
    last_login: Optional[datetime] = None

class UserProfileUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None

# ========== AUTHENTICATION SCHEMAS ==========
class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class TokenData(BaseModel):
    username: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 6:
            raise ValueError('New password must be at least 6 characters long')
        return v

# ========== PREDICTION SCHEMAS ==========
class URLInput(BaseModel):
    url: str

    @validator('url')
    def validate_url(cls, v):
        from urllib.parse import urlparse
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        
        # Add protocol if missing
        if not v.startswith(('http://', 'https://')):
            v = "http://" + v
            
        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
        except Exception:
            raise ValueError("Invalid URL format")
        return v

class PredictionOutput(BaseModel):
    url: str
    label: str
    confidence: float
    risk_score: int
    features: Dict[str, Any]
    prediction_time: float
    scan_id: Optional[int] = None

# ========== SCAN HISTORY SCHEMAS ==========
class ScanHistoryResponse(BaseModel):
    id: int
    url: str
    label: str
    confidence: float
    risk_score: int
    features: Optional[str] = None
    prediction_time: Optional[float] = None
    scan_date: datetime

    class Config:
        from_attributes = True

class ScanHistoryDetail(ScanHistoryResponse):
    model_version: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

# ========== USER PREFERENCES SCHEMAS ==========
class UserPreferences(BaseModel):
    # General Settings
    darkMode: bool = False
    language: str = "en"
    timezone: str = "UTC"
    autoSave: bool = True
    
    # Security Settings
    scanSensitivity: str = "medium"
    realtimeProtection: bool = True
    whitelistDomains: bool = True
    sessionTimeout: int = 60
    twoFactorEnabled: bool = False
    
    # Notification Settings
    securityAlerts: bool = True
    scanCompletion: bool = False
    weeklyReports: bool = False
    systemUpdates: bool = True
    emailNotifications: bool = True
    
    # Display Settings
    themeColor: str = "#667eea"
    resultsPerPage: int = 10
    animationSpeed: float = 1.0
    compactMode: bool = False
    
    # Privacy Settings
    analytics: bool = True
    historyRetention: int = 365
    publicProfile: bool = False
    shareStatistics: bool = False
    
    # Advanced Settings
    apiRateLimit: int = 100
    exportFormat: str = "json"
    
    @validator('scanSensitivity')
    def validate_scan_sensitivity(cls, v):
        if v not in ['low', 'medium', 'high']:
            raise ValueError('Scan sensitivity must be low, medium, or high')
        return v
    
    @validator('language')
    def validate_language(cls, v):
        allowed_languages = ['en', 'es', 'fr', 'de', 'zh', 'ja', 'ko', 'pt', 'ru', 'it']
        if v not in allowed_languages:
            raise ValueError(f'Language must be one of: {", ".join(allowed_languages)}')
        return v
    
    @validator('resultsPerPage')
    def validate_results_per_page(cls, v):
        if v < 5 or v > 100:
            raise ValueError('Results per page must be between 5 and 100')
        return v
    
    @validator('animationSpeed')
    def validate_animation_speed(cls, v):
        if v < 0.1 or v > 3.0:
            raise ValueError('Animation speed must be between 0.1 and 3.0')
        return v
    
    @validator('historyRetention')
    def validate_history_retention(cls, v):
        if v < 0 or v > 3650:  # Max 10 years
            raise ValueError('History retention must be between 0 and 3650 days')
        return v

class UserPreferencesUpdate(BaseModel):
    # General Settings
    darkMode: Optional[bool] = None
    language: Optional[str] = None
    timezone: Optional[str] = None
    autoSave: Optional[bool] = None
    
    # Security Settings
    scanSensitivity: Optional[str] = None
    realtimeProtection: Optional[bool] = None
    whitelistDomains: Optional[bool] = None
    sessionTimeout: Optional[int] = None
    twoFactorEnabled: Optional[bool] = None
    
    # Notification Settings
    securityAlerts: Optional[bool] = None
    scanCompletion: Optional[bool] = None
    weeklyReports: Optional[bool] = None
    systemUpdates: Optional[bool] = None
    emailNotifications: Optional[bool] = None
    
    # Display Settings
    themeColor: Optional[str] = None
    resultsPerPage: Optional[int] = None
    animationSpeed: Optional[float] = None
    compactMode: Optional[bool] = None
    
    # Privacy Settings
    analytics: Optional[bool] = None
    historyRetention: Optional[int] = None
    publicProfile: Optional[bool] = None
    shareStatistics: Optional[bool] = None
    
    # Advanced Settings
    apiRateLimit: Optional[int] = None
    exportFormat: Optional[str] = None

# ========== BLACKLIST SCHEMAS ==========
class BlacklistDomain(BaseModel):
    domain: str
    category: str
    description: Optional[str] = None
    
    @validator('category')
    def validate_category(cls, v):
        allowed_categories = ['malware', 'phishing', 'spam', 'adult', 'custom']
        if v not in allowed_categories:
            raise ValueError(f'Category must be one of: {", ".join(allowed_categories)}')
        return v
    
    @validator('domain')
    def validate_domain(cls, v):
        import re
        # Simple domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, v):
            raise ValueError('Invalid domain format')
        return v.lower()

class BlacklistResponse(BaseModel):
    id: int
    domain: str
    category: str
    description: Optional[str] = None
    is_active: bool
    blocked_count: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# ========== ANALYTICS SCHEMAS ==========
class UserAnalytics(BaseModel):
    total_scans: int
    safe_scans: int
    phishing_scans: int
    recent_scans_30d: int
    accuracy_rate: float
    avg_confidence: float
    avg_risk_score: float
    monthly_breakdown: Dict[str, Dict[str, int]]

class SystemAnalytics(BaseModel):
    total_users: int
    total_scans: int
    total_threats_blocked: int
    average_scans_per_user: float
    top_threat_categories: List[Dict[str, Any]]
    scan_trends: Dict[str, int]

# ========== API KEY SCHEMAS ==========
class ApiKeyCreate(BaseModel):
    name: str
    permissions: Optional[List[str]] = ["scan"]
    expires_at: Optional[datetime] = None
    
    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3 or len(v) > 100:
            raise ValueError('API key name must be between 3 and 100 characters')
        return v

class ApiKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    permissions: List[str]
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# ========== SYSTEM SCHEMAS ==========
class SystemHealth(BaseModel):
    status: str
    database_connected: bool
    model_loaded: bool
    model_type: str
    total_users: Optional[int] = 0
    total_scans: Optional[int] = 0
    version: str
    timestamp: str
    features: List[str]

class SystemSettings(BaseModel):
    maintenance_mode: bool = False
    allow_registration: bool = True
    max_scans_per_day: int = 1000
    enable_analytics: bool = True
    default_scan_sensitivity: str = "medium"
    session_timeout_minutes: int = 1440
    max_history_retention_days: int = 365

# ========== EXPORT SCHEMAS ==========
class ExportRequest(BaseModel):
    format: str = "json"
    include_scan_history: bool = True
    include_preferences: bool = True
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    
    @validator('format')
    def validate_format(cls, v):
        if v not in ['json', 'csv']:
            raise ValueError('Export format must be json or csv')
        return v

# ========== NOTIFICATION SCHEMAS ==========
class NotificationSettings(BaseModel):
    email_notifications: bool = True
    security_alerts: bool = True
    weekly_reports: bool = False
    marketing_emails: bool = False
    
class NotificationPreference(BaseModel):
    type: str
    enabled: bool
    frequency: Optional[str] = "immediate"
    
    @validator('type')
    def validate_type(cls, v):
        allowed_types = ['security_alert', 'scan_complete', 'weekly_report', 'system_update']
        if v not in allowed_types:
            raise ValueError(f'Notification type must be one of: {", ".join(allowed_types)}')
        return v

# ========== AUDIT LOG SCHEMAS ==========
class AuditLogEntry(BaseModel):
    id: int
    action: str
    resource: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    success: bool
    timestamp: datetime
    
    class Config:
        from_attributes = True

# ========== ERROR SCHEMAS ==========
class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
    timestamp: Optional[str] = None

class ValidationError(BaseModel):
    field: str
    message: str
    invalid_value: Optional[str] = None

# ========== PAGINATION SCHEMAS ==========
class PaginationParams(BaseModel):
    limit: int = 100
    offset: int = 0
    
    @validator('limit')
    def validate_limit(cls, v):
        if v < 1 or v > 1000:
            raise ValueError('Limit must be between 1 and 1000')
        return v
    
    @validator('offset')
    def validate_offset(cls, v):
        if v < 0:
            raise ValueError('Offset must be non-negative')
        return v

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    limit: int
    offset: int
    has_more: bool