import os
from dotenv import load_dotenv

load_dotenv()  # Load .env file

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-change-in-production-abc123xyz'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 2FA Settings
    TOTP_ISSUER = "RiskBased2FA"
    
    # IP Geolocation - Get free key at https://ipstack.com/signup/free
    IPSTACK_API_KEY = os.environ.get('IPSTACK_API_KEY') or ''
    
    # Email Settings - Use Gmail App Password or SendGrid
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or ''
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or ''
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@riskbased2fa.com'
    
    # SMS Settings - Get free trial at https://www.twilio.com/try-twilio
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID') or ''
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN') or ''
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER') or ''
    
    # Risk Scoring Thresholds
    RISK_LOW_MAX = 30
    RISK_MEDIUM_MAX = 65
    RISK_HIGH_MAX = 85