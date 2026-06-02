from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import pyotp

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20), nullable=True)
    
    # Known good locations and devices (stored as JSON strings)
    known_ips = db.Column(db.Text, default='[]')
    known_devices = db.Column(db.Text, default='[]')
    
    # Relationships
    login_history = db.relationship('LoginHistory', backref='user', lazy=True)
    
    def get_totp_uri(self):
        if self.totp_secret:
            return pyotp.totp.TOTP(self.totp_secret)\
                   .provisioning_uri(name=self.email, issuer_name="RiskBased2FA")
        return None

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username_attempt = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    success = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Float, default=0)
    risk_level = db.Column(db.String(20))
    action_taken = db.Column(db.String(50))
    location = db.Column(db.String(200))