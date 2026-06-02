import pyotp
import random
import string
import qrcode
import io
import base64
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from twilio.rest import Client
from config import Config

mail = Mail()

# OTP Storage (in-memory for demo - use database in production)
otp_store = {}

def generate_totp_secret():
    """Generate random base32 secret for TOTP."""
    return pyotp.random_base32()

def generate_otp_code(length=6):
    """Generate a random numeric OTP."""
    return ''.join(random.choices(string.digits, k=length))

def generate_qr_code(totp_uri):
    """Generate QR code image for TOTP setup."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding in HTML
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_base64}"

def send_email_otp(email, otp_code):
    """Send OTP via email using Flask-Mail."""
    try:
        msg = Message(
            subject='Your Login Verification Code',
            recipients=[email],
            body=f'''
            Hello,
            
            Your one-time verification code is: {otp_code}
            
            This code will expire in 5 minutes.
            
            If you did not attempt to login, please change your password immediately.
            
            - Risk-Based 2FA System
            '''
        )
        mail.send(msg)
        print(f"[EMAIL SENT] To: {email}, Code: {otp_code}")
        
        # Store OTP for verification
        otp_store[email] = {
            'code': otp_code,
            'expires': datetime.utcnow() + timedelta(minutes=5)
        }
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        print(f"[EMAIL OTP - SIMULATED] To: {email}, Code: {otp_code}")
        # Still store for testing
        otp_store[email] = {
            'code': otp_code,
            'expires': datetime.utcnow() + timedelta(minutes=5)
        }
        return True  # Return True for testing even if email fails

def send_sms_otp(phone_number, otp_code):
    """Send OTP via SMS using Twilio."""
    try:
        client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f'Your verification code is: {otp_code}',
            from_=Config.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        print(f"[SMS SENT] To: {phone_number}, Code: {otp_code}, SID: {message.sid}")
        
        # Store OTP for verification
        otp_store[phone_number] = {
            'code': otp_code,
            'expires': datetime.utcnow() + timedelta(minutes=5)
        }
        return True
    except Exception as e:
        print(f"[SMS ERROR] {e}")
        print(f"[SMS OTP - SIMULATED] To: {phone_number}, Code: {otp_code}")
        # Still store for testing
        otp_store[phone_number] = {
            'code': otp_code,
            'expires': datetime.utcnow() + timedelta(minutes=5)
        }
        return True  # Return True for testing

def verify_otp(identifier, code):
    """Verify OTP code for email or phone."""
    stored = otp_store.get(identifier)
    if not stored:
        return False, "No OTP found. Please request a new code."
    
    if datetime.utcnow() > stored['expires']:
        del otp_store[identifier]
        return False, "OTP has expired. Please request a new code."
    
    if stored['code'] != code:
        return False, "Invalid OTP code."
    
    # Clean up after successful verification
    del otp_store[identifier]
    return True, "Code verified successfully."

def verify_totp_code(secret, code):
    """Verify a TOTP code against a secret."""
    if not secret:
        return False, "No TOTP secret configured"
    
    totp = pyotp.TOTP(secret)
    
    if totp.verify(code, valid_window=1):
        return True, "Code verified successfully"
    else:
        return False, "Invalid TOTP code"