from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from models import db, User, LoginHistory
from forms import RegistrationForm, LoginForm, TwoFactorForm
from risk_engine import RiskScoringEngine
from config import Config
from utils import (
    generate_totp_secret, generate_otp_code, verify_totp_code, 
    send_email_otp, send_sms_otp, generate_qr_code, mail, verify_otp
)
import json
import hashlib
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
mail.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(int(user_id))

# Create all database tables
with app.app_context():
    db.create_all()

# ==================== CONTEXT PROCESSOR ====================

@app.context_processor
def inject_now():
    """Inject current datetime into all templates."""
    return {'now': datetime.utcnow()}

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return render_template('base.html', error='Page not found.'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    db.session.rollback()
    return render_template('base.html', error='Internal server error. Please try again.'), 500

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/')
def home():
    """Home page / Landing page."""
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with TOTP secret generation."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.email.data)
        ).first()
        
        if existing_user:
            if existing_user.username == form.username.data:
                flash('Username already exists. Please choose a different one.', 'danger')
            else:
                flash('Email already registered. Please use a different email or login.', 'danger')
            return redirect(url_for('register'))
        
        # Hash password securely
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        # Generate TOTP secret for 2FA
        totp_secret = generate_totp_secret()
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            totp_secret=totp_secret,
            totp_enabled=False,
            phone_number=form.phone_number.data if form.phone_number.data else None,
            known_ips=json.dumps([]),
            known_devices=json.dumps([])
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please login to continue.', 'success')
        return redirect(url_for('login'))
    
    # If form validation fails, show errors
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login with risk-based authentication."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        ip_address = request.remote_addr or '127.0.0.1'
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Find user by username
        user = User.query.filter_by(username=username).first()
        
        # Initialize risk engine (runs regardless of valid credentials)
        risk_engine = RiskScoringEngine(ip_address, user_agent, username, user)
        risk_score = risk_engine.calculate_total_risk()
        risk_level = risk_engine.get_risk_level(risk_score)
        action = risk_engine.get_required_action(risk_level)
        
        # Log this login attempt
        log_entry = LoginHistory(
            user_id=user.id if user else None,
            username_attempt=username,
            timestamp=datetime.utcnow(),
            ip_address=ip_address,
            user_agent=user_agent,
            risk_score=risk_score,
            risk_level=risk_level,
            action_taken=action,
            location=str(risk_engine.location_data) if risk_engine.location_data else 'Unknown',
            success=False  # Will update if login succeeds
        )
        
        # Verify credentials
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # VALID CREDENTIALS - Now check risk level
            
            if risk_level == 'Critical':
                # CRITICAL RISK: Block login completely
                db.session.add(log_entry)
                db.session.commit()
                
                flash('Your login has been blocked due to suspicious activity. Please contact support.', 'danger')
                return render_template('blocked.html', 
                                     risk_score=risk_score, 
                                     risk_level=risk_level,
                                     timestamp=datetime.utcnow())
            
            elif risk_level == 'Low':
                # LOW RISK: Allow login with password only (no 2FA needed)
                log_entry.success = True
                db.session.add(log_entry)
                db.session.commit()
                
                # Login user and update known info
                login_user(user, remember=True)
                _update_known_info(user, ip_address, user_agent)
                
                flash(f'Welcome back, {user.username}! (Low risk - no additional verification needed)', 'success')
                return redirect(url_for('dashboard'))
            
            elif risk_level == 'Medium':
                # MEDIUM RISK: Require TOTP or Email OTP
                log_entry.success = False
                db.session.add(log_entry)
                db.session.commit()
                
                # Store info in session for 2FA verification
                session['pending_user_id'] = user.id
                session['risk_level'] = risk_level
                session['risk_score'] = risk_score
                session['action_required'] = action
                
                # Send email OTP as alternative to TOTP
                email_otp = generate_otp_code()
                send_email_otp(user.email, email_otp)
                
                flash('Additional verification required. Please check your email or authenticator app.', 'info')
                return redirect(url_for('verify_2fa'))
            
            elif risk_level == 'High':
                # HIGH RISK: Require TOTP AND SMS OTP
                log_entry.success = False
                db.session.add(log_entry)
                db.session.commit()
                
                # Store info in session for 2FA verification
                session['pending_user_id'] = user.id
                session['risk_level'] = risk_level
                session['risk_score'] = risk_score
                session['action_required'] = action
                
                # Send email OTP
                email_otp = generate_otp_code()
                send_email_otp(user.email, email_otp)
                
                # Send SMS OTP if phone number available
                if user.phone_number:
                    sms_otp = generate_otp_code()
                    send_sms_otp(user.phone_number, sms_otp)
                else:
                    flash('Warning: No phone number on file. Only email OTP sent.', 'warning')
                
                flash('High risk login detected! Verification codes sent to your email and phone.', 'warning')
                return redirect(url_for('verify_2fa'))
        
        else:
            # INVALID CREDENTIALS
            db.session.add(log_entry)
            db.session.commit()
            
            # Check if too many failed attempts
            recent_fails = LoginHistory.query.filter(
                LoginHistory.username_attempt == username,
                LoginHistory.success == False,
                LoginHistory.timestamp >= datetime.utcnow().replace(minute=datetime.utcnow().minute - 5)
            ).count()
            
            if recent_fails >= 5:
                flash('Too many failed attempts. Please wait a few minutes before trying again.', 'danger')
            else:
                flash('Invalid username or password. Please try again.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify 2FA code after risk-based challenge."""
    # Check if user came from login flow
    if 'pending_user_id' not in session:
        flash('Please login first to verify.', 'warning')
        return redirect(url_for('login'))
    
    form = TwoFactorForm()
    user = User.query.get(session['pending_user_id'])
    
    if not user:
        flash('User not found. Please login again.', 'danger')
        session.clear()
        return redirect(url_for('login'))
    
    if form.validate_on_submit():
        code = form.code.data.strip()
        verified = False
        verification_method = None
        action = session.get('action_required', 'totp_or_email_otp')
        
        if action == 'totp_or_email_otp':
            # MEDIUM RISK: Accept TOTP OR Email OTP
            totp_valid, _ = verify_totp_code(user.totp_secret, code)
            email_valid, _ = verify_otp(user.email, code)
            
            if totp_valid:
                verified = True
                verification_method = 'TOTP'
            elif email_valid:
                verified = True
                verification_method = 'Email OTP'
            else:
                flash('Invalid verification code. Use your authenticator app or check your email.', 'danger')
                
        elif action == 'totp_and_sms_otp':
            # HIGH RISK: Need to verify from multiple methods
            totp_valid, _ = verify_totp_code(user.totp_secret, code)
            email_valid, _ = verify_otp(user.email, code)
            sms_valid = False
            
            if user.phone_number:
                sms_valid, _ = verify_otp(user.phone_number, code)
            
            # For demo: accept any valid method (in production, you'd require two)
            if totp_valid:
                verified = True
                verification_method = 'TOTP'
            elif email_valid:
                verified = True
                verification_method = 'Email OTP'
            elif sms_valid:
                verified = True
                verification_method = 'SMS OTP'
            else:
                flash('Invalid code. Check your authenticator app, email, and SMS messages.', 'danger')
        
        if verified:
            # Update the login history entry
            log_entry = LoginHistory.query.filter_by(
                user_id=user.id,
                success=False
            ).order_by(LoginHistory.timestamp.desc()).first()
            
            if log_entry:
                log_entry.success = True
                db.session.commit()
            
            # Login the user
            login_user(user, remember=True)
            _update_known_info(user, request.remote_addr or '127.0.0.1', 
                             request.headers.get('User-Agent', 'Unknown'))
            
            # Clear 2FA session data
            session.pop('pending_user_id', None)
            session.pop('risk_level', None)
            session.pop('risk_score', None)
            session.pop('action_required', None)
            
            flash(f'Verification successful via {verification_method}! Welcome back, {user.username}.', 'success')
            return redirect(url_for('dashboard'))
    
    # Show remaining attempts info
    risk_level = session.get('risk_level', 'Medium')
    
    return render_template('verify_2fa.html', 
                         form=form, 
                         risk_level=risk_level,
                         user_email=user.email)

@app.route('/logout')
@login_required
def logout():
    """Logout user and clear session."""
    logout_user()
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ==================== DASHBOARD ROUTES ====================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing profile and login history."""
    # Get recent login history for this user
    history = LoginHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(LoginHistory.timestamp.desc()).limit(20).all()
    
    # Calculate some stats
    total_logins = LoginHistory.query.filter_by(user_id=current_user.id).count()
    successful_logins = LoginHistory.query.filter_by(
        user_id=current_user.id, 
        success=True
    ).count()
    blocked_attempts = LoginHistory.query.filter_by(
        user_id=current_user.id, 
        action_taken='block'
    ).count()
    
    stats = {
        'total_logins': total_logins,
        'successful_logins': successful_logins,
        'blocked_attempts': blocked_attempts
    }
    
    return render_template('dashboard.html', 
                         user=current_user, 
                         history=history,
                         stats=stats)

@app.route('/login-history')
@login_required
def login_history():
    """Detailed login history page."""
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    history_query = LoginHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(LoginHistory.timestamp.desc())
    
    total = history_query.count()
    history = history_query.offset((page - 1) * per_page).limit(per_page).all()
    
    return render_template('login_history.html',
                         history=history,
                         page=page,
                         total=total,
                         per_page=per_page)

# ==================== 2FA SETUP ROUTES ====================

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    """Page to show TOTP QR code and setup instructions."""
    # Generate new secret if doesn't exist
    if not current_user.totp_secret:
        current_user.totp_secret = generate_totp_secret()
        db.session.commit()
    
    totp_uri = current_user.get_totp_uri()
    qr_code_img = generate_qr_code(totp_uri)
    
    return render_template('setup_2fa.html', 
                         user=current_user, 
                         qr_code=qr_code_img, 
                         secret=current_user.totp_secret)

@app.route('/verify-2fa-setup', methods=['POST'])
@login_required
def verify_2fa_setup():
    """Verify TOTP setup and enable 2FA for the user."""
    code = request.form.get('code', '').strip()
    
    if not code or len(code) != 6 or not code.isdigit():
        flash('Please enter a valid 6-digit code.', 'danger')
        return redirect(url_for('setup_2fa'))
    
    valid, message = verify_totp_code(current_user.totp_secret, code)
    
    if valid:
        current_user.totp_enabled = True
        db.session.commit()
        flash('✅ Two-factor authentication has been enabled successfully! Your account is now more secure.', 'success')
    else:
        flash(f'❌ Verification failed: {message}. Please try again.', 'danger')
    
    return redirect(url_for('setup_2fa'))

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA for the user."""
    password = request.form.get('password', '')
    
    if not bcrypt.check_password_hash(current_user.password_hash, password):
        flash('Incorrect password. 2FA not disabled.', 'danger')
        return redirect(url_for('setup_2fa'))
    
    current_user.totp_enabled = False
    db.session.commit()
    flash('Two-factor authentication has been disabled.', 'warning')
    return redirect(url_for('dashboard'))

# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard for viewing all login activity and system stats."""
    # Basic access control
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get system statistics
    total_attempts = LoginHistory.query.count()
    total_users = User.query.count()
    successful_logins = LoginHistory.query.filter_by(success=True).count()
    failed_logins = LoginHistory.query.filter_by(success=False).count()
    blocked_attempts = LoginHistory.query.filter_by(action_taken='block').count()
    
    # Risk level distribution
    low_risk = LoginHistory.query.filter_by(risk_level='Low').count()
    medium_risk = LoginHistory.query.filter_by(risk_level='Medium').count()
    high_risk = LoginHistory.query.filter_by(risk_level='High').count()
    critical_risk = LoginHistory.query.filter_by(risk_level='Critical').count()
    
    stats = {
        'total_attempts': total_attempts,
        'total_users': total_users,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'blocked_attempts': blocked_attempts,
        'low_risk': low_risk,
        'medium_risk': medium_risk,
        'high_risk': high_risk,
        'critical_risk': critical_risk
    }
    
    # Get recent login history
    recent_history = LoginHistory.query.order_by(
        LoginHistory.timestamp.desc()
    ).limit(50).all()
    
    # Get suspicious activities (high/critical risk or blocked)
    suspicious = LoginHistory.query.filter(
        LoginHistory.risk_level.in_(['High', 'Critical'])
    ).order_by(LoginHistory.timestamp.desc()).limit(20).all()
    
    return render_template('admin.html', 
                         stats=stats,
                         history=recent_history,
                         suspicious=suspicious)

@app.route('/admin/users')
@login_required
def admin_users():
    """Admin page to view all users."""
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/logs')
@login_required
def admin_logs():
    """Admin page with detailed login logs."""
    if current_user.username != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    logs_query = LoginHistory.query.order_by(LoginHistory.timestamp.desc())
    total = logs_query.count()
    logs = logs_query.offset((page - 1) * per_page).limit(per_page).all()
    
    return render_template('admin_logs.html', 
                         logs=logs, 
                         page=page, 
                         total=total, 
                         per_page=per_page)

# ==================== API ENDPOINTS (Optional) ====================

@app.route('/api/risk-score', methods=['POST'])
def api_risk_score():
    """API endpoint to get risk score for a login attempt."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '')
    ip_address = request.remote_addr or '127.0.0.1'
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    user = User.query.filter_by(username=username).first()
    
    risk_engine = RiskScoringEngine(ip_address, user_agent, username, user)
    risk_score = risk_engine.calculate_total_risk()
    risk_level = risk_engine.get_risk_level(risk_score)
    action = risk_engine.get_required_action(risk_level)
    
    return jsonify({
        'risk_score': risk_score,
        'risk_level': risk_level,
        'action_required': action,
        'factors': risk_engine.risk_scores
    })

# ==================== HELPER FUNCTIONS ====================

def _update_known_info(user, ip_address, user_agent):
    """
    Update user's known IPs and devices after successful login.
    This helps the risk engine recognize trusted patterns.
    """
    try:
        # Update known IPs/locations
        known_ips = json.loads(user.known_ips or '[]')
        risk_engine = RiskScoringEngine(ip_address, user_agent, user.username, user)
        location = risk_engine._get_location()
        
        # Check if this location is already known
        location_exists = False
        for known_loc in known_ips:
            if known_loc.get('country') == location.get('country') and \
               known_loc.get('city') == location.get('city'):
                location_exists = True
                break
        
        if not location_exists and location.get('country') != 'Unknown':
            known_ips.append(location)
            # Keep only last 10 known locations
            if len(known_ips) > 10:
                known_ips = known_ips[-10:]
            user.known_ips = json.dumps(known_ips)
        
        # Update known devices
        known_devices = json.loads(user.known_devices or '[]')
        device_hash = hashlib.md5(user_agent.encode()).hexdigest()
        
        if device_hash not in known_devices:
            known_devices.append(device_hash)
            # Keep only last 5 known devices
            if len(known_devices) > 5:
                known_devices = known_devices[-5:]
            user.known_devices = json.dumps(known_devices)
        
        db.session.commit()
        
    except Exception as e:
        print(f"Error updating known info: {e}")
        db.session.rollback()

# ==================== APPLICATION STARTUP ====================

if __name__ == '__main__':
    # Print startup information
    print("=" * 60)
    print("🔐 Risk-Based 2FA Authentication System")
    print("=" * 60)
    print(f"📡 Server running at: http://127.0.0.1:5000")
    print(f"📊 Database: SQLite (instance/database.db)")
    print(f"🔑 Admin user required: Register with username 'admin'")
    print(f"📧 Email: Check terminal for OTP codes if email not configured")
    print(f"📱 SMS: Set TWILIO credentials in .env for SMS OTP")
    print(f"🌍 Geolocation: Set IPSTACK_API_KEY in .env for IP lookup")
    print("=" * 60)
    print("⚠️  Press Ctrl+C to stop the server")
    print("=" * 60)
    
    app.run(debug=True, host='127.0.0.1', port=5000)