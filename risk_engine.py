from datetime import datetime, timedelta
from models import LoginHistory, User
from config import Config
import json
import requests
import hashlib

class RiskScoringEngine:
    """Calculates risk scores based on contextual login factors."""
    
    # Weights for each risk indicator
    WEIGHTS = {
        'ip_geolocation': 25,
        'device_fingerprint': 20,
        'login_time': 15,
        'login_frequency': 15,
        'consecutive_failures': 15,
        'geo_velocity': 10
    }
    
    def __init__(self, ip_address, user_agent, username, user=None):
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.username = username
        self.user = user
        self.risk_scores = {}
        self.location_data = None
    
    def calculate_total_risk(self):
        """Calculate total risk score (0-100)."""
        self.risk_scores['ip_geolocation'] = self._check_ip_geolocation()
        self.risk_scores['device_fingerprint'] = self._check_device_fingerprint()
        self.risk_scores['login_time'] = self._check_login_time()
        self.risk_scores['login_frequency'] = self._check_login_frequency()
        self.risk_scores['consecutive_failures'] = self._check_consecutive_failures()
        self.risk_scores['geo_velocity'] = self._check_geo_velocity()
        
        total = sum(
            (self.WEIGHTS[factor] / 100) * (score / 3) * 100
            for factor, score in self.risk_scores.items()
        )
        
        return min(round(total, 2), 100)
    
    def get_risk_level(self, score):
        """Determine risk level based on score."""
        if score <= Config.RISK_LOW_MAX:
            return 'Low'
        elif score <= Config.RISK_MEDIUM_MAX:
            return 'Medium'
        elif score <= Config.RISK_HIGH_MAX:
            return 'High'
        else:
            return 'Critical'
    
    def get_required_action(self, risk_level):
        """Map risk level to authentication action."""
        actions = {
            'Low': 'password_only',
            'Medium': 'totp_or_email_otp',
            'High': 'totp_and_sms_otp',
            'Critical': 'block'
        }
        return actions.get(risk_level, 'totp_or_email_otp')
    
    def _get_location(self):
        """Get geolocation data from IP address."""
        if self.ip_address in ('127.0.0.1', 'localhost'):
            return {'city': 'Local', 'country': 'Local'}
        
        try:
            api_key = Config.IPSTACK_API_KEY
            if api_key:
                url = f'http://api.ipstack.com/{self.ip_address}?access_key={api_key}'
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    self.location_data = {
                        'city': data.get('city', 'Unknown'),
                        'country': data.get('country_name', 'Unknown'),
                        'latitude': data.get('latitude'),
                        'longitude': data.get('longitude')
                    }
                    return self.location_data
        except:
            pass
        
        self.location_data = {'city': 'Unknown', 'country': 'Unknown'}
        return self.location_data
    
    def _check_ip_geolocation(self):
        """0=matches known, 1=same region, 2=different country, 3=foreign/anonymous"""
        if not self.user:
            return 1
        
        location = self._get_location()
        country = location.get('country', '')
        
        # Check if country in known locations
        known_ips = json.loads(self.user.known_ips or '[]')
        known_countries = [loc.get('country') for loc in known_ips]
        
        if country in known_countries:
            return 0
        elif country == 'Unknown':
            return 2
        else:
            return 3
    
    def _check_device_fingerprint(self):
        """0=known device, 1=same family, 2=new, 3=suspicious"""
        if not self.user:
            return 1
        
        device_hash = hashlib.md5(self.user_agent.encode()).hexdigest()
        known_devices = json.loads(self.user.known_devices or '[]')
        
        if device_hash in known_devices:
            return 0
        
        # Check browser family
        ua = self.user_agent.lower()
        for device in known_devices:
            if any(browser in ua for browser in ['chrome', 'firefox', 'safari', 'edge']):
                if any(browser in device.lower() for browser in ['chrome', 'firefox', 'safari', 'edge']):
                    return 1
        
        return 2
    
    def _check_login_time(self):
        """0=normal hours, 1=slightly outside, 2=unusual, 3=deep night"""
        hour = datetime.utcnow().hour
        
        if 6 <= hour <= 22:
            return 0
        elif 5 <= hour < 6 or 22 < hour <= 23:
            return 1
        elif 4 <= hour < 5 or 23 < hour <= 24:
            return 2
        else:  # 0-4
            return 3
    
    def _check_login_frequency(self):
        """Check number of logins in last 24 hours."""
        since = datetime.utcnow() - timedelta(hours=24)
        count = LoginHistory.query.filter(
            LoginHistory.username_attempt == self.username,
            LoginHistory.timestamp >= since
        ).count()
        
        if count <= 2:
            return 0
        elif count <= 5:
            return 1
        elif count <= 10:
            return 2
        else:
            return 3
    
    def _check_consecutive_failures(self):
        """Check consecutive failed login attempts."""
        recent_logins = LoginHistory.query.filter(
            LoginHistory.username_attempt == self.username
        ).order_by(LoginHistory.timestamp.desc()).limit(10).all()
        
        consecutive_fails = 0
        for login in recent_logins:
            if not login.success:
                consecutive_fails += 1
            else:
                break
        
        if consecutive_fails == 0:
            return 0
        elif consecutive_fails <= 2:
            return 1
        elif consecutive_fails <= 4:
            return 2
        else:
            return 3
    
    def _check_geo_velocity(self):
        """Detect impossible travel (simplified)."""
        if not self.user or not self.location_data:
            return 0
        
        # Check last successful login location
        last_login = LoginHistory.query.filter(
            LoginHistory.user_id == self.user.id,
            LoginHistory.success == True
        ).order_by(LoginHistory.timestamp.desc()).first()
        
        if not last_login or not last_login.location:
            return 0
        
        # Simplified: if country changes rapidly, flag it
        if self.location_data.get('country') != 'Unknown' and \
           last_login.location != str(self.location_data):
            time_diff = (datetime.utcnow() - last_login.timestamp).total_seconds() / 3600
            if time_diff < 1:  # Less than 1 hour between different locations
                return 3
        
        return 0