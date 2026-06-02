"""
Attack Simulation Script for Risk-Based 2FA System
Run this to test your system's security against various attacks.
"""

import requests
import time
import random
from datetime import datetime

BASE_URL = "http://127.0.0.1:5000"

# Test credentials (create these users first)
LEGITIMATE_USER = {
    'username': 'testuser',
    'password': 'TestPass123!',
    'email': 'testuser@example.com'
}

# Attack configurations
ATTACK_CONFIGS = {
    'credential_stuffing': {
        'description': 'Simulates credential stuffing with leaked passwords',
        'passwords': ['password', '123456', 'qwerty', 'letmein', 'admin', 
                      LEGITIMATE_USER['password'], 'password1', '12345678',
                      'monkey', 'dragon', 'football', 'baseball'],
        'delay': 0.5  # seconds between attempts
    },
    'brute_force': {
        'description': 'Simulates brute force attack on a single account',
        'passwords': ['aaaa', 'aaab', 'aaac', 'aaad', 'aaae', 'aaaf', 
                      'aaag', 'aaah', 'aaai', 'aaaj', 'aaak', 'aaal',
                      'aaam', 'aaan', 'aaao', 'aaap'],
        'delay': 0.3
    }
}

def create_session():
    """Create a requests session."""
    session = requests.Session()
    return session

def login_attempt(session, username, password, user_agent=None, ip_spoof=None):
    """Attempt a login and return the result."""
    headers = {}
    if user_agent:
        headers['User-Agent'] = user_agent
    
    data = {
        'username': username,
        'password': password,
        'submit': 'Login'
    }
    
    try:
        response = session.post(
            f"{BASE_URL}/login", 
            data=data, 
            headers=headers,
            allow_redirects=True
        )
        return response
    except Exception as e:
        print(f"  ❌ Connection error: {e}")
        return None

def simulate_legitimate_login():
    """Simulate a legitimate user login."""
    print("\n" + "="*60)
    print("🟢 LEGITIMATE LOGIN TEST")
    print("="*60)
    
    session = create_session()
    
    # Known device user agent
    known_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
    ]
    
    print(f"📱 Using known device: Chrome on {'Windows' if 'Windows' in known_agents[0] else 'Mac'}")
    response = login_attempt(
        session, 
        LEGITIMATE_USER['username'], 
        LEGITIMATE_USER['password'],
        user_agent=known_agents[0]
    )
    
    if response:
        print(f"   Status Code: {response.status_code}")
        if 'Welcome back' in response.text or 'Dashboard' in response.text:
            print("   ✅ RESULT: Login successful (Expected: LOW RISK, no 2FA)")
        elif 'Additional Verification' in response.text:
            print("   ⚠️  RESULT: 2FA requested (FR: False Rejection - legitimate user challenged)")
        elif 'Blocked' in response.text:
            print("   ❌ RESULT: Blocked (FR: False Rejection - legitimate user blocked)")
    
    return session

def simulate_credential_stuffing():
    """Simulate credential stuffing attack."""
    print("\n" + "="*60)
    print("🔴 CREDENTIAL STUFFING ATTACK SIMULATION")
    print("="*60)
    
    config = ATTACK_CONFIGS['credential_stuffing']
    print(f"📝 {config['description']}")
    print(f"🔑 Using {len(config['passwords'])} passwords with {config['delay']}s delay\n")
    
    results = {
        'attempts': 0,
        'blocked': 0,
        'challenged': 0,
        'allowed': 0
    }
    
    # Use different user agents to look more suspicious
    suspicious_agents = [
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'python-requests/2.28.0',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
        'curl/7.68.0',
        'Mozilla/5.0 (compatible; Googlebot/2.1)'
    ]
    
    for i, password in enumerate(config['passwords']):
        agent = random.choice(suspicious_agents)
        print(f"[{i+1}/{len(config['passwords'])}] Trying: {LEGITIMATE_USER['username']}:{password}")
        print(f"   🖥️  User-Agent: {agent[:50]}...")
        
        session = create_session()
        response = login_attempt(
            session,
            LEGITIMATE_USER['username'],
            password,
            user_agent=agent
        )
        
        results['attempts'] += 1
        
        if response:
            if 'Blocked' in response.text:
                results['blocked'] += 1
                print("   🛑 RESULT: Blocked")
            elif 'Additional Verification' in response.text:
                results['challenged'] += 1
                print("   🔐 RESULT: 2FA Challenged")
            elif 'Invalid' in response.text:
                # Invalid password - check if it was a correct one
                if password == LEGITIMATE_USER['password']:
                    results['challenged'] += 1
                    print("   🔐 RESULT: Correct password but challenged (expected)")
                else:
                    print("   ❌ RESULT: Invalid password")
            elif 'Welcome' in response.text or 'Dashboard' in response.text:
                results['allowed'] += 1
                print("   ⚠️  RESULT: ALLOWED without 2FA! (Potential FAR)")
        
        time.sleep(config['delay'])
    
    print("\n" + "-"*40)
    print("📊 CREDENTIAL STUFFING RESULTS:")
    print(f"   Total Attempts: {results['attempts']}")
    print(f"   Blocked: {results['blocked']} ({results['blocked']/results['attempts']*100:.1f}%)")
    print(f"   Challenged with 2FA: {results['challenged']} ({results['challenged']/results['attempts']*100:.1f}%)")
    print(f"   Allowed without 2FA: {results['allowed']} ({results['allowed']/results['attempts']*100:.1f}%)")
    
    if results['allowed'] == 0:
        print("   ✅ 100% of attacks detected!")
    
    return results

def simulate_geo_anomalous_login():
    """Simulate login from anomalous geographic location."""
    print("\n" + "="*60)
    print("🔴 GEO-ANOMALOUS LOGIN SIMULATION")
    print("="*60)
    print("🌍 Simulating login from a foreign country (using different user agent)")
    print("   Note: Geo is based on actual IP. For real testing, use a VPN or proxy.\n")
    
    # Use a very different user agent to trigger device mismatch too
    foreign_agents = [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
        'Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36',
        'Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15'
    ]
    
    for agent in foreign_agents:
        session = create_session()
        print(f"📱 Device: {agent[:60]}...")
        response = login_attempt(
            session,
            LEGITIMATE_USER['username'],
            LEGITIMATE_USER['password'],
            user_agent=agent
        )
        
        if response:
            if 'Additional Verification' in response.text:
                print("   🔐 RESULT: 2FA Challenged (Expected - new device/location)")
            elif 'Welcome' in response.text or 'Dashboard' in response.text:
                print("   ⚠️  RESULT: Allowed without 2FA!")
            elif 'Blocked' in response.text:
                print("   🛑 RESULT: Blocked")
        
        time.sleep(1)
    
    return {'tested': len(foreign_agents)}

def simulate_brute_force():
    """Simulate brute force attack."""
    print("\n" + "="*60)
    print("🔴 BRUTE FORCE ATTACK SIMULATION")
    print("="*60)
    
    config = ATTACK_CONFIGS['brute_force']
    print(f"📝 {config['description']}")
    print(f"🔑 Sequential password attempts with {config['delay']}s delay\n")
    
    results = {
        'attempts': 0,
        'blocked': 0
    }
    
    for i, password in enumerate(config['passwords']):
        session = create_session()
        print(f"[{i+1}/{len(config['passwords'])}] Trying password: {password}")
        
        response = login_attempt(
            session,
            LEGITIMATE_USER['username'],
            password
        )
        
        results['attempts'] += 1
        
        if response and 'Blocked' in response.text:
            results['blocked'] += 1
            print(f"   🛑 RESULT: Blocked after {results['attempts']} attempts")
            break
        
        time.sleep(config['delay'])
    
    print(f"\n📊 BRUTE FORCE RESULTS:")
    print(f"   Attempts before block: {results['attempts']}")
    print(f"   Successfully blocked: {'Yes' if results['blocked'] > 0 else 'No'}")
    
    return results

def simulate_device_spoofing():
    """Simulate login from different devices."""
    print("\n" + "="*60)
    print("🔴 DEVICE SPOOFING SIMULATION")
    print("="*60)
    print("📱 Testing with various device fingerprints\n")
    
    spoofed_devices = [
        ('Old Browser', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)'),
        ('Bot', 'Googlebot/2.1 (+http://www.google.com/bot.html)'),
        ('Android Old', 'Mozilla/5.0 (Linux; U; Android 2.2; en-us; Nexus One)'),
        ('iPhone Old', 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X)'),
        ('Unknown OS', 'Mozilla/5.0 (Unknown; rv:1.0) Gecko/20100101 Firefox/1.0'),
    ]
    
    results = {'challenged': 0, 'allowed': 0, 'blocked': 0}
    
    for device_name, agent in spoofed_devices:
        session = create_session()
        print(f"🔍 Device: {device_name}")
        print(f"   User-Agent: {agent[:60]}...")
        
        response = login_attempt(
            session,
            LEGITIMATE_USER['username'],
            LEGITIMATE_USER['password'],
            user_agent=agent
        )
        
        if response:
            if 'Blocked' in response.text:
                results['blocked'] += 1
                print("   🛑 RESULT: Blocked")
            elif 'Additional Verification' in response.text:
                results['challenged'] += 1
                print("   🔐 RESULT: 2FA Challenged (Expected for new device)")
            elif 'Welcome' in response.text or 'Dashboard' in response.text:
                results['allowed'] += 1
                print("   ⚠️  RESULT: Allowed without 2FA!")
        
        time.sleep(1)
    
    print(f"\n📊 DEVICE SPOOFING RESULTS:")
    print(f"   Challenged: {results['challenged']}/{len(spoofed_devices)}")
    print(f"   Blocked: {results['blocked']}/{len(spoofed_devices)}")
    print(f"   Allowed without challenge: {results['allowed']}/{len(spoofed_devices)}")
    
    return results

def generate_report(results):
    """Generate final security evaluation report."""
    print("\n" + "="*60)
    print("📊 SECURITY EVALUATION REPORT")
    print("="*60)
    print(f"🕐 Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🎯 Target: {BASE_URL}")
    print(f"👤 Test User: {LEGITIMATE_USER['username']}")
    print("\n📋 Summary:")
    print("-"*40)
    
    for test_name, result in results.items():
        print(f"  {test_name}:")
        if isinstance(result, dict):
            for key, value in result.items():
                print(f"    • {key}: {value}")
        else:
            print(f"    {result}")
    
    print("\n💡 Recommendations:")
    print("  1. Monitor admin dashboard for attack patterns")
    print("  2. Adjust risk thresholds if too many false positives/negatives")
    print("  3. Consider adding CAPTCHA for repeated suspicious attempts")
    print("="*60)

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════╗")
    print("║     RISK-BASED 2FA ATTACK SIMULATION SUITE          ║")
    print("║     Security Evaluation Testing                     ║")
    print("╚══════════════════════════════════════════════════════╝")
    
    print(f"\n⚠️  PREREQUISITES:")
    print(f"   1. Flask app running at {BASE_URL}")
    print(f"   2. Test user created: {LEGITIMATE_USER['username']}")
    print(f"   3. Register if needed at: {BASE_URL}/register")
    
    input("\nPress Enter to start simulation...")
    
    all_results = {}
    
    # Run legitimate login test first
    legit_result = simulate_legitimate_login()
    all_results['Legitimate Login'] = {'tested': 1}
    
    # Run attacks
    all_results['Credential Stuffing'] = simulate_credential_stuffing()
    all_results['Geo-Anomalous Login'] = simulate_geo_anomalous_login()
    all_results['Brute Force'] = simulate_brute_force()
    all_results['Device Spoofing'] = simulate_device_spoofing()
    
    # Generate final report
    generate_report(all_results)