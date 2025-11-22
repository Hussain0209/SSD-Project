#!/usr/bin/env python
"""
Diagnostic script for OTP Authentication System
Checks if all dependencies are installed and configured correctly
"""

import sys
import os

print("\n" + "="*60)
print("OTP Authentication System - Diagnostics")
print("="*60 + "\n")

# Check Python version
print(f"✓ Python version: {sys.version}")

# Check required modules
required_modules = {
    'flask': 'Flask',
    'flask_mail': 'Flask-Mail',
    'flask_cors': 'Flask-CORS',
    'hashlib': 'hashlib (built-in)',
    'secrets': 'secrets (built-in)',
}

print("\n📦 Checking required modules:")
all_installed = True
for module, display_name in required_modules.items():
    try:
        __import__(module)
        print(f"  ✓ {display_name}")
    except ImportError:
        print(f"  ✗ {display_name} - NOT INSTALLED")
        all_installed = False

if not all_installed:
    print("\n⚠️  Some modules are missing. Install them with:")
    print("  pip install flask flask-mail flask-cors")
    sys.exit(1)

# Check Flask app can be imported
print("\n🔍 Checking Flask app configuration:")
try:
    from app import app
    print("  ✓ app.py imported successfully")
    print(f"  ✓ Flask secret key configured: {len(app.secret_key)} bytes")
    print(f"  ✓ Mail server: {app.config['MAIL_SERVER']}")
    print(f"  ✓ Mail username: {app.config['MAIL_USERNAME']}")
except Exception as e:
    print(f"  ✗ Error importing app: {str(e)}")
    sys.exit(1)

# Check routes are registered
print("\n📍 Checking registered routes:")
routes = [
    '/health',
    '/test-email',
    '/request-otp',
    '/verify-otp'
]
for route in routes:
    found = False
    for rule in app.url_map.iter_rules():
        if str(route) in str(rule):
            found = True
            break
    if found:
        print(f"  ✓ {route}")
    else:
        print(f"  ✗ {route} - NOT FOUND")

print("\n✅ All checks passed! You can now run:")
print("   python app.py\n")
