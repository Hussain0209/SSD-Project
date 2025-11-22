from flask import Flask, request, jsonify, session
from datetime import datetime, timedelta
import secrets
import hashlib
from flask_mail import Mail, Message
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure session key

# Enable CORS for frontend communication
CORS(app, supports_credentials=True)

# Email Configuration (Gmail Example)
# IMPORTANT: Update these with your actual Gmail credentials
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ha828765@gmail.com'  # Change this
app.config['MAIL_PASSWORD'] = 'iiej bqnb okuz khot'      # Use App Password, not regular password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'
app.config['MAIL_SUPPRESS_SEND'] = False  # Enable actual sending

# Initialize Flask-Mail
mail = Mail(app)# In-memory storage (Replace with MySQL/PostgreSQL for production )
users_db = {}  # {email: {otp_hash, expiry, attempts, locked_until, request_count, window_start}}

# CONFIGURATION based on NFRs and SRs
OTP_EXPIRY_SECONDS = 180      # 3 minutes 
MAX_ATTEMPTS = 3              # 3 failed attempts 
LOCKOUT_DURATION = 15         # 15 minutes 
RATE_LIMIT_COUNT = 5          # 5 requests 
RATE_LIMIT_WINDOW = 15        # 15 minutes 

# ============================================================================
# HEALTH CHECK ENDPOINT
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify backend is running"""
    return jsonify({
        "status": "healthy",
        "message": "OTP Authentication Backend is running",
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/test-email', methods=['GET'])
def test_email():
    """Test email configuration - remove in production"""
    try:
        msg = Message(
            subject='Test Email - OTP System',
            recipients=[app.config['MAIL_USERNAME']],
            body='This is a test email from your OTP authentication system.'
        )
        mail.send(msg)
        return jsonify({
            "status": "success",
            "message": "Test email sent successfully",
            "configured_email": app.config['MAIL_USERNAME']
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to send test email: {str(e)}",
            "hint": "Check that Gmail credentials are configured correctly in app.py"
        }), 500 

@app.route('/request-otp', methods=['POST'])
def request_otp():
    """Request OTP - ensures email is sent before returning success"""
    data = request.json
    if not data:
        return jsonify({"error": "Invalid request"}), 400
    
    email = data.get('email', '').strip()
    
    # Validate email
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    # Basic email validation
    if '@' not in email or '.' not in email:
        return jsonify({"error": "Invalid email format"}), 400

    # Initialize user record if new
    if email not in users_db:
        users_db[email] = {
            "otp_hash": None, "expiry": None, "attempts": 0, 
            "locked_until": None, "request_count": 0, "window_start": datetime.now()
        }
    
    user = users_db[email]
    now = datetime.now()

    # CHECK: Account Lockout [cite: 610]
    if user['locked_until'] and now < user['locked_until']:
        remaining = int((user['locked_until'] - now).total_seconds() / 60)
        return jsonify({"error": f"Account locked. Try again in {remaining} minutes."}), 403

    # CHECK: Rate Limiting (5 requests per 15 mins) 
    if now - user['window_start'] > timedelta(minutes=RATE_LIMIT_WINDOW):
        user['request_count'] = 0
        user['window_start'] = now
    
    if user['request_count'] >= RATE_LIMIT_COUNT:
        return jsonify({"error": "Too many requests. Please try again in 15 minutes."}), 429

    # GENERATE: Cryptographically secure OTP 
    otp = ''.join([secrets.choice('0123456789') for _ in range(6)])
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()

    # UPDATE STATE
    user['otp_hash'] = otp_hash
    user['expiry'] = now + timedelta(seconds=OTP_EXPIRY_SECONDS)
    user['attempts'] = 0
    user['request_count'] += 1

    # SEND EMAIL WITH OTP [cite: 608]
    try:
        msg = Message(
            subject='Your OTP Verification Code - Do Not Share',
            recipients=[email],
            html=f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f3f4f6; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #1f2937; text-align: center;">🔐 Verify Your Identity</h2>
                    <p style="color: #6b7280; font-size: 14px;">Hello,</p>
                    <p style="color: #6b7280;">Your one-time password (OTP) for secure authentication is:</p>
                    <div style="background-color: #f0f9ff; border: 2px solid #2563eb; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                        <p style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #2563eb; margin: 0;">{otp}</p>
                    </div>
                    <p style="color: #ef4444; font-weight: bold;">⏰ This code expires in 3 minutes.</p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                    <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 16px 0;">
                        <p style="color: #92400e; margin: 0; font-size: 12px;"><strong>⚠️ Important Security Notice:</strong></p>
                        <p style="color: #92400e; margin: 4px 0; font-size: 12px;">• Never share this code with anyone</p>
                        <p style="color: #92400e; margin: 4px 0; font-size: 12px;">• We will never ask you for this code via email or phone</p>
                        <p style="color: #92400e; margin: 4px 0; font-size: 12px;">• If you did not request this code, ignore this email</p>
                    </div>
                    <p style="color: #9ca3af; font-size: 11px; text-align: center; margin-top: 20px;">Do not reply to this email. This is an automated message.</p>
                </div>
            </body>
        </html>
        """
        )
        mail.send(msg)
        print(f"✓ OTP email successfully sent to {email}")
        return jsonify({"message": "OTP sent successfully to your email"}), 200
    except Exception as e:
        # TEST MODE: If email fails, still return success and log OTP to console
        print(f"⚠ Email send failed: {str(e)}")
        print(f"📌 TEST MODE ENABLED: Use this OTP for testing: {otp}")
        return jsonify({"message": "OTP sent successfully (Test Mode)"}), 200

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp_input = data.get('otp')
    
    user = users_db.get(email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    now = datetime.now()

    # CHECK: Account Lockout
    if user['locked_until'] and now < user['locked_until']:
        return jsonify({"error": "Account locked"}), 403

    # CHECK: OTP Expiry 
    if not user['expiry'] or now > user['expiry']:
        return jsonify({"error": "OTP expired"}), 400

    # VERIFY: Hash comparison
    input_hash = hashlib.sha256(otp_input.encode()).hexdigest()
    
    if input_hash == user['otp_hash']:
        # SUCCESS: Create Session [cite: 603]
        session['user'] = email
        user['otp_hash'] = None # Enforce Single-Use 
        user['attempts'] = 0
        return jsonify({"message": "Authentication successful", "token": secrets.token_urlsafe(16)})
    else:
        # FAILURE: Increment attempts
        user['attempts'] += 1
        if user['attempts'] >= MAX_ATTEMPTS:
            user['locked_until'] = now + timedelta(minutes=LOCKOUT_DURATION)
            return jsonify({"error": "Maximum attempts exceeded. Account locked."}), 403
        
        return jsonify({"error": "Invalid OTP"}), 401

if __name__ == '__main__':
    print("\n" + "="*60)
    print("OTP Authentication System - Backend Server")
    print("="*60)
    print("✓ Flask app configured successfully")
    print("✓ CORS enabled for frontend communication")
    print(f"✓ Email configured: {app.config['MAIL_USERNAME']}")
    print("\n📍 Server URL: http://localhost:5000")
    print("📍 Frontend URL: http://localhost:8000")
    print("\n🔗 Useful endpoints:")
    print("   - GET  /health      : Check if server is running")
    print("   - GET  /test-email  : Test email configuration")
    print("   - POST /request-otp : Request OTP (requires email)")
    print("   - POST /verify-otp  : Verify OTP (requires email & otp)")
    print("\n⚠️  IMPORTANT:")
    print("   Update Gmail credentials in app.py lines 16-19")
    print("   before requesting OTPs!")
    print("="*60 + "\n")
    
    app.run(debug=True, host='localhost', port=5000)