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
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Change this
app.config['MAIL_PASSWORD'] = 'your_app_password'      # Use App Password, not regular password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'

mail = Mail(app) 

# In-memory storage (Replace with MySQL/PostgreSQL for production )
users_db = {}  # {email: {otp_hash, expiry, attempts, locked_until, request_count, window_start}}

# CONFIGURATION based on NFRs and SRs
OTP_EXPIRY_SECONDS = 180      # 3 minutes 
MAX_ATTEMPTS = 3              # 3 failed attempts 
LOCKOUT_DURATION = 15         # 15 minutes 
RATE_LIMIT_COUNT = 5          # 5 requests 
RATE_LIMIT_WINDOW = 15        # 15 minutes 

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({"error": "Email required"}), 400

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
        return jsonify({"error": "Account locked. Try again later."}), 403

    # CHECK: Rate Limiting (5 requests per 15 mins) 
    if now - user['window_start'] > timedelta(minutes=RATE_LIMIT_WINDOW):
        user['request_count'] = 0
        user['window_start'] = now
    
    if user['request_count'] >= RATE_LIMIT_COUNT:
        return jsonify({"error": "Rate limit exceeded."}), 429

    # GENERATE: Cryptographically secure OTP 
    otp = ''.join([secrets.choice('0123456789') for _ in range(6)])
    otp_hash = hashlib.sha256(otp.encode()).hexdigest() # Store hash only 

    # UPDATE STATE
    user['otp_hash'] = otp_hash
    user['expiry'] = now + timedelta(seconds=OTP_EXPIRY_SECONDS)
    user['attempts'] = 0  # Reset validation attempts on new OTP
    user['request_count'] += 1

    # SEND EMAIL WITH OTP [cite: 608]
    # TEST MODE: Comment out mail.send() to use console OTP instead
    try:
        msg = Message(
            subject='Your OTP Verification Code',
            recipients=[email],
            html=f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f3f4f6; padding: 20px;">
                    <div style="max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #1f2937; text-align: center;">Verify Your Identity</h2>
                        <p style="color: #6b7280; font-size: 14px;">Hi,</p>
                        <p style="color: #6b7280;">Your one-time password (OTP) for authentication is:</p>
                        <div style="background-color: #f0f9ff; border: 2px solid #2563eb; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                            <p style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #2563eb; margin: 0;">{otp}</p>
                        </div>
                        <p style="color: #ef4444; font-weight: bold;">⏰ This code expires in 3 minutes.</p>
                        <p style="color: #6b7280; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                        <p style="color: #9ca3af; font-size: 12px; text-align: center;">Do not share this code with anyone.</p>
                    </div>
                </body>
            </html>
            """
        )
        mail.send(msg)
        print(f"✓ Email sent successfully to {email}")
    except Exception as e:
        # If email fails (e.g., invalid credentials), log to console for testing
        print(f"⚠ Email send failed: {str(e)}")
        print(f"📌 TEST MODE: Use OTP from console: {otp}")
    
    # Log OTP for debugging (remove in production)
    print(f"DEBUG: OTP for {email} is {otp}")
    return jsonify({"message": "OTP sent successfully"})

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
    app.run(debug=True, host='localhost', port=5000) # Development mode