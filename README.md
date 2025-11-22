# OTP Authentication System

A secure One-Time Password (OTP) authentication system built with Flask backend and modern frontend.

## Features

- **Secure OTP Generation**: Cryptographically secure 6-digit OTP
- **Email Verification**: Send OTP via email (Gmail/Outlook/Yahoo)
- **Rate Limiting**: 5 requests per 15 minutes
- **Account Lockout**: 15-minute lockout after 3 failed attempts
- **OTP Expiry**: 3-minute expiration for each OTP
- **Single-Use OTP**: Each OTP can only be used once
- **Session Management**: Secure session handling with HTTPS/TLS support
- **Responsive UI**: Mobile-friendly authentication interface

## Project Structure

```
.
├── app.py              # Flask backend with OTP logic
├── index.html          # Frontend authentication page
├── script.js           # Frontend JavaScript logic
├── styles.css          # Frontend styling
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## Requirements

- Python 3.7+
- Flask
- Flask-Mail
- Flask-CORS
- cryptography
- pyopenssl

## Installation

1. **Clone the repository**:
```bash
git clone <your-repo-url>
cd "Semester 7\SSD\Project"
```

2. **Create virtual environment**:
```bash
python -m venv .venv
.venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install flask flask-mail flask-cors cryptography pyopenssl
```

## Configuration

### Email Setup (Gmail Example)

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Update `app.py` lines 18-20:

```python
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_16_char_app_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'
```

### Other Email Providers

- **Outlook**: `smtp.outlook.com` (port 587)
- **Yahoo**: `smtp.mail.yahoo.com` (port 587)

## Running the Application

### Backend (Flask Server)

```bash
cd "d:\University\Semester 7\SSD\Project"
python app.py
```

Server runs on: `http://localhost:5000`

### Frontend (HTTP Server)

```bash
cd "d:\University\Semester 7\SSD\Project"
python -m http.server 8000
```

Open in browser: `http://localhost:8000`

## API Endpoints

### POST `/request-otp`
Request OTP for email address

**Request**:
```json
{
  "email": "user@example.com"
}
```

**Response**:
```json
{
  "message": "OTP sent successfully"
}
```

### POST `/verify-otp`
Verify OTP and authenticate user

**Request**:
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response**:
```json
{
  "message": "Authentication successful",
  "token": "secure_token_here"
}
```

## Security Features

- ✅ Hash-based OTP storage (SHA-256)
- ✅ Cryptographically secure random generation
- ✅ Rate limiting and brute-force protection
- ✅ Account lockout mechanism
- ✅ CORS enabled for secure frontend-backend communication
- ✅ Session management with secure cookies
- ✅ HTTPS/TLS support

## Testing

1. Navigate to `http://localhost:8000`
2. Enter an email address
3. Click "Request OTP"
4. Check your email for the OTP code
5. Enter the OTP on the verification screen
6. Upon successful verification, you'll receive an authentication token

**Test Mode**: If email configuration fails, OTP will be printed to Flask console for testing.

## License

This project is part of a university semester project.

## Author

Created for SSD (Software Security Design) Semester 7 Project
