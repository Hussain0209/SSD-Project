# Troubleshooting Guide - OTP Authentication System

## Problem: Backend URL Not Responding

### Step 1: Verify Backend is Running
```bash
# Terminal 1: Start Flask backend
cd "d:\University\Semester 7\SSD\Project"
python app.py
```

You should see output like:
```
============================================================
OTP Authentication System - Backend Server
============================================================
✓ Flask app configured successfully
✓ CORS enabled for frontend communication
✓ Email configured: your_email@gmail.com

📍 Server URL: http://localhost:5000
📍 Frontend URL: http://localhost:8000
...
```

### Step 2: Test if Backend is Responding
Open your browser and visit:
```
http://localhost:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "message": "OTP Authentication Backend is running",
  "timestamp": "2025-11-22T..."
}
```

If this doesn't work, check:

### Step 3: Check for Common Issues

#### Issue A: Port 5000 Already in Use
**Error**: `Address already in use`

**Solution**:
```powershell
# Find process using port 5000
netstat -ano | findstr :5000

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F

# Or use a different port
# Edit app.py line: app.run(..., port=5001)
```

#### Issue B: Flask-Mail Configuration Error
**Error**: `Error sending email` or `Connection refused`

**Solution**:
1. Check Gmail credentials in `app.py` lines 16-19:
   ```python
   app.config['MAIL_USERNAME'] = 'your_actual_email@gmail.com'
   app.config['MAIL_PASSWORD'] = 'your_16_char_app_password'
   ```

2. Test email configuration:
   ```
   http://localhost:5000/test-email
   ```

3. If test fails, verify:
   - 2FA is enabled on Google account
   - App Password was generated (not regular password)
   - App Password is exactly 16 characters with spaces

#### Issue C: Module Not Found Error
**Error**: `ModuleNotFoundError: No module named 'flask_mail'`

**Solution**:
```powershell
# Install missing dependencies
pip install flask flask-mail flask-cors

# Or reinstall all dependencies
pip install -r requirements.txt
```

#### Issue D: CORS Error (Frontend Can't Connect)
**Error**: `No 'Access-Control-Allow-Origin' header`

**Solution**: This is already fixed in the updated app.py. The CORS is properly configured:
```python
CORS(app, supports_credentials=True)
```

#### Issue E: Frontend Not Connecting to Backend
**Error**: Network tab shows failed request to `http://localhost:5000`

**Checklist**:
- [ ] Backend is running on port 5000
- [ ] Frontend is running on port 8000
- [ ] Both are on `localhost` (not `127.0.0.1`)
- [ ] No firewall blocking ports 5000/8000
- [ ] Check browser console (F12) for detailed error

## Startup Checklist

Before running the application:

1. **Configure Gmail Credentials**
   ```python
   # app.py lines 16-19
   app.config['MAIL_USERNAME'] = 'your.email@gmail.com'
   app.config['MAIL_PASSWORD'] = 'xxxx xxxx xxxx xxxx'
   app.config['MAIL_DEFAULT_SENDER'] = 'your.email@gmail.com'
   ```

2. **Check Virtual Environment**
   ```powershell
   # Activate venv
   .venv\Scripts\Activate.ps1
   
   # Check Flask is installed
   pip list | grep -i flask
   ```

3. **Start Backend**
   ```powershell
   python app.py
   ```
   Should see the startup banner with ✓ marks

4. **Start Frontend** (in another terminal)
   ```powershell
   python -m http.server 8000
   ```

5. **Test Health Endpoint**
   ```
   http://localhost:5000/health
   ```

6. **Test Email Configuration**
   ```
   http://localhost:5000/test-email
   ```

7. **Open Frontend**
   ```
   http://localhost:8000
   ```

## Debug Mode

If you encounter issues, enable verbose logging:

```python
# app.py
import logging
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)
```

Then restart the backend and check the console output for detailed error messages.

## Port Numbers Reference

| Service | Port | URL |
|---------|------|-----|
| Flask Backend | 5000 | http://localhost:5000 |
| HTTP Frontend Server | 8000 | http://localhost:8000 |

## Quick Restart

If something is wrong, restart everything:

```powershell
# Terminal 1: Kill Flask (Ctrl+C)
# Terminal 2: Kill HTTP server (Ctrl+C)

# Check ports are free
netstat -ano | findstr :5000
netstat -ano | findstr :8000

# Restart Flask backend
python app.py

# Restart Frontend server (in another terminal)
python -m http.server 8000
```

## Getting Help

If you still have issues:

1. Check the exact error message
2. Take a screenshot of the error
3. Check Flask console output (not browser)
4. Run `/health` endpoint to verify backend
5. Check browser console (F12 → Console tab)
6. Verify ports 5000 and 8000 are free

