# Fix SQLAlchemy Python 3.13 Compatibility Issue

## Quick Fix

You're using Python 3.13.9, which requires SQLAlchemy 2.0.31 or higher. Here's how to fix it:

### Option 1: Use Virtual Environment (Recommended)

1. **Create/Activate Virtual Environment:**
   ```bash
   cd /home/decipher/Desktop/ThreatScanner/phishing_line
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install/Upgrade Dependencies:**
   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. **Run the Server:**
   ```bash
   python3 run_server.py
   ```

### Option 2: Use System Packages (if you have permissions)

If you need to use system packages:
```bash
cd /home/decipher/Desktop/ThreatScanner/phishing_line
pip install --upgrade SQLAlchemy --break-system-packages
python3 run_server.py
```

### Option 3: Use Existing Virtual Environment

If you have an existing venv at `/home/decipher/phishing_line/venv`:
```bash
source /home/decipher/phishing_line/venv/bin/activate
cd /home/decipher/Desktop/ThreatScanner/phishing_line
pip install -r requirements.txt --upgrade
python3 run_server.py
```

## Verify SQLAlchemy Version

After upgrading, verify the version:
```bash
python3 -c "import sqlalchemy; print(f'SQLAlchemy version: {sqlalchemy.__version__}')"
```

You should see version 2.0.31 or higher.

## Run the Server

Once SQLAlchemy is upgraded, run from the `phishing_line` directory (NOT from inside `backend/`):

```bash
cd /home/decipher/Desktop/ThreatScanner/phishing_line
python3 run_server.py
```

Or:
```bash
python3 backend/main.py
```

## What Was Fixed

1. **Updated requirements.txt** - Changed SQLAlchemy from `2.0.21` to `>=2.0.31` for Python 3.13 compatibility
2. **Fixed main.py imports** - Improved import handling to work when run from parent directory
3. **Created documentation** - Added START_SERVER.md with proper instructions
