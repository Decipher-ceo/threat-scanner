# How to Start the Backend Server

## Prerequisites

1. **Install/Update Dependencies**
   ```bash
   cd /home/decipher/Desktop/ThreatScanner/phishing_line
   pip install -r requirements.txt --upgrade
   ```

   This will update SQLAlchemy to a version compatible with Python 3.13.

2. **Initialize Database** (if not already done)
   ```bash
   python3 -m backend.init_db
   ```

## Starting the Server

### Option 1: Using run_server.py (Recommended)
From the `phishing_line` directory:
```bash
cd /home/decipher/Desktop/ThreatScanner/phishing_line
python3 run_server.py
```

### Option 2: Using main.py from parent directory
From the `phishing_line` directory:
```bash
cd /home/decipher/Desktop/ThreatScanner/phishing_line
python3 backend/main.py
```

### Option 3: Using Python module syntax
From the `phishing_line` directory:
```bash
cd /home/decipher/Desktop/ThreatScanner/phishing_line
python3 -m backend.main
```

### Option 4: Directly from app.py
From the `phishing_line` directory:
```bash
cd /home/decipher/Desktop/ThreatScanner/phishing_line
python3 -m backend.app
```

## ⚠️ Important Notes

- **DO NOT** run `main.py` from inside the `backend` directory directly
- Always run from the `phishing_line` parent directory
- The server will start on `http://0.0.0.0:5000`
- Access the dashboard at `http://127.0.0.1:5000`
- API endpoints are at `http://127.0.0.1:5000/api`

## Troubleshooting

### SQLAlchemy Python 3.13 Compatibility Error
If you see an error about SQLAlchemy and Python 3.13:
```bash
pip install --upgrade SQLAlchemy
```
This will install the latest version (2.0.31+) which supports Python 3.13.

### Import Errors
Make sure you're running from the `phishing_line` directory, not from inside `backend/`.

### Database Errors
If you see database-related errors, initialize the database:
```bash
python3 -m backend.init_db
```
