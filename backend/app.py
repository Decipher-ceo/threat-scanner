from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from .core_engine.url_checker import analyze_url
from .core_engine.email_checker import analyze_email
from .core_engine.sms_checker import analyze_sms
from .models import User, Base, ScanLog
from .db import SessionLocal, engine
from .auth_utils import generate_token, get_current_user_from_token, require_auth
from datetime import datetime, timedelta
from collections import defaultdict
import os
import re

app = Flask(__name__)
CORS(app)

# Initialize database tables
Base.metadata.create_all(bind=engine)

# ===== GLOBAL STATS TRACKING =====
scan_stats = {
    "email": {"total": 0, "safe": 0, "suspicious": 0, "phishing": 0, "latest": []},
    "sms": {"total": 0, "safe": 0, "suspicious": 0, "phishing": 0, "latest": []},
    "url": {"total": 0, "safe": 0, "suspicious": 0, "phishing": 0, "latest": []},
    "pie": {"phishing": 0, "suspicious": 0, "safe": 0}
}

# ===== DAILY STATS TRACKING =====
# Structure: daily_stats[date_str][scan_type] = {"safe": count, "phishing": count}
daily_stats = defaultdict(lambda: defaultdict(lambda: {"safe": 0, "phishing": 0}))

def update_stats(scan_type: str, verdict: str, input_value: str, summary: str = "", metadata: dict = None):
    """Update statistics after a scan and persist to database"""
    if scan_type not in scan_stats:
        return
    
    scan_stats[scan_type]["total"] += 1
    
    verdict_lower = verdict.lower()
    today = datetime.now().date().isoformat()
    
    if verdict_lower == "phishing":
        scan_stats[scan_type]["phishing"] += 1
        scan_stats["pie"]["phishing"] += 1
        daily_stats[today][scan_type]["phishing"] += 1
    elif verdict_lower == "suspicious":
        scan_stats[scan_type]["suspicious"] += 1
        scan_stats["pie"]["suspicious"] += 1
        daily_stats[today][scan_type]["safe"] += 1
    else:
        scan_stats[scan_type]["safe"] += 1
        scan_stats["pie"]["safe"] += 1
        daily_stats[today][scan_type]["safe"] += 1
    
    # Create scan log in database
    db = SessionLocal()
    try:
        import json
        log_entry = ScanLog(
            scan_type=scan_type.upper(),
            input_value=input_value,
            result=json.dumps({
                "verdict": verdict,
                "summary": summary,
                "timestamp": datetime.now().isoformat(),
                "details": metadata or {}
            }),
            created_at=datetime.utcnow()
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        print(f"Error saving scan log: {e}")
        db.rollback()
    finally:
        db.close()

    # Add to latest (keep last 10)
    scan_stats[scan_type]["latest"].insert(0, {
        "type": scan_type.upper(),
        "summary": summary or input_value[:50],
        "verdict": verdict,
        "timestamp": datetime.now().isoformat()
    })
    scan_stats[scan_type]["latest"] = scan_stats[scan_type]["latest"][:10]

# Helper function to convert verdict to status format (for backward compatibility)
def verdict_to_status(verdict: str) -> str:
    """Convert lowercase verdict to uppercase status"""
    verdict_map = {
        "phishing": "PHISHING",
        "suspicious": "SUSPICIOUS",
        "safe": "SAFE"
    }
    return verdict_map.get(verdict.lower(), "SAFE")


# -----------------------------
# AUTHENTICATION ENDPOINTS
# -----------------------------

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")

        # Validation
        if not username or not email or not password:
            return jsonify({"error": "All fields are required"}), 400

        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), 400

        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400

        db = SessionLocal()
        try:
            # Check if username already exists
            if db.query(User).filter(User.username == username).first():
                return jsonify({"error": "Username already exists"}), 400

            # Check if email already exists
            if db.query(User).filter(User.email == email).first():
                return jsonify({"error": "Email already registered"}), 400

            # Create new user
            new_user = User(
                username=username,
                email=email
            )
            new_user.set_password(password)
            db.add(new_user)
            db.commit()
            db.refresh(new_user)

            # Generate token
            token = generate_token(
                new_user.id,
                new_user.username,
                new_user.email,
                new_user.is_admin
            )

            return jsonify({
                "message": "User registered successfully",
                "token": token,
                "user": new_user.to_dict()
            }), 201
        finally:
            db.close()
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    """Login user and return JWT token"""
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        db = SessionLocal()
        try:
            # Find user by username or email
            user = db.query(User).filter(
                (User.username == username) | (User.email == username)
            ).first()

            if not user or not user.check_password(password):
                return jsonify({"error": "Invalid username or password"}), 401

            # Generate token
            token = generate_token(
                user.id,
                user.username,
                user.email,
                user.is_admin
            )

            return jsonify({
                "message": "Login successful",
                "token": token,
                "user": user.to_dict()
            }), 200
        finally:
            db.close()
    except Exception as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def get_current_user(current_user):
    """Get current authenticated user information"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"user": user.to_dict()}), 200
    finally:
        db.close()

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    """Logout endpoint (client-side token removal)"""
    return jsonify({"message": "Logged out successfully"}), 200

@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def change_password(current_user):
    """Change user password"""
    try:
        data = request.get_json()
        old_password = data.get("old_password", "")
        new_password = data.get("new_password", "")

        if not old_password or not new_password:
            return jsonify({"error": "Both old and new passwords are required"}), 400

        if len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters long"}), 400

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == current_user["user_id"]).first()
            if not user:
                return jsonify({"error": "User not found"}), 404

            # Verify old password
            if not user.check_password(old_password):
                return jsonify({"error": "Current password is incorrect"}), 401

            # Update password
            user.set_password(new_password)
            db.commit()

            return jsonify({"message": "Password changed successfully"}), 200
        finally:
            db.close()
    except Exception as e:
        return jsonify({"error": f"Password change failed: {str(e)}"}), 500


# -----------------------------
# URL SCANNER
# -----------------------------
@app.route("/scan-url", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url", "")

    if not url:
        return jsonify({
            "status": "SAFE",
            "score": 0,
            "domain": "",
            "reasons": ["No URL provided"]
        })

    # Use the comprehensive URL checker
    result = analyze_url(url)

    # Extract domain for backward compatibility
    domain = result.get("parsed", {}).get("root_domain", "")
    verdict = result.get("verdict", "safe")
    
    # Update stats
    summary = f"{domain} — {verdict}" if domain else f"{url[:30]}... — {verdict}"
    update_stats("url", verdict, url, summary, result)

    return jsonify({
        "status": verdict_to_status(verdict),
        "score": result.get("score", 0),
        "domain": domain,
        "reasons": result.get("reasons", []),
        "is_phishy": result.get("verdict") == "phishing",
        "indicators": result.get("indicators", {})
    })


# -----------------------------
# EMAIL SCANNER
# -----------------------------
@app.route("/scan-email", methods=["POST"])
def scan_email():
    data = request.get_json()
    sender = data.get("sender", "")
    subject = data.get("subject", "")
    content = data.get("content", "")
    attachments = data.get("attachments", [])

    # Use the comprehensive email checker
    result = analyze_email(
        sender=sender,
        subject=subject,
        content=content,
        attachments=attachments
    )
    
    verdict = result.get("verdict", "safe")
    sender_addr = result.get("sender", "")
    
    # Update stats
    summary = f"{sender_addr} — {verdict}" if sender_addr else f"Email — {verdict}"
    update_stats("email", verdict, sender_addr or "unknown", summary, result)

    return jsonify({
        "status": verdict_to_status(verdict),
        "score": result.get("score", 0),
        "reasons": result.get("reasons", []),
        "sender": sender_addr,
        "subject": result.get("subject", ""),
        "indicators": result.get("indicators", {}),
        "links_found": result.get("links_found", []),
        "attachments_found": result.get("attachments_found", [])
    })


# -----------------------------
# SMS SCANNER
# -----------------------------
@app.route("/scan-sms", methods=["POST"])
def scan_sms():
    data = request.get_json()
    sender = data.get("sender", "")
    number = data.get("number", "")
    content = data.get("content", "")

    # Use the comprehensive SMS checker
    result = analyze_sms(
        sender=sender,
        number=number,
        content=content
    )
    
    verdict = result.get("verdict", "safe")
    sms_number = result.get("number", "")
    
    # Update stats
    summary = f"{sms_number} — {verdict}" if sms_number else f"{sender} — {verdict}"
    update_stats("sms", verdict, sms_number or sender or "unknown", summary, result)

    return jsonify({
        "status": verdict_to_status(verdict),
        "score": result.get("score", 0),
        "reasons": result.get("reasons", []),
        "sender": result.get("sender", ""),
        "number": sms_number,
        "indicators": result.get("indicators", {}),
        "links_found": result.get("links_found", [])
    })


# -----------------------------
# DASHBOARD STATS API
# -----------------------------
@app.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Get dashboard statistics"""
    def calculate_safe_percent(stats):
        total = stats["total"]
        if total == 0:
            return 100
        safe = stats["safe"]
        return int((safe / total) * 100)
    
    def get_risk_level(stats):
        total = stats["total"]
        if total == 0:
            return "Low", "var(--good)"
        phishing_ratio = stats["phishing"] / total
        if phishing_ratio > 0.3:
            return "Critical", "var(--danger)"
        elif phishing_ratio > 0.15:
            return "High", "var(--warn)"
        else:
            return "Low", "var(--good)"
    
    # Get latest incidents from all types
    all_latest = []
    for scan_type in ["email", "sms", "url"]:
        all_latest.extend(scan_stats[scan_type]["latest"][:3])
    
    # Sort by timestamp (most recent first)
    all_latest.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_latest = all_latest[:5]
    
    # Format latest incidents
    formatted_latest = []
    for item in all_latest:
        verdict = item.get("verdict", "safe").lower()
        if verdict == "phishing":
            status = "critical"
        elif verdict == "suspicious":
            status = "low-risk"
        else:
            status = "safe"
        formatted_latest.append({
            "type": item.get("type", "Unknown"),
            "summary": item.get("summary", "") + f" — {status}"
        })
    
    email_risk, email_color = get_risk_level(scan_stats["email"])
    sms_risk, sms_color = get_risk_level(scan_stats["sms"])
    url_risk, url_color = get_risk_level(scan_stats["url"])
    
    return jsonify({
        "email": {
            "safe_percent": calculate_safe_percent(scan_stats["email"]),
            "total": scan_stats["email"]["total"],
            "risk": email_risk,
            "risk_color": email_color,
            "latest": scan_stats["email"]["latest"][0].get("summary", "No scans yet") if scan_stats["email"]["latest"] else "No scans yet"
        },
        "sms": {
            "safe_percent": calculate_safe_percent(scan_stats["sms"]),
            "total": scan_stats["sms"]["total"],
            "risk": sms_risk,
            "risk_color": sms_color,
            "latest": scan_stats["sms"]["latest"][0].get("summary", "No scans yet") if scan_stats["sms"]["latest"] else "No scans yet"
        },
        "url": {
            "safe_percent": calculate_safe_percent(scan_stats["url"]),
            "total": scan_stats["url"]["total"],
            "risk": url_risk,
            "risk_color": url_color,
            "latest": scan_stats["url"]["latest"][0].get("summary", "No scans yet") if scan_stats["url"]["latest"] else "No scans yet"
        },
        "latest": formatted_latest
    })

# -----------------------------
# REPORTS API
# -----------------------------
@app.route("/api/reports", methods=["GET"])
def get_reports():
    """Fetch reports with filtering"""
    filter_input = request.args.get("filter", "").strip()
    
    db = SessionLocal()
    try:
        query = db.query(ScanLog)
        
        if filter_input:
            # Check for range "YYYY-MM-DD - YYYY-MM-DD"
            if " - " in filter_input:
                parts = filter_input.split(" - ")
                if len(parts) == 2:
                    try:
                        start_date = datetime.strptime(parts[0].strip(), "%Y-%m-%d")
                        end_date = datetime.strptime(parts[1].strip(), "%Y-%m-%d") + timedelta(days=1)
                        query = query.filter(ScanLog.created_at >= start_date, ScanLog.created_at < end_date)
                    except ValueError:
                        pass
            else:
                # Single date YYYY-MM-DD
                try:
                    target_date = datetime.strptime(filter_input, "%Y-%m-%d")
                    next_day = target_date + timedelta(days=1)
                    query = query.filter(ScanLog.created_at >= target_date, ScanLog.created_at < next_day)
                except ValueError:
                    # Not a date, maybe search in input_value or scan_type
                    query = query.filter(
                        (ScanLog.input_value.ilike(f"%{filter_input}%")) | 
                        (ScanLog.scan_type.ilike(f"%{filter_input}%"))
                    )
        else:
            # Default: Last 7 days
            week_ago = datetime.utcnow() - timedelta(days=7)
            query = query.filter(ScanLog.created_at >= week_ago)

        logs = query.order_by(ScanLog.created_at.desc()).all()
        
        results = []
        import json
        for log in logs:
            try:
                data = json.loads(log.result)
            except:
                data = {"verdict": "unknown", "summary": "No data"}
                
            results.append({
                "id": log.id,
                "type": log.scan_type,
                "input": log.input_value,
                "verdict": data.get("verdict", "unknown"),
                "summary": data.get("summary", ""),
                "date": log.created_at.strftime("%Y-%m-%d"),
                "timestamp": log.created_at.isoformat(),
                "details": data.get("details", {})
            })
            
        return jsonify(results)
    finally:
        db.close()

# -----------------------------
# PIE CHART STATS API
# -----------------------------
@app.route("/stats/pie", methods=["GET"])
def pie_stats():
    """Get pie chart statistics"""
    return jsonify(scan_stats["pie"])


# -----------------------------
# BAR CHART STATS API
# -----------------------------
@app.route("/stats/bar", methods=["GET"])
def bar_stats():
    """Get bar chart statistics with filters"""
    department = request.args.get("department", "all").lower()
    period = request.args.get("period", "daily").lower()
    
    # Calculate date range based on period
    today = datetime.now().date()
    date_ranges = {
        "daily": 7,      # Last 7 days
        "weekly": 4,     # Last 4 weeks
        "monthly": 6,    # Last 6 months
        "3months": 3,   # Last 3 months
        "6months": 6    # Last 6 months
    }
    
    days_back = date_ranges.get(period, 7)
    
    # Generate date list based on period
    data_points = []
    if period == "daily":
        # Daily data for last 7 days
        for i in range(days_back - 1, -1, -1):
            date = today - timedelta(days=i)
            date_str = date.isoformat()
            data_points.append({
                "date": date_str,
                "label": date.strftime("%a"),  # Mon, Tue, etc.
                "full_label": date.strftime("%b %d")  # Jan 15
            })
    elif period == "weekly":
        # Weekly data for last 4 weeks
        for i in range(days_back - 1, -1, -1):
            week_start = today - timedelta(days=i * 7)
            week_end = week_start + timedelta(days=6)
            data_points.append({
                "date": week_start.isoformat(),
                "label": f"W{i+1}",
                "full_label": f"{week_start.strftime('%b %d')} - {week_end.strftime('%b %d')}"
            })
    elif period in ["monthly", "3months", "6months"]:
        # Monthly data
        for i in range(days_back - 1, -1, -1):
            month_date = today - timedelta(days=i * 30)
            data_points.append({
                "date": month_date.isoformat(),
                "label": month_date.strftime("%b"),
                "full_label": month_date.strftime("%B %Y")
            })
    
    # Aggregate data for each data point
    chart_data = []
    departments_to_include = ["email", "sms", "url"] if department == "all" else [department]
    
    for point in data_points:
        date_str = point["date"]
        safe_total = 0
        phishing_total = 0
        
        if period == "daily":
            # For daily, just use the specific date
            for dept in departments_to_include:
                if date_str in daily_stats and dept in daily_stats[date_str]:
                    safe_total += daily_stats[date_str][dept]["safe"]
                    phishing_total += daily_stats[date_str][dept]["phishing"]
        elif period == "weekly":
            # For weekly, sum all days in that week
            week_start = datetime.fromisoformat(date_str).date()
            for i in range(7):
                day_date = week_start + timedelta(days=i)
                day_str = day_date.isoformat()
                for dept in departments_to_include:
                    if day_str in daily_stats and dept in daily_stats[day_str]:
                        safe_total += daily_stats[day_str][dept]["safe"]
                        phishing_total += daily_stats[day_str][dept]["phishing"]
        elif period in ["monthly", "3months", "6months"]:
            # For monthly, sum all days in that month
            month_start = datetime.fromisoformat(date_str).date()
            # Get first and last day of month
            if month_start.month == 12:
                month_end = month_start.replace(year=month_start.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                month_end = month_start.replace(month=month_start.month + 1, day=1) - timedelta(days=1)
            
            current_date = month_start
            while current_date <= month_end:
                day_str = current_date.isoformat()
                for dept in departments_to_include:
                    if day_str in daily_stats and dept in daily_stats[day_str]:
                        safe_total += daily_stats[day_str][dept]["safe"]
                        phishing_total += daily_stats[day_str][dept]["phishing"]
                current_date += timedelta(days=1)
        
        chart_data.append({
            "label": point["label"],
            "full_label": point["full_label"],
            "safe": safe_total,
            "phishing": phishing_total,
            "total": safe_total + phishing_total
        })
    
    return jsonify({
        "data": chart_data,
        "period": period,
        "department": department
    })


# -----------------------------
# FRONTEND SERVING
# -----------------------------
@app.route("/", methods=["GET"])
def index():
    """Serve dashboard as homepage"""
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
    return send_from_directory(frontend_path, "dashboard.html")

@app.route("/<path:filename>")
def serve_frontend(filename):
    """Serve frontend files"""
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
    return send_from_directory(frontend_path, filename)


# -----------------------------
# SERVER RUN
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
