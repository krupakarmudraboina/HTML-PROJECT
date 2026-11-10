from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_connection, create_tables
import re
from datetime import datetime

app = Flask(__name__)
app.config["SECRET_KEY"] = "scamshield-ai-dev-secret-change-this-in-production"
CORS(app, supports_credentials=True)

# Make sure the database/table exists when the server starts.
create_tables()


def _valid_email(email):
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email or ""))


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")

    if not name or not email or not password:
        return jsonify({"status": "error", "message": "Name, email and password are required"}), 400

    if not _valid_email(email):
        return jsonify({"status": "error", "message": "Enter a valid email address"}), 400

    if len(password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400

    connection = get_connection()
    cursor = connection.cursor()
    existing = cursor.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        connection.close()
        return jsonify({"status": "error", "message": "An account with this email already exists"}), 409

    password_hash = generate_password_hash(password)
    cursor.execute(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        (name, email, password_hash)
    )
    connection.commit()
    user_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "status": "success",
        "message": "Account created successfully",
        "user": {"id": user_id, "name": name, "email": email}
    }), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required"}), 400

    connection = get_connection()
    user = connection.execute(
        "SELECT id, name, email, password_hash FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    connection.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"status": "error", "message": "Invalid email or password"}), 401

    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "user": {"id": user["id"], "name": user["name"], "email": user["email"]}
    })


@app.route("/auth/status", methods=["GET"])
def auth_status():
    if "user_id" not in session:
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "user": {
            "id": session["user_id"],
            "name": session["user_name"],
            "email": session["user_email"]
        }
    })


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully"})


def analyze_content(content):
    """
    Basic rule-based scam/threat analysis.
    Returns a score, level, indicators and recommendation.
    """
    text = (content or "").strip()
    lower = text.lower()

    indicators = []
    score = 0

    # Common scam indicators
    patterns = [
        (r"\burgent\b|\bimmediately\b|\bact now\b", "Urgency / pressure language", 15),
        (r"\bpassword\b|\bpasswd\b|\bpin\b|\botp\b", "Requests sensitive authentication information", 25),
        (r"\bupi\b|\bbank account\b|\bcredit card\b|\bdebit card\b", "Financial information reference", 20),
        (r"\bclick here\b|\bclick the link\b|\bverify your account\b", "Suspicious link / verification request", 20),
        (r"\bprize\b|\blottery\b|\bwon\b|\bwinner\b|\breward\b", "Prize / reward scam language", 15),
        (r"\brefund\b|\bcashback\b|\bkyc\b", "Refund / KYC lure", 15),
        (r"\bsend money\b|\bpay now\b|\btransfer money\b", "Payment request", 20),
    ]

    for pattern, label, points in patterns:
        if re.search(pattern, lower):
            indicators.append(label)
            score += points

    # URLs can increase suspicion when combined with other indicators.
    urls = re.findall(r"https?://[^\s]+|www\.[^\s]+", text, flags=re.I)
    if urls:
        indicators.append("Contains a URL")
        score += 10

    score = min(score, 100)

    if score >= 70:
        risk_level = "HIGH"
        recommendation = "Do not interact with the message or share personal/financial information. Verify the source independently."
    elif score >= 35:
        risk_level = "MEDIUM"
        recommendation = "Be cautious. Do not share sensitive information and verify the sender or website before taking action."
    else:
        risk_level = "LOW"
        recommendation = "No strong scam indicators were detected. Still verify unexpected requests before responding."

    if not indicators:
        indicators = ["No obvious scam indicators detected"]

    return score, risk_level, indicators, recommendation


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "success",
        "message": "SCAMSHIELD AI backend is running"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "SCAMSHIELD AI"
    })


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    content = data.get("content") or data.get("text") or data.get("message")
    scan_type = data.get("scan_type") or data.get("type") or "text"

    if not content or not str(content).strip():
        return jsonify({
            "status": "error",
            "message": "Content is required"
        }), 400

    content = str(content).strip()
    scan_type = str(scan_type).strip()

    risk_score, risk_level, indicators, recommendation = analyze_content(content)

    # Save scan result to SQLite.
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO scans
        (scan_type, content, risk_score, risk_level)
        VALUES (?, ?, ?, ?)
        """,
        (scan_type, content, risk_score, risk_level)
    )
    connection.commit()
    connection.close()

    return jsonify({
        "status": "success",
        "scan_type": scan_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation
    })


@app.route("/history", methods=["GET"])
def history():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, scan_type, content, risk_score, risk_level, created_at
        FROM scans
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()
    connection.close()

    scans = []
    for row in rows:
        scans.append({
            "id": row[0],
            "scan_type": row[1],
            "content": row[2],
            "risk_score": row[3],
            "risk_level": row[4],
            "created_at": row[5]
        })

    return jsonify({
        "status": "success",
        "scans": scans
    })


@app.route("/analytics", methods=["GET"])
def analytics():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'HIGH'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'MEDIUM'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'LOW'")
    low = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM scans")
    avg_score = cursor.fetchone()[0]

    connection.close()

    return jsonify({
        "status": "success",
        "total_scans": total,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        "average_risk_score": round(avg_score or 0, 2)
    })


if __name__ == "__main__":
    print("SCAMSHIELD AI backend starting...")
    print("API: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
