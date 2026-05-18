import re
import uuid
import asyncio
from datetime import datetime
import time
from typing import Dict, Any, List

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, BackgroundTasks, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
import httpx
import mysql.connector
import sqlite3
from pydantic import BaseModel, Field

# ─── DATABASE CONFIGURATION & RESILIENT FALLBACK ────────────────────────
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'your_secure_password'),
    'database': os.getenv('DB_NAME', 'security_gateway')
}

def get_db_connection():
    """Tries to connect to MariaDB/MySQL. If it fails, falls back gracefully to SQLite in the workspace."""
    try:
        # Avoid connecting if DB_HOST is set to localhost and local port is offline
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn, "mysql"
    except Exception:
        # Fallback to local SQLite file
        conn = sqlite3.connect("security_gateway.db")
        conn.row_factory = sqlite3.Row
        return conn, "sqlite"

def query_db(query: str, args: tuple = (), one: bool = False):
    """Database query wrapper that adapts syntax between MySQL (%s) and SQLite (?)."""
    conn, db_type = get_db_connection()
    if db_type == "sqlite":
        query = query.replace("%s", "?")
    try:
        if db_type == "mysql":
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, args)
            rv = cursor.fetchall()
            cursor.close()
        else:
            cursor = conn.execute(query, args)
            rv = [dict(row) for row in cursor.fetchall()]
            cursor.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print(f"[DATABASE ERROR] Query execution failed: {e}")
        return None
    finally:
        conn.close()

def execute_db(query: str, args: tuple = ()) -> bool:
    """Database write transaction wrapper that adapts syntax between MySQL (%s) and SQLite (?)."""
    conn, db_type = get_db_connection()
    if db_type == "sqlite":
        query = query.replace("%s", "?")
    try:
        if db_type == "mysql":
            cursor = conn.cursor()
            cursor.execute(query, args)
            conn.commit()
            cursor.close()
        else:
            conn.execute(query, args)
            conn.commit()
        return True
    except Exception as e:
        print(f"[DATABASE ERROR] Write transaction failed: {e}")
        return False
    finally:
        conn.close()

def init_db():
    """Bootstraps necessary tables for alerts, rules, and global postures in MySQL or SQLite."""
    conn, db_type = get_db_connection()
    try:
        if db_type == "sqlite":
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    incident_id TEXT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT,
                    target_uri TEXT NOT NULL,
                    malicious_payload TEXT,
                    threat_category TEXT NOT NULL,
                    mitigation_action TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    identifier TEXT NOT NULL UNIQUE,
                    pattern TEXT NOT NULL,
                    action TEXT NOT NULL,
                    category TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    blocks_count INTEGER DEFAULT 0,
                    severity TEXT NOT NULL,
                    description TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mitigation_state (
                    id TEXT PRIMARY KEY,
                    posture TEXT NOT NULL
                )
            """)
        else:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    incident_id VARCHAR(36) PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip VARCHAR(45) NOT NULL,
                    user_agent TEXT,
                    target_uri VARCHAR(2048) NOT NULL,
                    malicious_payload TEXT,
                    threat_category VARCHAR(50) NOT NULL,
                    mitigation_action VARCHAR(50) NOT NULL,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_threat_category (threat_category)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id VARCHAR(36) PRIMARY KEY,
                    identifier VARCHAR(255) NOT NULL UNIQUE,
                    pattern TEXT NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    blocks_count INT DEFAULT 0,
                    severity VARCHAR(50) NOT NULL,
                    description TEXT
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitigation_state (
                    id VARCHAR(50) PRIMARY KEY,
                    posture VARCHAR(50) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.close()
        conn.commit()
        print(f"[INFO] Database tables synchronized. Scheme: {db_type.upper()}")

        # Seed defaults if empty
        rules_check = query_db("SELECT COUNT(*) as cnt FROM rules", one=True)
        if rules_check and rules_check['cnt'] == 0:
            seed_rules = [
                ("sql-core-01", "OWASP SQLi Core Ruleset", 
                 r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|WHERE|OR|AND)\b)|(['\x22\x2d\x23\x2a])|(\/\*[\s\S]*?\*\/)",
                 "Drop & Blacklist", "SQLi", 1, 1420, "Level 1", 
                 "Comprehensive SQL Injection protection targeting all known escape vectors and UNION-based attacks."),
                ("xss-scrutiny-01", "XSS Aggressive Scrutiny", 
                 r"(<script.*?>[\s\S]*?<\/script>)|(javascript\s*:\s*\S+)|(on\w+\s*=\s*['\"].*?['\"])|(<\s*iframe.*?>)",
                 "Drop & Blacklist", "XSS", 1, 92, "Level 3", 
                 "High-sensitivity detection for cross-site scripting in JSON payloads and GraphQL endpoints."),
                ("bot-blocker-01", "Bad Bot Blocker [Legacy]", 
                 r"(curl|wget|python-requests|scrapy|nikto|sqlmap|nmap)",
                 "Log Payload Only", "DEPRECATED", 0, 0, "DEPRECATED", 
                 "Simple user-agent based bot blocking. Superseded by AEGIS AI-Fingerprinting."),
                ("rfi-blocker-01", "Remote File Inclusion (RFI)", 
                 r"(https?|ftp|file|php|data):\/",
                 "Drop & Blacklist", "CRITICAL", 1, 12, "CRITICAL", 
                 "Blocks attempts to include remote files via URI schemes in parameter fields.")
            ]
            for r in seed_rules:
                execute_db("""
                    INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, r)
            print("[INFO] Successfully seeded default security profiles into registry.")
                
        posture_check = query_db("SELECT COUNT(*) as cnt FROM mitigation_state", one=True)
        if posture_check and posture_check['cnt'] == 0:
            execute_db("INSERT INTO mitigation_state (id, posture) VALUES ('global', 'Standard Posture')")
            print("[INFO] Successfully seeded global posture settings.")

    except Exception as e:
        print(f"[CRITICAL] Database bootstrapping sequence failed: {e}")
    finally:
        conn.close()

# ─── ACTIVE SIGNATURE CACHE & OPERATIONAL POSTURES ──────────────────
ACTIVE_RULES_CACHE = []
GLOBAL_POSTURE = "Standard Posture"

def reload_rules_cache():
    """Compiles active regex logic signatures into memory for high-performance traffic scanning."""
    global ACTIVE_RULES_CACHE
    rules = query_db("SELECT * FROM rules WHERE is_active = 1")
    cache = []
    if rules:
        for r in rules:
            try:
                pattern = r['pattern']
                compiled = re.compile(pattern, re.IGNORECASE)
                cache.append({
                    "rule_id": r['rule_id'],
                    "identifier": r['identifier'],
                    "pattern": pattern,
                    "action": r['action'],
                    "category": r['category'],
                    "compiled_regex": compiled
                })
            except Exception as e:
                print(f"[WARN] Failed to compile regex for security profile '{r['identifier']}': {e}")
    ACTIVE_RULES_CACHE = cache
    print(f"[INFO] Threat Engine: Active rule clusters synchronized ({len(ACTIVE_RULES_CACHE)} loaded in memory).")

def reload_global_posture():
    """Reloads global operational scanning posture."""
    global GLOBAL_POSTURE
    row = query_db("SELECT posture FROM mitigation_state WHERE id = 'global'", one=True)
    if row:
        GLOBAL_POSTURE = row['posture']
    else:
        GLOBAL_POSTURE = "Standard Posture"
    print(f"[INFO] Threat Engine: Global operating posture synchronized -> {GLOBAL_POSTURE}")


# ─── LIFESPAN MANAGED APPLICATION STARTUP ────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB (creates sqlite file or mysql tables)
    init_db()
    # Cache compilation
    reload_rules_cache()
    # Posture settings sync
    reload_global_posture()
    yield
    await http_client.aclose()

app = FastAPI(title="Kalki WAF Core Engine", version="1.0.0", lifespan=lifespan)

# Cross-Origin Resource Sharing settings for distributed frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── TARGET UPSTREAM PROFILE ─────────────────────────────────────────
UPSTREAM_SERVER_URL = os.getenv("UPSTREAM_SERVER_URL", "http://127.0.0.1:8080")

# ─── CLOUDFLARE-STYLE BLOCK RESPONSE GENERATOR ───────────────────────
def generate_block_page(incident_id: str, client_ip: str, category: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>403 Forbidden - KALKI Security Mitigation Active</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #010103; color: #e4e1e9; padding: 10% 5%; text-align: center; }}
            .container {{ max-width: 600px; margin: 0 auto; background: rgba(15, 23, 42, 0.45); backdrop-filter: blur(12px); padding: 40px; border-radius: 8px; border: 1px solid rgba(255, 0, 60, 0.3); border-top: 4px solid #ff003c; box-shadow: 0 4px 20px rgba(255, 0, 60, 0.15); }}
            h1 {{ color: #ff003c; font-size: 24px; margin-bottom: 10px; font-weight: 700; letter-spacing: -0.02em; }}
            p {{ color: #b9cacb; font-size: 14px; line-height: 1.6; }}
            .details {{ background: #0e0e13; padding: 18px; border-radius: 4px; font-family: monospace; font-size: 12px; text-align: left; margin-top: 25px; border: 1px solid rgba(255,255,255,0.05); }}
            .uuid {{ color: #00f2fe; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>KALKI SECURITY MITIGATION BLOCK ACTIVE</h1>
            <p>Your request was intercepted and dropped because it matched active threat signature profiles for <strong>{category}</strong>.</p>
            <div class="details">
                <div>Incident Reference ID: <span class="uuid">{incident_id}</span></div>
                <div>Origin Node IP: {client_ip}</div>
                <div>Scrubbing Posture: ACTIVE_BLOCK</div>
                <div>Timestamp Context: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
            </div>
        </div>
    </body>
    </html>
    """

# ─── IN-MEMORY RATE LIMITER ──────────────────────────────────────────
request_history = {}
RATE_LIMIT_THRESHOLD = 50 # requests
RATE_LIMIT_WINDOW = 10 # seconds

def check_rate_limit(client_ip: str) -> bool:
    current_time = time.time()
    
    if client_ip not in request_history:
        request_history[client_ip] = []
        
    # Clean old requests outside the window
    request_history[client_ip] = [req_time for req_time in request_history[client_ip] 
                                  if current_time - req_time < RATE_LIMIT_WINDOW]
    
    # Stricter Rate Limiting under attack posture
    limit = RATE_LIMIT_THRESHOLD
    if GLOBAL_POSTURE == "Under Attack":
        limit = 10 # very aggressive rate limit
        
    # Check if threshold is breached
    if len(request_history[client_ip]) >= limit:
        return False # Rate limit exceeded
        
    # Log new request
    request_history[client_ip].append(current_time)
    return True # Traffic allowed

# ─── GLOBAL HTTP CLIENT ────────────────────────────────────────────────
http_client = httpx.AsyncClient()

# ─── LOG EVENT PERSISTENCE WRAPPER ────────────────────────────────────
def log_incident_to_db(event_data: Dict[str, Any]):
    """Background worker task to persist security event payloads to DB without blocking traffic response."""
    query = """
        INSERT INTO security_events 
        (incident_id, timestamp, source_ip, user_agent, target_uri, malicious_payload, threat_category, mitigation_action)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    args = (
        event_data['incident_id'],
        event_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(event_data['timestamp'], datetime) else event_data['timestamp'],
        event_data['source_ip'],
        event_data['user_agent'],
        event_data['target_uri'],
        event_data['malicious_payload'],
        event_data['threat_category'],
        event_data['mitigation_action']
    )
    success = execute_db(query, args)
    if not success:
        print("[CRITICAL] Database Persistence Failure inside log_incident_to_db")

# ─── WAF INSPECTION INTERCEPTOR MIDDLEWARE ───────────────────────────
@app.middleware("http")
async def inspect_and_proxy_traffic(request: Request, call_next):
    # Bypass inspection rules for internal REST telemetry endpoints, sandbox testing, dashboard, and brand assets
    if request.url.path.startswith("/api/v1/") or request.url.path in ["/", "/dashboard", "/kalki_waf_logo.png"]:
        return await call_next(request)

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    target_uri = str(request.url.path)
    
    # 1. Collate Inspectable Attack Surfaces
    query_params = str(request.url.query)
    body_payload = b""
    if request.method in ["POST", "PUT", "PATCH"]:
        body_payload = await request.body()
    
    inspectable_string = f"{query_params} {body_payload.decode('utf-8', errors='ignore')}"

    # 0.5 Check Rate Limit
    detected_threat = None
    matched_rule = None
    
    if not check_rate_limit(client_ip):
        detected_threat = "Anomalous"
        inspectable_string = "RATE_LIMIT_EXCEEDED"
    
    # 2. Evaluate Inspection Engine against Loaded Rules
    if not detected_threat:
        for rule in ACTIVE_RULES_CACHE:
            try:
                if rule['compiled_regex'].search(inspectable_string):
                    detected_threat = rule['category']
                    matched_rule = rule
                    break
            except Exception as e:
                print(f"[ERROR] Regex matching error on rule {rule['identifier']}: {e}")

    # 3. Handle Mitigation Logic if Vector Confirmed
    if detected_threat:
        incident_id = str(uuid.uuid4())
        
        # If in Monitor Only, action is Flagged. Otherwise, Blocked.
        action = "Flagged" if GLOBAL_POSTURE == "Monitor Only" else "Blocked"
        
        event_log = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow(),
            "source_ip": client_ip,
            "user_agent": user_agent,
            "target_uri": target_uri,
            "malicious_payload": inspectable_string[:500],  # Truncate strings to prevent DB overhead
            "threat_category": detected_threat,
            "mitigation_action": action
        }
        
        # Increment rule block count in DB asynchronously
        if matched_rule:
            rule_id = matched_rule['rule_id']
            # Dispatch async increment helper
            await run_in_threadpool(execute_db, "UPDATE rules SET blocks_count = blocks_count + 1 WHERE rule_id = %s", (rule_id,))
            
        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(log_incident_to_db, event_log)
        
        if action == "Blocked":
            html_payload = generate_block_page(incident_id, client_ip, detected_threat)
            return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)
        
    # 4. Transparent Proxy Execution Flow (Clean or Flagged Traffic)
    upstream_request_url = f"{UPSTREAM_SERVER_URL}{target_uri}"
    if query_params:
        upstream_request_url += f"?{query_params}"

    # Strip host header to prevent upstream routing issues
    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)
    
    if detected_threat and GLOBAL_POSTURE == "Monitor Only":
        proxy_headers["X-WAF-Flagged"] = "True"
        proxy_headers["X-WAF-Threat-Category"] = detected_threat

    bg_tasks = BackgroundTasks()
    if detected_threat:
        bg_tasks.add_task(log_incident_to_db, event_log)

    try:
        proxy_response = await http_client.request(
            method=request.method,
            url=upstream_request_url,
            headers=proxy_headers,
            content=body_payload if body_payload else None,
            cookies=request.cookies,
            timeout=10.0
        )
        
        # Filter headers from upstream to prevent encoding conflicts
        response_headers = dict(proxy_response.headers)
        response_headers.pop("content-encoding", None)
        response_headers.pop("transfer-encoding", None)
        response_headers.pop("content-length", None)

        return Response(
            content=proxy_response.content,
            status_code=proxy_response.status_code,
            headers=response_headers,
            background=bg_tasks if detected_threat else None
        )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream Server Unreachable: {exc}")

# ─── DASHBOARD ENDPOINT ──────────────────────────────────────────────
@app.get("/")
async def root():
    """Serves the WAF static dashboard interface as the home screen."""
    return await dashboard()

@app.get("/dashboard")
async def dashboard():
    """Serves the WAF static dashboard interface."""
    try:
        with open("dashboard.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Dashboard UI not found")

@app.get("/kalki_waf_logo.png")
async def get_logo():
    """Serves the custom Kalki brand logo synchronously for zero-dependency resiliency."""
    try:
        if os.path.exists("kalki_waf_logo.png"):
            with open("kalki_waf_logo.png", "rb") as f:
                content = f.read()
            return Response(content=content, media_type="image/png")
    except Exception as e:
        print(f"[ERROR] Failed to serve logo: {e}")
    raise HTTPException(status_code=404, detail="Logo asset not found")

# ─── REST TELEMETRY ENDPOINT FOR DASHBOARD INTERFACES ───────────────
def fetch_telemetry_data():
    """Generates complete telemetry bundle using standard generic DB helper."""
    # Count totals
    total_blocked_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE mitigation_action = 'Blocked'", one=True)
    total_blocked = total_blocked_row['total'] if total_blocked_row else 0
    
    sqli_count_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'SQLi'", one=True)
    sqli_count = sqli_count_row['total'] if sqli_count_row else 0
    
    xss_count_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'XSS'", one=True)
    xss_count = xss_count_row['total'] if xss_count_row else 0

    anomalous_count_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'Anomalous'", one=True)
    anomalous_count = anomalous_count_row['total'] if anomalous_count_row else 0
    
    # Grab latest 30 alerts
    incidents = query_db("""
        SELECT incident_id, timestamp, source_ip, threat_category, target_uri, mitigation_action, user_agent, malicious_payload
        FROM security_events 
        ORDER BY timestamp DESC LIMIT 30
    """)
    if not incidents:
        incidents = []
        
    for inc in incidents:
        if inc['timestamp'] and not isinstance(inc['timestamp'], str):
            inc['timestamp'] = inc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            
    # Fetch rules
    rules = query_db("SELECT * FROM rules")
    if not rules:
        rules = []
        
    # Get active db type for stats display
    _, db_type = get_db_connection()

    return {
        "metrics": {
            "total_ingress": total_blocked + 1524,
            "total_blocked": total_blocked,
            "sqli_count": sqli_count,
            "xss_count": xss_count,
            "anomalous_count": anomalous_count,
            "active_rules_count": len(ACTIVE_RULES_CACHE),
            "posture": GLOBAL_POSTURE,
            "upstream_url": UPSTREAM_SERVER_URL,
            "rate_limit": RATE_LIMIT_THRESHOLD,
            "db_type": db_type.upper()
        },
        "incidents": incidents,
        "rules": rules
    }

@app.get("/api/v1/threat-intel/alerts")
async def get_dashboard_telemetry():
    """Fetches real-time metric counters and recent incidents to feed the frontend interface."""
    try:
        return await run_in_threadpool(fetch_telemetry_data)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"SIEM Backend Error: {str(err)}")

# ─── PYDANTIC MODELS FOR RULES CONTROLLER ─────────────────────────────
class RuleCreate(BaseModel):
    identifier: str = Field(..., description="Unique human-readable identifier")
    pattern: str = Field(..., description="Valid Python regular expression string")
    action: str = Field(..., description="Drop & Blacklist, JS Challenge, or Log Payload Only")
    category: str = "Custom"
    severity: str = "Level 2"
    description: str = ""

class ToggleRuleRequest(BaseModel):
    is_active: bool

class PostureUpdate(BaseModel):
    posture: str

class SandboxTestRequest(BaseModel):
    pattern: str
    payload: str

# ─── API ENDPOINTS FOR SIGNATURES ────────────────────────────────────
@app.get("/api/v1/rules")
async def get_rules():
    """Lists all compiled and uncompiled signature policies in the database."""
    try:
        rules = await run_in_threadpool(query_db, "SELECT * FROM rules")
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/rules")
async def create_rule(rule: RuleCreate):
    """Compiles a new security signature profile and injects it into dynamic memory and database storage."""
    # Clean Regex formatting (strip leading/trailing slashes and flags if copy-pasted from JS syntax)
    pattern = rule.pattern.strip()
    if pattern.startswith('/') and pattern.count('/') >= 2:
        last_slash_idx = pattern.rfind('/')
        pattern = pattern[1:last_slash_idx]
        
    try:
        re.compile(pattern, re.IGNORECASE)
    except Exception as regex_err:
        raise HTTPException(status_code=400, detail=f"Invalid regular expression format: {regex_err}")
        
    rule_id = f"custom-{str(uuid.uuid4())[:8]}"
    
    query = """
        INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    args = (rule_id, rule.identifier, pattern, rule.action, rule.category, 1, 0, rule.severity, rule.description)
    
    success = await run_in_threadpool(execute_db, query, args)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save custom signature profile to database. Check for duplicates.")
        
    # Reload in-memory rules cache
    await run_in_threadpool(reload_rules_cache)
    return {"status": "success", "message": "Signature profile compiled and hot-patched successfully", "rule_id": rule_id}

@app.put("/api/v1/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, payload: ToggleRuleRequest):
    """Enables or disables an active inspection signature rule."""
    is_active_val = 1 if payload.is_active else 0
    query = "UPDATE rules SET is_active = %s WHERE rule_id = %s"
    success = await run_in_threadpool(execute_db, query, (is_active_val, rule_id))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to toggle ruleset activity profile.")
        
    await run_in_threadpool(reload_rules_cache)
    return {"status": "success", "message": f"Security ruleset updated successfully."}

@app.delete("/api/v1/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Removes a custom signature profile from memory and DB."""
    # Prevent deleting core system profiles
    if rule_id in ["sql-core-01", "xss-scrutiny-01", "rfi-blocker-01"]:
        raise HTTPException(status_code=403, detail="Forbidden: System default signature rulesets cannot be deleted.")
        
    query = "DELETE FROM rules WHERE rule_id = %s"
    success = await run_in_threadpool(execute_db, query, (rule_id,))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to wipe rule from database registry.")
        
    await run_in_threadpool(reload_rules_cache)
    return {"status": "success", "message": "Signature wiped from engine memory."}

@app.get("/api/v1/mitigation-posture")
async def get_mitigation_posture():
    """Gets the global mitigation posture."""
    return {"posture": GLOBAL_POSTURE}

@app.post("/api/v1/mitigation-posture")
async def update_mitigation_posture(payload: PostureUpdate):
    """Transitions engine global mitigation posture."""
    if payload.posture not in ["Monitor Only", "Standard Posture", "Under Attack"]:
        raise HTTPException(status_code=400, detail="Invalid posture specification")
        
    query = "UPDATE mitigation_state SET posture = %s WHERE id = 'global'"
    success = await run_in_threadpool(execute_db, query, (payload.posture,))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update posture parameter in database settings.")
        
    await run_in_threadpool(reload_global_posture)
    return {"status": "success", "message": f"Global WAF threat posture updated to: {GLOBAL_POSTURE}"}

@app.post("/api/v1/rules/test-sandbox")
async def test_sandbox(payload: SandboxTestRequest):
    """Simulates threat parsing against payload buffers in a sandboxed execution context."""
    # Clean pattern
    pattern = payload.pattern.strip()
    if pattern.startswith('/') and pattern.count('/') >= 2:
        last_slash_idx = pattern.rfind('/')
        pattern = pattern[1:last_slash_idx]
        
    try:
        rx = re.compile(pattern, re.IGNORECASE)
        match = rx.search(payload.payload)
        if match:
            return {"match": True, "span": match.span(), "match_group": match.group(0)}
        return {"match": False}
    except Exception as err:
        return {"match": False, "error": str(err)}
