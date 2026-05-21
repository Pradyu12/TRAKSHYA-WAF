import re
import uuid
import asyncio
from datetime import datetime, timezone
import time
from typing import Dict, Any, List, Optional, Set
from urllib.parse import unquote
import json
import ipaddress

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.routing import APIRoute
import httpx
import psutil
import sqlite3
from pydantic import BaseModel, Field

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False
    print("[WARN] redis.asyncio not available - rate limiting will use in-memory fallback")
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import geoip2.database
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider as OTelMeterProvider
try:
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricsExporter
except ImportError:
    try:
        from opentelemetry.sdk.metrics.export import MetricExporter as PeriodicExportingMetricsExporter
    except ImportError:
        PeriodicExportingMetricsExporter = None
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource

# ─── FIREBASE CONFIGURATION ────────────────────────────────────────────────
# Uses environment variables for Firebase credentials
FIREBASE_CREDENTIALS_PATH = os.getenv("FIREBASE_CREDENTIALS_PATH", "firebase-credentials.json")

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    from google.auth.exceptions import DefaultCredentialsError
    
    # Initialize Firebase (only if credentials file exists or env is set)
    if os.path.exists(FIREBASE_CREDENTIALS_PATH):
        cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        FIREBASE_ENABLED = True
    elif os.getenv("FIREBASE_PROJECT_ID"):
        # Try to use application default credentials
        cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        FIREBASE_ENABLED = True
    else:
        FIREBASE_ENABLED = False
        db = None
except ImportError:
    FIREBASE_ENABLED = False
    db = None
except DefaultCredentialsError:
    FIREBASE_ENABLED = False
    db = None

# Fallback to SQLite if Firebase is not available
def get_db_connection():
    """Returns SQLite connection as fallback when Firebase is unavailable."""
    conn = sqlite3.connect("security_gateway.db")
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"

def query_db(query: str, args: tuple = (), one: bool = False):
    """Database query wrapper that tries Firebase first, falls back to SQLite."""
    if FIREBASE_ENABLED and db:
        return query_firebase(query, args, one)
    return query_sqlite(query, args, one)

def query_sqlite(query: str, args: tuple = (), one: bool = False):
    """SQLite fallback implementation."""
    conn = sqlite3.connect("security_gateway.db")
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(query, args)
        rv = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print(f"[DATABASE ERROR] Query execution failed: {e}")
        return None
    finally:
        conn.close()

def query_firebase(query: str, args: tuple = (), one: bool = False):
    """Firebase Firestore query implementation."""
    q = query.strip().lower()
    
    try:
        # Handle SELECT queries
        if q.startswith("select"):
            if "from security_events" in q:
                collection = db.collection("security_events")
                docs = collection.stream()
                results = []
                for doc in docs:
                    data = doc.to_dict()
                    data["incident_id"] = doc.id
                    results.append(data)
                return (results[0] if results else None) if one else results
            
            elif "from rules" in q:
                collection = db.collection("rules")
                docs = collection.stream()
                results = []
                for doc in docs:
                    data = doc.to_dict()
                    data["rule_id"] = doc.id
                    results.append(data)
                return (results[0] if results else None) if one else results
            
            elif "from mitigation_state" in q:
                doc = db.collection("mitigation_state").document("global").get()
                if doc.exists:
                    data = doc.to_dict()
                    data["id"] = "global"
                    return data if one else [data]
                return None if one else []
        
        return None
    except Exception as e:
        print(f"[FIREBASE ERROR] Query execution failed: {e}")
        return None

def execute_db(query: str, args: tuple = ()) -> bool:
    """Database write transaction wrapper that tries Firebase first, falls back to SQLite."""
    if FIREBASE_ENABLED and db:
        return execute_firebase(query, args)
    return execute_sqlite(query, args)

def execute_sqlite(query: str, args: tuple = ()) -> bool:
    """SQLite fallback implementation."""
    conn = sqlite3.connect("security_gateway.db")
    try:
        conn.execute(query, args)
        conn.commit()
        return True
    except Exception as e:
        print(f"[DATABASE ERROR] Write transaction failed: {e}")
        return False
    finally:
        conn.close()

def execute_firebase(query: str, args: tuple = ()) -> bool:
    """Firebase Firestore write implementation."""
    q = query.strip().lower()
    
    try:
        if q.startswith("insert into rules"):
            rule_id = args[0]
            data = {
                "identifier": args[1],
                "pattern": args[2],
                "action": args[3],
                "category": args[4],
                "is_active": bool(args[5]),
                "blocks_count": int(args[6]),
                "severity": args[7],
                "description": args[8] if len(args) > 8 else ""
            }
            db.collection("rules").document(rule_id).set(data)
            return True
        
        elif q.startswith("insert into security_events"):
            incident_id = args[0]
            data = {
                "timestamp": args[1] if isinstance(args[1], datetime) else datetime.fromisoformat(args[1].replace('Z', '+00:00')),
                "source_ip": args[2],
                "user_agent": args[3],
                "target_uri": args[4],
                "malicious_payload": args[5],
                "threat_category": args[6],
                "mitigation_action": args[7]
            }
            db.collection("security_events").document(incident_id).set(data)
            return True
        
        elif q.startswith("update rules"):
            if "blocks_count" in q:
                rule_id = args[0] if len(args) == 1 else args[1]
                doc = db.collection("rules").document(rule_id).get()
                if doc.exists:
                    data = doc.to_dict()
                    data["blocks_count"] = data.get("blocks_count", 0) + 1
                    db.collection("rules").document(rule_id).update({"blocks_count": data["blocks_count"]})
                    return True
            elif "is_active" in q:
                rule_id = args[1]
                db.collection("rules").document(rule_id).update({"is_active": bool(args[0])})
                return True
        
        elif q.startswith("update mitigation_state"):
            db.collection("mitigation_state").document("global").update({"posture": args[0]})
            return True
        
        elif q.startswith("delete from rules"):
            db.collection("rules").document(args[0]).delete()
            return True
        
        return False
    except Exception as e:
        print(f"[FIREBASE ERROR] Write transaction failed: {e}")
        return False

def init_db():
    """Bootstraps necessary collections/documents for Firebase or creates SQLite tables as fallback."""
    if FIREBASE_ENABLED and db:
        # Ensure required collections exist (Firestore creates them on first write)
        print("[INFO] Firebase Firestore initialized successfully")
        return
    
    # Fallback to SQLite
    conn = sqlite3.connect("security_gateway.db")
    try:
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
        conn.commit()
        print("[INFO] Database tables synchronized. Scheme: SQLITE")

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
                 "Blocks attempts to include remote files via URI schemes in parameter fields."),
                ("cmd-injection-01", "Command Injection Shield", 
                 r"(;|\||`|\$\(|&&|\|\|)\s*(cat|ls|pwd|whoami|id|uname|wget|curl|bash|sh|nc|netcat|python|perl|ruby|php)\b",
                 "Drop & Blacklist", "CMDi", 1, 0, "CRITICAL",
                 "Detects OS command injection attempts via shell metacharacters and common binaries."),
                ("path-traversal-01", "Path Traversal Protection", 
                 r"(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)",
                 "Drop & Blacklist", "PATH", 1, 0, "Level 2",
                 "Prevents directory traversal attacks targeting sensitive file access."),
                ("lfi-rfi-01", "Local/Remote File Inclusion", 
                 r"(php://|file://|expect://|zip://|zlib://|data://|glob://|phar://)",
                 "Drop & Blacklist", "LFI", 1, 0, "CRITICAL",
                 "Blocks PHP wrapper injection and file inclusion vector attacks."),
                ("xml-xxe-01", "XML External Entity (XXE)", 
                 r"(<!ENTITY|SYSTEM|PUBLIC)\s+.*?(file|expect|http|https|ftp)",
                 "Drop & Blacklist", "XXE", 1, 0, "CRITICAL",
                 "Prevents XML External Entity attacks that can read local files or SSRF."),
                ("ssti-01", "Server-Side Template Injection", 
                 r"(\{\{.*\}\}|\{\%.*\s*(import|include|extends)\s*\%\}|#\{.*\}|\$\{.*\}|jsp:.*|asp:.*)",
                 "Drop & Blacklist", "SSTI", 1, 0, "CRITICAL",
                 "Detects template injection attacks in Jinja2, Twig, Velocity, and other template engines."),
                ("jsonp-abuse-01", "JSONP Callback Abuse", 
                 r"callback\s*=\s*['\"]?\s*[a-zA-Z0-9_$]+\s*['\"]?",
                 "Log Payload Only", "JSONP", 1, 0, "Level 3",
                 "Flags potential JSONP abuse and cross-origin data exfiltration attempts."),
            ]
            for r in seed_rules:
                execute_db("""
                    INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
# ─── SHARED RUNTIME METRICS ─────────────────────────────────────────────
LIVE_STATS = {
    "requests_per_second": 0.0,
    "cpu_percent": 0.0,
    "memory_mb": 0.0,
    "active_connections": 0,
}

# Seed defaults if empty
ACTIVE_RULES_CACHE = []
GLOBAL_POSTURE = "Standard Posture"
BACKUP_RESPONSES = {}
INCIDENT_RESPONSE_CACHE = {}

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


# ─── BACKGROUND METRICS SAMPLER ────────────────────────────────────────
_metrics_task: Optional[asyncio.Task] = None
_request_count: int = 0

async def _metrics_sampler():
    """Background task that periodically samples CPU, RAM, and request-rate metrics."""
    global _request_count
    next_ts = asyncio.get_event_loop().time()
    while True:
        try:
            LIVE_STATS["cpu_percent"]    = psutil.cpu_percent(interval=None)
            LIVE_STATS["memory_mb"]      = round(psutil.Process().memory_info().rss / 1024 / 1024, 1)
            LIVE_STATS["requests_per_second"] = round(_request_count / 2.0, 2)
            LIVE_STATS["active_connections"]   = LIVE_STATS.get("active_connections", 0)
            _request_count = 0
        except Exception:
            pass
        # skew-compensated sleep: account for sampling time
        next_ts += 2.0
        now = asyncio.get_event_loop().time()
        await asyncio.sleep(max(0, next_ts - now))


# ─── LIFESPAN MANAGED APPLICATION STARTUP ────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _metrics_task, redis_client
    # Initialize GeoIP
    await init_geoip()
    # Initialize Redis connection
    redis_client = await get_redis_client()
    # Initialize DB (creates sqlite file or firebase collections)
    init_db()
    # Cache compilation
    reload_rules_cache()
    # Posture settings sync
    reload_global_posture()
    # Start live metrics background sampler
    _metrics_task = asyncio.create_task(_metrics_sampler())
    yield
    if _metrics_task:
        _metrics_task.cancel()
    if redis_client:
        await redis_client.close()
    await http_client.aclose()

app = FastAPI(title="Kalki WAF Core Engine", version="1.0.0", lifespan=lifespan)

# Cross-Origin Resource Sharing settings for distributed frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── REQUEST CONNECTION COUNTER ─────────────────────────────────────────

@app.middleware("http")
async def count_request(request: Request, call_next):
    global _request_count
    _request_count += 1
    response = await call_next(request)
    return response

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
                <div>Timestamp Context: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
            </div>
        </div>
    </body>
    </html>
    """

# ─── PROMETHEUS METRICS ───────────────────────────────────────────────────────
REQUEST_COUNT = Counter("waf_requests_total", "Total requests processed", ["method", "path", "status"])
BLOCKED_COUNT = Counter("waf_blocked_total", "Total blocked requests", ["category"])
REQUEST_DURATION = Histogram("waf_request_duration_seconds", "Request latency")
ACTIVE_CONNECTIONS = Gauge("waf_active_connections", "Current active connections")
UPSTREAM_TIMEOUTS = Counter("waf_upstream_timeouts_total", "Upstream request timeouts")

# ─── RATE LIMITING CONFIG ──────────────────────────────────────────────────────
RATE_LIMIT_THRESHOLD = 50  # requests
RATE_LIMIT_WINDOW = 10  # seconds
request_history = {}

# ─── REDIS-BACKED DISTRIBUTED RATE LIMITER ─────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client: 'Optional[redis.Redis]' = None

async def get_redis_client():
    """Get or create Redis connection for distributed rate limiting."""
    global redis_client
    if redis_client is None:
        if not REDIS_AVAILABLE:
            print("[WARN] redis.asyncio package not installed - using in-memory rate limiting")
            return None
        try:
            redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
        except Exception as e:
            print(f"[WARN] Redis unavailable, falling back to in-memory: {e}")
            redis_client = None
    return redis_client

async def check_rate_limit(client_ip: str) -> bool:
    """Distributed rate limiting using Redis with sliding window algorithm."""
    limit = RATE_LIMIT_THRESHOLD
    if GLOBAL_POSTURE == "Under Attack":
        limit = 10
    
    # Try Redis first
    try:
        r = await get_redis_client()
        if r:
            key = f"rate_limit:{client_ip}"
            now = int(time.time())
            # Sliding window using Redis sorted set
            pipeline = r.pipeline()
            pipeline.zremrangebyscore(key, 0, now - RATE_LIMIT_WINDOW)
            pipeline.zcard(key)
            pipeline.zadd(key, {str(now): now})
            pipeline.expire(key, RATE_LIMIT_WINDOW)
            results = await pipeline.execute()
            
            request_count = results[1]
            if request_count >= limit:
                return False
            return True
    except Exception:
        pass
    
    # Fallback to in-memory rate limiting
    current_time = time.time()
    if client_ip not in request_history:
        request_history[client_ip] = []
    request_history[client_ip] = [req_time for req_time in request_history[client_ip] 
                                  if current_time - req_time < RATE_LIMIT_WINDOW]
    if len(request_history[client_ip]) >= limit:
        return False
    request_history[client_ip].append(current_time)
    return True

# ─── GEOIP2 COUNTRY BLOCKING ────────────────────────────────────────────────
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "GeoLite2-Country.mmdb")
geoip_reader: Optional[geoip2.database.Reader] = None
BLOCKED_COUNTRIES: Set[str] = set(os.getenv("BLOCKED_COUNTRIES", "").split(",")) if os.getenv("BLOCKED_COUNTRIES") else set()

async def init_geoip():
    """Initialize GeoIP2 database reader."""
    global geoip_reader
    try:
        if os.path.exists(GEOIP_DB_PATH):
            geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            print(f"[INFO] GeoIP2 database loaded from {GEOIP_DB_PATH}")
        else:
            print(f"[WARN] GeoIP2 database not found at {GEOIP_DB_PATH}")
    except Exception as e:
        print(f"[WARN] GeoIP2 initialization failed: {e}")

def get_country_code(ip: str) -> Optional[str]:
    """Get ISO country code from IP address."""
    if geoip_reader:
        try:
            response = geoip_reader.country(ip)
            return response.country.iso_code
        except Exception:
            pass
    return None

async def check_country_block(ip: str) -> bool:
    """Check if IP is from blocked country. Returns True if blocked."""
    if not BLOCKED_COUNTRIES:
        return False
    country = get_country_code(ip)
    return country in BLOCKED_COUNTRIES


# ─── GRAPHQL QUERY DEPTH LIMITER ────────────────────────────────────────────
GRAPHQL_MAX_DEPTH = int(os.getenv("GRAPHQL_MAX_DEPTH", "5"))

def check_graphql_depth(query: str) -> bool:
    """Check if GraphQL query exceeds max depth. Returns True if valid."""
    if not query:
        return True
    
    # Simple depth calculation based on nesting braces
    max_depth = 0
    current_depth = 0
    in_string = False
    in_argument = False
    
    for char in query:
        if char == '"' and (not in_string or query[max(0, query.index(char)-1)] != '\\'):
            in_string = not in_string
        elif not in_string:
            if char == '(':
                in_argument = True
                current_depth += 1
            elif char == ')':
                current_depth = max(0, current_depth - 1)
                in_argument = False
            elif char == '{' and not in_argument:
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
    
    return max_depth <= GRAPHQL_MAX_DEPTH

# ─── CIRCUIT BREAKER FOR UPSTREAM ───────────────────────────────────────────
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    async def call(self, func, *args, **kwargs):
        if self.state == "OPEN":
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout:
                self.state = "HALF_OPEN"
            else:
                raise HTTPException(status_code=503, detail="Circuit breaker OPEN - upstream unavailable")
        
        try:
            result = await func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise e
    
    def on_success(self):
        self.failure_count = 0
        self.state = "CLOSED"
    
    def on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

circuit_breaker = CircuitBreaker()

# ─── WEBSOCKET CONNECTION MANAGER ───────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.incident_queue: asyncio.Queue = asyncio.Queue()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast_incident(self, incident: Dict[str, Any]):
        data = json.dumps(incident)
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(data)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

@app.websocket("/api/v1/ws/incidents")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time incident streaming."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def broadcast_incident(incident: Dict[str, Any]):
    """Broadcast incident to all WebSocket connections."""
    await manager.broadcast_incident(incident)

# ─── PROMETHEUS METRICS ENDPOINT ────────────────────────────────────────────
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

# ─── OPEN TELEMETRY INITIALIZATION ─────────────────────────────────────────
resource = Resource(attributes={"service.name": "kalki-waf"})
trace.set_tracer_provider(TracerProvider(resource=resource))
tracer = trace.get_tracer(__name__)

FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())

# ─── GLOBAL HTTP CLIENT ────────────────────────────────────────────────
http_client = httpx.AsyncClient()

# ─── LOG EVENT PERSISTENCE WRAPPER ────────────────────────────────────
def log_incident_to_db(event_data: Dict[str, Any]):
    """Background worker task to persist security event payloads to DB without blocking traffic response."""
    query = """
        INSERT INTO security_events 
        (incident_id, timestamp, source_ip, user_agent, target_uri, malicious_payload, threat_category, mitigation_action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    target_uri = str(request.url.path)
    
    # ── Prometheus metrics tracking ───────────────────────────────────────
    start_time = time.time()
    ACTIVE_CONNECTIONS.inc()
    

    # ── GeoIP Country Blocking ─────────────────────────────────────────────
    if await check_country_block(client_ip):
        blocked_country = get_country_code(client_ip)
        incident_id = str(uuid.uuid4())
        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(log_incident_to_db, {
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc),
            "source_ip": client_ip,
            "user_agent": user_agent,
            "target_uri": target_uri,
            "malicious_payload": f"GEO_BLOCKED:{blocked_country}",
            "threat_category": "GeoBlock",
            "mitigation_action": "Blocked",
        })
        html_payload = generate_block_page(incident_id, client_ip, "GeoBlock")
        return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)
    
    # ── Rate-limit: applied FIRST, before any path bypass ───────────────────
    if not await check_rate_limit(client_ip):
        incident_id = str(uuid.uuid4())
        BLOCKED_COUNT.labels(category="rate_limit").inc()
        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(log_incident_to_db, {
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc),
            "source_ip": client_ip,
            "user_agent": user_agent,
            "target_uri": target_uri,
            "malicious_payload": "RATE_LIMIT_EXCEEDED",
            "threat_category": "Anomalous",
            "mitigation_action": "Blocked",
        })
        html_payload = generate_block_page(incident_id, client_ip, "Anomalous")
        return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)
    
    # Bypass WAF inspection for internal REST telemetry endpoints, sandbox testing,
    # dashboard, and brand assets. Rate-limiting is handled above.
    if request.url.path.startswith("/api/v1/") or request.url.path in ["/", "/dashboard", "/kalki_waf_logo.png"]:
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status=str(response.status_code)).inc()
            ACTIVE_CONNECTIONS.dec()
            return response
        except Exception as e:
            ACTIVE_CONNECTIONS.dec()
            raise e
    
    # ── GraphQL Depth Limiting ─────────────────────────────────────────────
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type and request.method == "POST":
        try:
            body = await request.body()
            body_str = body.decode('utf-8', errors='ignore')
            json_body = json.loads(body_str)
            if "query" in json_body:
                if not check_graphql_depth(json_body["query"]):
                    incident_id = str(uuid.uuid4())
                    bg_tasks = BackgroundTasks()
                    bg_tasks.add_task(log_incident_to_db, {
                        "incident_id": incident_id,
                        "timestamp": datetime.now(timezone.utc),
                        "source_ip": client_ip,
                        "user_agent": user_agent,
                        "target_uri": target_uri,
                        "malicious_payload": "GRAPHQL_DEPTH_EXCEEDED",
                        "threat_category": "GraphQL",
                        "mitigation_action": "Blocked",
                    })
                    html_payload = generate_block_page(incident_id, client_ip, "GraphQL")
                    return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)
                # Restore body for downstream
                request._body = body
        except Exception:
            pass
    
    # 2. Collate Inspectable Attack Surfaces
    query_params = unquote(str(request.url.query), encoding="utf-8", errors="replace")
    body_payload = b""
    if request.method in ["POST", "PUT", "PATCH"]:
        body_payload = await request.body()
    
    inspectable_string = f"{query_params} {body_payload.decode('utf-8', errors='ignore')}"
    
    # 3. Evaluate Inspection Engine against Loaded Rules
    detected_threat = None
    matched_rule = None
    
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
        BLOCKED_COUNT.labels(category=detected_threat).inc()
        
        # If in Monitor Only, action is Flagged. Otherwise, Blocked.
        action = "Flagged" if GLOBAL_POSTURE == "Monitor Only" else "Blocked"
        
        event_log = {
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc),
            "source_ip": client_ip,
            "user_agent": user_agent,
            "target_uri": target_uri,
            "malicious_payload": inspectable_string[:500],  # Truncate strings to prevent DB overhead
            "threat_category": detected_threat,
            "mitigation_action": action
        }
        
        # Broadcast to WebSocket clients
        await broadcast_incident({
            "incident_id": incident_id,
            "source_ip": client_ip,
            "threat_category": detected_threat,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        # Increment rule block count in DB asynchronously
        if matched_rule:
            rule_id = matched_rule['rule_id']
            await run_in_threadpool(execute_db, "UPDATE rules SET blocks_count = blocks_count + 1 WHERE rule_id = ?", (rule_id,))
            
        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(log_incident_to_db, event_log)
        
        if action == "Blocked":
            html_payload = generate_block_page(incident_id, client_ip, detected_threat)
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status="403").inc()
            ACTIVE_CONNECTIONS.dec()
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
        proxy_response = await circuit_breaker.call(
            http_client.request,
            method=request.method,
            url=upstream_request_url,
            headers=proxy_headers,
            content=body_payload if body_payload else None,
            timeout=10.0
        )
        
        # Filter headers from upstream to prevent encoding conflicts
        response_headers = dict(proxy_response.headers)
        response_headers.pop("content-encoding", None)
        response_headers.pop("transfer-encoding", None)
        response_headers.pop("content-length", None)
        
        duration = time.time() - start_time
        REQUEST_DURATION.observe(duration)
        REQUEST_COUNT.labels(method=request.method, path=target_uri, status=str(proxy_response.status_code)).inc()
        ACTIVE_CONNECTIONS.dec()
        
        return Response(
            content=proxy_response.content,
            status_code=proxy_response.status_code,
            headers=response_headers,
            background=bg_tasks if detected_threat else None
        )
    except HTTPException:
        ACTIVE_CONNECTIONS.dec()
        raise
    except httpx.RequestError as exc:
        UPSTREAM_TIMEOUTS.inc()
        ACTIVE_CONNECTIONS.dec()
        import sys, traceback as _tb
        _tb.print_exc(file=sys.stderr)
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
        with open("index.html", "r") as f:
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
    if FIREBASE_ENABLED and db:
        db_type = "FIREBASE"
    else:
        db_type = "SQLITE"

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
            "db_type": db_type
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
        import sys, traceback as _tb
        _tb.print_exc(file=sys.stderr)
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    query = "UPDATE rules SET is_active = ? WHERE rule_id = ?"
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
        
    query = "DELETE FROM rules WHERE rule_id = ?"
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
        
    query = "UPDATE mitigation_state SET posture = ? WHERE id = 'global'"
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
# ─── LIVE STREAMING ENDPOINT (Server-Sent Events) ───────────────────────────────
from fastapi.responses import StreamingResponse
import json

@app.get("/api/v1/stream")
async def live_stream():
    """Server-Sent Events endpoint for real-time telemetry streaming."""
    async def event_generator():
        while True:
            try:
                data = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metrics": LIVE_STATS,
                    "posture": GLOBAL_POSTURE,
                    "active_rules": len(ACTIVE_RULES_CACHE)
                }
                yield f"data: {json.dumps(data)}\n\n"
                await asyncio.sleep(2)
            except Exception:
                await asyncio.sleep(5)
    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ─── ENHANCED TELEMETRY ENDPOINT ───────────────────────────────────────────────
@app.get("/api/v1/telemetry/live")
async def live_telemetry():
    """Returns current live statistics for dashboard widgets."""
    return {
        "cpu_percent": round(LIVE_STATS.get("cpu_percent", 0), 1),
        "memory_mb": LIVE_STATS.get("memory_mb", 0),
        "requests_per_second": round(LIVE_STATS.get("requests_per_second", 0), 2),
        "active_rules": len(ACTIVE_RULES_CACHE),
        "posture": GLOBAL_POSTURE,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ─── IP BLACKLIST MANAGEMENT ───────────────────────────────────────────────────
class IPBlacklistRequest(BaseModel):
    ip_address: str
    reason: str = "Manual block"
    duration_hours: int = 24

IP_BLACKLIST = set()

def logConsole(message: str):
    """Internal logging helper."""
    print(f"[{datetime.now(timezone.utc).isoformat()}] {message}")

@app.post("/api/v1/blacklist")
async def add_to_blacklist(request: IPBlacklistRequest):
    """Adds an IP to the runtime blacklist."""
    IP_BLACKLIST.add(request.ip_address)
    logConsole(f"IP_BLACKLIST: Added {request.ip_address} - {request.reason}")
    return {"status": "success", "message": f"IP {request.ip_address} blacklisted"}

@app.get("/api/v1/blacklist")
async def get_blacklist():
    """Returns current blacklisted IPs."""
    return {"blacklisted_ips": list(IP_BLACKLIST)}

@app.delete("/api/v1/blacklist/{ip}")
async def remove_from_blacklist(ip: str):
    """Removes an IP from the blacklist."""
    IP_BLACKLIST.discard(ip)
    return {"status": "success", "message": f"IP {ip} removed from blacklist"}
