import sys
import os
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))
sys.path.insert(0, ROOT)

os.environ.setdefault("WAF_ENV", "production")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

os.environ.setdefault("DB_PATH", "/tmp/security_gateway.db")
os.environ.setdefault("GEOIP_DB_PATH", "/tmp/GeoLite2-Country.mmdb")
os.environ.setdefault("GEOIP_CITY_DB_PATH", "/tmp/GeoLite2-City.mmdb")

try:
    from waf.db import init_db
    init_db()
    from waf.rules.engine import reload_rules_cache, reload_global_posture
    reload_rules_cache()
    reload_global_posture()
    print("[INFO] Serverless cold-start init complete")
except Exception as e:
    print(f"[WARN] Serverless init skipped: {e}")

from mangum import Mangum
from main import app

handler = Mangum(app, lifespan="off")
