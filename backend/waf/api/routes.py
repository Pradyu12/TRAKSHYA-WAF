import asyncio
import json
import os
import re
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from waf import state
from waf.api.auth import verify_admin_key
from waf.core.metrics import metrics_endpoint
from waf.core.telemetry import fetch_telemetry_data
from waf.core.websocket import manager
from waf.db import execute_db, query_db
from waf.rules.engine import reload_global_posture, reload_rules_cache
from waf.rules.models import IPBlacklistRequest, PostureUpdate, RuleCreate, SandboxTestRequest, ToggleRuleRequest

router = APIRouter()

_FRONTEND_DIR: str = ""
_dashboard_html: str | None = None


def _resolve_frontend():
    global _FRONTEND_DIR, _dashboard_html
    candidates = [
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "frontend")),
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend")),
        os.path.normpath(os.path.join(os.getcwd(), "..", "frontend")),
        os.path.normpath(os.path.join(os.getcwd(), "frontend")),
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "frontend")),
    ]
    for d in candidates:
        p = os.path.join(d, "dashboard.html")
        if os.path.isfile(p):
            _FRONTEND_DIR = d
            _dashboard_html = p
            return
    _FRONTEND_DIR = candidates[0]


_resolve_frontend()

PROTECTED_RULE_IDS = {"sql-core-01", "xss-scrutiny-01", "rfi-blocker-01"}


@router.get("/health")
async def health():
    """Liveness probe — returns 200 if the process is alive."""
    return {"status": "healthy", "service": "kalki-waf", "version": "2.0.0"}


@router.get("/readyz")
async def readiness():
    """Readiness probe — checks database connectivity."""
    from waf.db import query_db

    try:
        row = query_db("SELECT COUNT(*) as cnt FROM rules", one=True)
        if row is not None:
            return {"status": "ready", "database": "connected"}
        return {"status": "degraded", "database": "empty"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}") from e


@router.get("/metrics")
async def metrics():
    return await metrics_endpoint()


@router.websocket("/api/v1/ws/incidents")
async def websocket_endpoint(websocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except Exception:
        manager.disconnect(websocket)


@router.get("/")
async def root():
    return await dashboard()


@router.get("/dashboard")
async def dashboard():
    global _dashboard_html, _FRONTEND_DIR
    if not _dashboard_html or not os.path.isfile(_dashboard_html):
        _resolve_frontend()
    p = _dashboard_html or os.path.join(_FRONTEND_DIR, "dashboard.html")
    try:
        with open(p) as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Dashboard UI not found") from None


@router.get("/earth.jpg")
async def earth_texture():
    path = os.path.join(_FRONTEND_DIR, "static", "earth.jpg")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return Response(content=f.read(), media_type="image/jpeg")
    raise HTTPException(status_code=404, detail="Earth texture not found")


@router.get("/kalki_waf_logo.png")
async def get_logo():
    path = os.path.join(_FRONTEND_DIR, "kalki_waf_logo.png")
    try:
        if os.path.exists(path):
            with open(path, "rb") as f:
                content = f.read()
            return Response(content=content, media_type="image/png")
    except Exception as e:
        print(f"[ERROR] Failed to serve logo: {e}")
    raise HTTPException(status_code=404, detail="Logo asset not found")


@router.get("/api/v1/threat-intel/alerts")
async def get_dashboard_telemetry():
    try:
        return await run_in_threadpool(fetch_telemetry_data)
    except Exception as err:
        import sys
        import traceback as _tb

        _tb.print_exc(file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"SIEM Backend Error: {str(err)}") from err


@router.get("/api/v1/rules")
async def get_rules():
    try:
        rules = await run_in_threadpool(query_db, "SELECT * FROM rules")
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/api/v1/rules")
async def create_rule(rule: RuleCreate, _: str | None = Depends(verify_admin_key)):
    pattern = rule.pattern.strip()
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash_idx = pattern.rfind("/")
        pattern = pattern[1:last_slash_idx]

    try:
        re.compile(pattern, re.IGNORECASE)
    except Exception as regex_err:
        raise HTTPException(status_code=400, detail=f"Invalid regular expression format: {regex_err}") from None

    rule_id = f"custom-{str(uuid.uuid4())[:8]}"

    query = """
        INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """  # noqa: E501
    args = (rule_id, rule.identifier, pattern, rule.action, rule.category, 1, 0, rule.severity, rule.description)

    success = await run_in_threadpool(execute_db, query, args)
    if not success:
        raise HTTPException(
            status_code=500, detail="Failed to save custom signature profile to database. Check for duplicates."
        )  # noqa: E501

    await run_in_threadpool(reload_rules_cache)
    return {
        "status": "success",
        "message": "Signature profile compiled and hot-patched successfully",
        "rule_id": rule_id,
    }  # noqa: E501


@router.put("/api/v1/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, payload: ToggleRuleRequest, _: str | None = Depends(verify_admin_key)):
    is_active_val = 1 if payload.is_active else 0
    query = "UPDATE rules SET is_active = ? WHERE rule_id = ?"
    success = await run_in_threadpool(execute_db, query, (is_active_val, rule_id))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to toggle ruleset activity profile.")

    await run_in_threadpool(reload_rules_cache)
    return {"status": "success", "message": "Security ruleset updated successfully."}


@router.delete("/api/v1/rules/{rule_id}")
async def delete_rule(rule_id: str, _: str | None = Depends(verify_admin_key)):
    if rule_id in PROTECTED_RULE_IDS:
        raise HTTPException(status_code=403, detail="Forbidden: System default signature rulesets cannot be deleted.")

    query = "DELETE FROM rules WHERE rule_id = ?"
    success = await run_in_threadpool(execute_db, query, (rule_id,))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to wipe rule from database registry.")

    await run_in_threadpool(reload_rules_cache)
    return {"status": "success", "message": "Signature wiped from engine memory."}


@router.get("/api/v1/mitigation-posture")
async def get_mitigation_posture():
    return {"posture": state.GLOBAL_POSTURE}


@router.post("/api/v1/mitigation-posture")
async def update_mitigation_posture(payload: PostureUpdate, _: str | None = Depends(verify_admin_key)):
    if payload.posture not in ["Monitor Only", "Standard Posture", "Under Attack"]:
        raise HTTPException(status_code=400, detail="Invalid posture specification")

    query = "UPDATE mitigation_state SET posture = ? WHERE id = 'global'"
    success = await run_in_threadpool(execute_db, query, (payload.posture,))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update posture parameter in database settings.")

    await run_in_threadpool(reload_global_posture)
    return {"status": "success", "message": f"Global WAF threat posture updated to: {state.GLOBAL_POSTURE}"}


@router.post("/api/v1/rules/test-sandbox")
async def test_sandbox(payload: SandboxTestRequest):
    pattern = payload.pattern.strip()
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash_idx = pattern.rfind("/")
        pattern = pattern[1:last_slash_idx]

    try:
        rx = re.compile(pattern, re.IGNORECASE)
        match = rx.search(payload.payload)
        if match:
            return {"match": True, "span": match.span(), "match_group": match.group(0)}
        return {"match": False}
    except Exception as err:
        return {"match": False, "error": str(err)}


@router.get("/api/v1/stream")
async def live_stream(request: Request):
    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                data = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "metrics": state.LIVE_STATS,
                    "posture": state.GLOBAL_POSTURE,
                    "active_rules": len(state.ACTIVE_RULES_CACHE),
                }
                yield f"data: {json.dumps(data)}\n\n"
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/api/v1/telemetry/live")
async def live_telemetry():
    return {
        "cpu_percent": round(state.LIVE_STATS.get("cpu_percent", 0), 1),
        "memory_mb": state.LIVE_STATS.get("memory_mb", 0),
        "requests_per_second": round(state.LIVE_STATS.get("requests_per_second", 0), 2),
        "active_rules": len(state.ACTIVE_RULES_CACHE),
        "posture": state.GLOBAL_POSTURE,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def log_console(message: str):
    print(f"[{datetime.now(UTC).isoformat()}] {message}")


@router.get("/api/v1/geo/lookup")
async def geo_lookup(ip: str):
    from waf.security.geoip import get_geo_location
    return {"ip": ip, "geo": get_geo_location(ip)}


@router.get("/api/v1/firewall/location")
async def firewall_location():
    from waf.config import FIREWALL_LABEL, FIREWALL_LAT, FIREWALL_LON
    return {
        "lat": FIREWALL_LAT,
        "lon": FIREWALL_LON,
        "label": FIREWALL_LABEL,
    }


@router.post("/api/v1/blacklist")
async def add_to_blacklist(request: IPBlacklistRequest, _: str | None = Depends(verify_admin_key)):
    state.IP_BLACKLIST.add(request.ip_address)
    log_console(f"IP_BLACKLIST: Added {request.ip_address} - {request.reason}")
    return {"status": "success", "message": f"IP {request.ip_address} blacklisted"}


@router.get("/api/v1/blacklist")
async def get_blacklist():
    return {"blacklisted_ips": list(state.IP_BLACKLIST)}


@router.delete("/api/v1/blacklist/{ip}")
async def remove_from_blacklist(ip: str, _: str | None = Depends(verify_admin_key)):
    state.IP_BLACKLIST.discard(ip)
    return {"status": "success", "message": f"IP {ip} removed from blacklist"}


# ─── Remote Agent / Device Monitoring ────────────────────────────────────────────


@router.get("/api/v1/agents/script")
async def agent_script():
    candidates = [
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "agents", "kalki-agent.py")),
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "agents", "kalki-agent.py")),
        os.path.normpath(os.path.join(os.getcwd(), "..", "agents", "kalki-agent.py")),
        os.path.normpath(os.path.join(os.getcwd(), "agents", "kalki-agent.py")),
    ]
    for p in candidates:
        if os.path.isfile(p):
            with open(p) as f:
                return Response(content=f.read(), media_type="text/x-python")
    raise HTTPException(status_code=404, detail="Agent script not found") from None


@router.post("/api/v1/agents/register")
async def agent_register(hostname: str, os_info: str = "", ip_address: str = "", agent_version: str = "1.0.0", tags: str = "[]"):
    from waf.agents.engine import register_agent
    return await run_in_threadpool(register_agent, hostname, os_info, ip_address, agent_version, tags)


@router.get("/api/v1/agents")
async def agent_list():
    from waf.agents.engine import get_agents
    return await run_in_threadpool(get_agents)


@router.get("/api/v1/agents/{agent_id}")
async def agent_get(agent_id: str):
    from waf.agents.engine import get_agent
    agent = await run_in_threadpool(get_agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.post("/api/v1/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, extra: str = "{}"):
    from waf.agents.engine import submit_agent_heartbeat
    try:
        extra_dict = json.loads(extra)
    except json.JSONDecodeError:
        extra_dict = {}
    result = await run_in_threadpool(submit_agent_heartbeat, agent_id, extra_dict)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/api/v1/agents/{agent_id}/commands")
async def agent_pending_commands(agent_id: str):
    from waf.agents.engine import get_pending_commands_for
    result = await run_in_threadpool(get_pending_commands_for, agent_id)
    return {"commands": result, "count": len(result)}


@router.post("/api/v1/agents/{agent_id}/commands")
async def agent_enqueue_command(agent_id: str, command: str = "{}"):
    from waf.agents.engine import enqueue_command
    try:
        cmd_dict = json.loads(command)
    except json.JSONDecodeError:
        cmd_dict = {"raw": command}
    return await run_in_threadpool(enqueue_command, agent_id, cmd_dict)


@router.post("/api/v1/agents/{agent_id}/commands/{command_id}/ack")
async def agent_ack_command(agent_id: str, command_id: int, status: str = "delivered"):
    from waf.agents.engine import ack_command
    return await run_in_threadpool(ack_command, command_id, agent_id, status)


@router.post("/api/v1/agents/{agent_id}/results")
async def agent_submit_result(agent_id: str, result_type: str, payload: str = "{}"):
    from waf.agents.engine import submit_agent_result
    try:
        payload_dict = json.loads(payload)
    except json.JSONDecodeError:
        payload_dict = {"raw": payload}
    result = await run_in_threadpool(submit_agent_result, agent_id, result_type, payload_dict)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/api/v1/agents/{agent_id}/results")
async def agent_get_results(agent_id: str, result_type: str | None = None, limit: int = 50):
    from waf.agents.engine import get_agent_results
    return await run_in_threadpool(get_agent_results, agent_id, result_type, limit)


# ─── SIEM (Security Information & Event Management) ──────────────────────────────


@router.get("/api/v1/siem/alerts")
async def siem_get_alerts(severity: str | None = None, limit: int = 50, offset: int = 0, unacked: bool = False):
    from waf.siem.engine import get_alerts
    return await run_in_threadpool(get_alerts, severity, limit, offset, unacked)


@router.post("/api/v1/siem/alerts/{alert_id}/ack")
async def siem_ack_alert(alert_id: int, _: str | None = Depends(verify_admin_key)):
    from waf.siem.engine import acknowledge_alert
    success = await run_in_threadpool(acknowledge_alert, alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "success"}


@router.get("/api/v1/siem/stats")
async def siem_stats():
    from waf.siem.engine import get_alert_stats
    return await run_in_threadpool(get_alert_stats)


@router.post("/api/v1/siem/ingest")
async def siem_ingest(source: str, log_type: str, content: str, severity: str = "info"):
    from waf.siem.engine import ingest_log
    rid = await run_in_threadpool(ingest_log, source, log_type, content, severity)
    return {"status": "ingested", "alert_id": rid}


@router.post("/api/v1/siem/correlate")
async def siem_correlate(window: int = 5):
    from waf.siem.engine import correlate_events
    return {"correlations": await run_in_threadpool(correlate_events, window)}


@router.post("/api/v1/siem/run-detection")
async def siem_run_detection(_: str | None = Depends(verify_admin_key)):
    from waf.siem.engine import run_detection_rules
    triggered = await run_in_threadpool(run_detection_rules)
    return {"alerts_triggered": len(triggered), "alerts": triggered}


# ─── HIDS (Host-based Intrusion Detection) ────────────────────────────────────────


@router.get("/api/v1/hids/alerts")
async def hids_get_alerts(severity: str | None = None, log_type: str | None = None, limit: int = 50, offset: int = 0):
    from waf.hids.engine import get_hids_alerts
    return await run_in_threadpool(get_hids_alerts, severity, log_type, limit, offset)


@router.get("/api/v1/hids/stats")
async def hids_stats():
    from waf.hids.engine import get_hids_stats
    return await run_in_threadpool(get_hids_stats)


@router.post("/api/v1/hids/ingest")
async def hids_ingest(line: str, source: str = "system"):
    from waf.hids.engine import ingest_log_line
    result = await run_in_threadpool(ingest_log_line, line, source)
    return {"parsed": result is not None, "alert": result}


@router.post("/api/v1/hids/bruteforce-check")
async def hids_bruteforce_check(source_ip: str):
    from waf.hids.engine import add_failure, detect_bruteforce
    add_failure(source_ip)
    alert = await run_in_threadpool(detect_bruteforce, source_ip)
    return {"bruteforce_detected": alert is not None, "alert": alert}


# ─── FIM (File Integrity Monitoring) ──────────────────────────────────────────────


@router.get("/api/v1/fim/events")
async def fim_get_events(limit: int = 50, offset: int = 0, change_type: str | None = None):
    from waf.fim.engine import get_fim_events
    return await run_in_threadpool(get_fim_events, limit, offset, change_type)


@router.get("/api/v1/fim/stats")
async def fim_stats():
    from waf.fim.engine import get_fim_stats
    return await run_in_threadpool(get_fim_stats)


@router.post("/api/v1/fim/record-baseline")
async def fim_record_baseline(_: str | None = Depends(verify_admin_key)):
    from waf.fim.engine import record_baselines_for, _MONITORED_PATHS
    await run_in_threadpool(record_baselines_for, _MONITORED_PATHS)
    return {"status": "success", "message": "Baseline recorded for monitored files"}


@router.post("/api/v1/fim/run-check")
async def fim_run_check(path: str | None = None, _: str | None = Depends(verify_admin_key)):
    from waf.fim.engine import check_integrity, run_integrity_check
    if path:
        result = await run_in_threadpool(check_integrity, path)
        return {"changed": result is not None, "event": result}
    results = await run_in_threadpool(run_integrity_check)
    return {"changed": len(results), "events": results}


# ─── SCA (Security Configuration Assessment) ─────────────────────────────────────


@router.post("/api/v1/sca/run")
async def sca_run(benchmark_id: str | None = None, _: str | None = Depends(verify_admin_key)):
    from waf.sca.engine import run_benchmark
    return await run_in_threadpool(run_benchmark, benchmark_id)


@router.get("/api/v1/sca/results")
async def sca_results(benchmark_id: str | None = None):
    from waf.sca.engine import get_benchmark_results, get_latest_benchmark
    if benchmark_id:
        return await run_in_threadpool(get_benchmark_results, benchmark_id)
    return await run_in_threadpool(get_latest_benchmark)


@router.get("/api/v1/sca/checks")
async def sca_checks(benchmark_id: str):
    from waf.sca.engine import get_check_details
    return await run_in_threadpool(get_check_details, benchmark_id)


@router.get("/api/v1/sca/stats")
async def sca_stats():
    from waf.sca.engine import get_sca_stats
    return await run_in_threadpool(get_sca_stats)


# ─── Vulnerability Detection ──────────────────────────────────────────────────────


@router.post("/api/v1/vuln/scan")
async def vuln_scan(_: str | None = Depends(verify_admin_key)):
    from waf.vulnerability.engine import scan_for_vulnerabilities
    return await run_in_threadpool(scan_for_vulnerabilities)


@router.get("/api/v1/vuln/list")
async def vuln_list(severity: str | None = None, limit: int = 50):
    from waf.vulnerability.engine import get_vulnerabilities
    return await run_in_threadpool(get_vulnerabilities, severity, limit)


@router.get("/api/v1/vuln/stats")
async def vuln_stats():
    from waf.vulnerability.engine import get_vuln_stats
    return await run_in_threadpool(get_vuln_stats)


@router.get("/api/v1/vuln/inventory")
async def vuln_inventory():
    from waf.vulnerability.engine import get_software_inventory
    return await run_in_threadpool(get_software_inventory)


# ─── Active Response ──────────────────────────────────────────────────────────────


@router.get("/api/v1/response/playbooks")
async def response_list_playbooks():
    from waf.active_response.engine import list_playbooks
    return await run_in_threadpool(list_playbooks)


@router.post("/api/v1/response/execute")
async def response_execute(playbook_id: str, target: str, rule_id: str | None = None, _: str | None = Depends(verify_admin_key)):
    from waf.active_response.engine import execute_playbook
    return await run_in_threadpool(execute_playbook, playbook_id, target, rule_id)


@router.get("/api/v1/response/log")
async def response_log(limit: int = 50):
    from waf.active_response.engine import get_response_log
    return await run_in_threadpool(get_response_log, limit)


@router.get("/api/v1/response/stats")
async def response_stats():
    from waf.active_response.engine import get_response_stats
    return await run_in_threadpool(get_response_stats)


# ─── Unified SIEM/XDR Dashboard ────────────────────────────────────────────────────


@router.get("/api/v1/siem/dashboard")
async def siem_dashboard():
    from waf.agents.engine import get_agents
    from waf.siem.engine import get_alert_stats
    from waf.hids.engine import get_hids_stats
    from waf.fim.engine import get_fim_stats
    from waf.vulnerability.engine import get_vuln_stats
    from waf.active_response.engine import get_response_stats

    siem_stats, hids_stats_data, fim_stats_data, vuln_stats_data, resp_stats, agents_data = await asyncio.gather(
        run_in_threadpool(get_alert_stats),
        run_in_threadpool(get_hids_stats),
        run_in_threadpool(get_fim_stats),
        run_in_threadpool(get_vuln_stats),
        run_in_threadpool(get_response_stats),
        run_in_threadpool(get_agents),
    )
    online_agents = sum(1 for a in agents_data if a.get("status") == "active")
    return {
        "posture": state.GLOBAL_POSTURE,
        "siem": siem_stats,
        "hids": hids_stats_data,
        "fim": fim_stats_data,
        "vulnerability": vuln_stats_data,
        "active_response": resp_stats,
        "live_stats": state.LIVE_STATS,
        "agents": {"total": len(agents_data), "online": online_agents, "list": agents_data},
    }
