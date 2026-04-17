from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import psutil, asyncio, json, subprocess, re
from datetime import datetime
import psycopg2
from contextlib import contextmanager

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Security Dashboard — lalu.dev")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://security.lalu.dev"],
    allow_methods=["GET"],
    allow_headers=["*"],
)
DB = {
    "host": "172.17.0.1",
    "database": "security_dashboard",
    "user": "lalu",
    "password": "tu_password_aqui"
}

@contextmanager
def get_db():
    conn = psycopg2.connect(**DB)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def get_system_metrics():
    return {
        "timestamp": datetime.now().isoformat(),
        "cpu":  psutil.cpu_percent(interval=0.5),
        "ram":  psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent,
        "net": {
            "sent": psutil.net_io_counters().bytes_sent,
            "recv": psutil.net_io_counters().bytes_recv,
        }
    }
def get_ip_location(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,lat,lon,isp"
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.loads(r.read().decode())
    except:
        return {"country": "Unknown", "countryCode": "XX", "city": "Unknown", "lat": 0, "lon": 0}

def get_open_ports():
    conns = psutil.net_connections(kind="inet")
    ports = []
    seen = set()
    for c in conns:
        if c.status == "LISTEN" and c.laddr and c.laddr.port not in seen:
            ports.append({"port": c.laddr.port, "pid": c.pid})
            seen.add(c.laddr.port)
    return sorted(ports, key=lambda x: x["port"])
def anonymize_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return "x.x.x.x"

def get_failed_logins():
    failed = []
    log_files = ['/var/log/auth.log', '/var/log/secure']
    
    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            for line in lines:
                if "Failed password" in line or "Invalid user" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        real_ip = ip_match.group(1)
                        failed.append({
                            "ip": anonymize_ip(real_ip),
                            "type": "Invalid user" if "Invalid user" in line else "Failed password",
                            "time": line.split(' ')[0] if line else "unknown"
                        })
        except:
            continue
    
    return failed[-20:]
def save_metrics(m):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO system_metrics (cpu, ram, disk, net_sent, net_recv)
                VALUES (%s, %s, %s, %s, %s)
            """, (m["cpu"], m["ram"], m["disk"], m["net"]["sent"], m["net"]["recv"]))
    except:
        pass

def save_attempts(attempts):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            for a in attempts:
                cur.execute("""
                    INSERT INTO ssh_attempts (ip, user_attempted)
                    SELECT %s, %s
                    WHERE NOT EXISTS (
                        SELECT 1 FROM ssh_attempts
                        WHERE ip = %s AND user_attempted = %s
                        AND timestamp > NOW() - INTERVAL '5 minutes'
                    )
                """, (a["ip"], a["user"], a["ip"], a["user"]))
    except:
        pass

@app.get("/metrics")
@limiter.limit("30/minute")
def metrics(request: Request):
    m = get_system_metrics()
    save_metrics(m)
    return m

@app.get("/ports")
@limiter.limit("30/minute")
def ports(request: Request):
    return get_open_ports()

@app.get("/threats")
@limiter.limit("30/minute")
def threats(request: Request):
    attempts = get_failed_logins()
    save_attempts(attempts)
    return {
        "attempts": attempts,
        "total": len(attempts),
        "unique_ips": len(set(a["ip"] for a in attempts))
    }
@app.get("/history/metrics")
@limiter.limit("30/minute")
def history_metrics(request: Request):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT timestamp, cpu, ram, disk
                FROM system_metrics
                WHERE timestamp > NOW() - INTERVAL '1 hour'
                ORDER BY timestamp ASC
            """)
            rows = cur.fetchall()
            return [{"timestamp": str(r[0]), "cpu": r[1], "ram": r[2], "disk": r[3]} for r in rows]
    except:
        return []

@app.get("/history/threats")
@limiter.limit("30/minute")
def history_threats(request: Request):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT timestamp, ip, user_attempted
                FROM ssh_attempts
                ORDER BY timestamp DESC
                LIMIT 50
            """)
            rows = cur.fetchall()
            return [{"timestamp": str(r[0]), "ip": r[1], "user": r[2]} for r in rows]
    except:
        return []
@app.get("/geo")
@limiter.limit("30/minute")
def geo(request: Request):
    attempts = get_failed_logins()
    seen_ips = set()
    locations = []
    
    for a in attempts:
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', a.get("raw", "")) if "raw" in a else None
        # read real ip from log directly
        pass
    
    try:
        with open('/var/log/auth.log', 'r') as f:
            lines = f.readlines()
        for line in lines:
            if "Failed password" in line or "Invalid user" in line:
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    real_ip = ip_match.group(1)
                    if real_ip not in seen_ips and not real_ip.startswith('192.168') and not real_ip.startswith('127.'):
                        seen_ips.add(real_ip)
                        loc = get_ip_location(real_ip)
                        loc["ip"] = anonymize_ip(real_ip)
                        loc["count"] = sum(1 for l in lines if real_ip in l and ("Failed" in l or "Invalid" in l))
                        locations.append(loc)
    except:
        pass
    
    return {"locations": locations, "total_countries": len(set(l["countryCode"] for l in locations))}
