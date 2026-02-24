import re
import base64
import json
import logging
from datetime import datetime, timezone
from models import db, Guest, UpdatePackage, ScanResult, GuestService
from ssh_client import SSHClient
from proxmox_api import ProxmoxClient

logger = logging.getLogger(__name__)

# Valid systemd unit names: alphanumeric, hyphens, underscores, dots, @, *
_VALID_UNIT_RE = re.compile(r'^[\w.\-@*]+$')

# Pure-Python3 Redis client script for Sidekiq stats.
# Uses only stdlib socket + urllib — no redis-cli required.
# \\r\\n in this bytes literal → \r\n in the inner Python source → CR+LF at runtime.
_SIDEKIQ_REDIS_SCRIPT = b"""\
import socket, urllib.parse as up, json, time

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    print("---queues---")
    rc(s, "SMEMBERS", "queues")
    qs = rr(s, bf) or []
    _lat_dbg = ''
    def _parse_ea(ea):
        try:
            ts = float(ea)
            if ts > 1e11: ts /= 1000.0
            return ts
        except (TypeError, ValueError): pass
        try:
            from datetime import datetime as _dt
            return _dt.fromisoformat(str(ea).replace('Z', '+00:00')).timestamp()
        except Exception: return None
    for q in qs:
        rc(s, "LLEN", "queue:"+q)
        size = rr(s, bf) or 0
        lat = 0.0
        if size > 0:
            rc(s, "LINDEX", "queue:"+q, "-1")
            rc(s, "LINDEX", "queue:"+q, "0")
            for _item in [rr(s, bf), rr(s, bf)]:
                if _item:
                    try:
                        _job = json.loads(_item)
                        _ea = _job.get("enqueued_at") or _job.get("created_at")
                        if _ea is not None:
                            _ts = _parse_ea(_ea)
                            if _ts is not None:
                                _l = time.time() - _ts
                                if _l > lat: lat = _l
                            if not _lat_dbg:
                                _lat_dbg = '{}|{}|{}'.format(q, type(_ea).__name__, str(_ea)[:30])
                        elif not _lat_dbg:
                            _lat_dbg = '{}|no_ea|keys:{}'.format(q, ','.join(list(_job.keys())[:5]))
                    except Exception as _ex:
                        if not _lat_dbg: _lat_dbg = '{}|ex|{}'.format(q, str(_ex)[:60])
        print("{}={}|{:.2f}".format(q, size, lat))
    print("---stats---")
    for k, c in [("processed", ("GET", "stat:processed")), ("failed", ("GET", "stat:failed")),
                 ("retry", ("ZCARD", "retry")), ("dead", ("ZCARD", "dead")),
                 ("scheduled", ("ZCARD", "schedule"))]:
        rc(s, *c)
        print("{}={}".format(k, rr(s, bf) or 0))
    s.close()
    print("---debug---")
    print("host={}".format(host))
    print("port={}".format(port))
    print("db={}".format(db))
    print("auth_set={}".format("yes" if pw else "no"))
    print("redis_cli=python3-ok")
    print("lat_dbg={}".format(_lat_dbg or 'none'))
except Exception as e:
    print("---debug---")
    print("host={}".format(host))
    print("port={}".format(port))
    print("db={}".format(db))
    print("auth_set={}".format("yes" if pw else "no"))
    print("redis_cli=python3-err")
    print("errmsg={}".format(str(e)[:120]))
"""


# Pure-Python3 Redis script to clear the Sidekiq dead queue.
# Shares the same connection discovery logic as _SIDEKIQ_REDIS_SCRIPT.
_SIDEKIQ_CLEAR_DEAD_SCRIPT = b"""\
import socket, urllib.parse as up

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    rc(s, "DEL", "dead")
    n = rr(s, bf)
    s.close()
    print("ok={}".format(n or 0))
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_clear_dead(guest, service):
    """Clear the Sidekiq dead queue by deleting the 'dead' sorted set from Redis.

    Returns (ok: bool, message: str).
    """
    _py_b64 = base64.b64encode(_SIDEKIQ_CLEAR_DEAD_SCRIPT).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            count = line.split("=", 1)[1]
            return True, f"Cleared {count} job(s) from the dead queue"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


# Pure-Python3 Redis script to retry all jobs in the Sidekiq dead queue.
# Reads each job from the 'dead' sorted set, LPUSHes it back onto its queue,
# then deletes the dead set. Shares connection discovery with the other scripts.
_SIDEKIQ_RETRY_DEAD_SCRIPT = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    rc(s, "ZRANGE", "dead", "0", "-1")
    jobs = rr(s, bf) or []
    count = 0
    for job_str in jobs:
        try:
            queue = json.loads(job_str).get("queue", "default")
            rc(s, "LPUSH", "queue:" + queue, job_str)
            rr(s, bf)
            count += 1
        except: pass
    rc(s, "DEL", "dead")
    rr(s, bf)
    s.close()
    print("ok={}".format(count))
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_retry_dead(guest, service):
    """Retry all jobs in the Sidekiq dead queue by requeueing them.

    Returns (ok: bool, message: str).
    """
    _py_b64 = base64.b64encode(_SIDEKIQ_RETRY_DEAD_SCRIPT).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            count = line.split("=", 1)[1]
            return True, f"Retried {count} job(s) from the dead queue"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


_SIDEKIQ_JID_RE = re.compile(r'^[0-9a-f]{16,32}$')


def _format_elapsed(secs):
    """Format seconds as a human-readable elapsed time string for queue latency."""
    try:
        secs = float(secs)
    except (TypeError, ValueError):
        return "—"
    if secs < 1:
        return "< 1s"
    elif secs < 60:
        return f"{secs:.0f}s"
    elif secs < 3600:
        m, s = int(secs // 60), int(secs % 60)
        return f"{m}m {s}s"
    else:
        h = int(secs // 3600)
        m = int((secs % 3600) // 60)
        return f"{h}h {m}m"


# Pure-Python3 Redis script template to list jobs from a Sidekiq sorted-set queue.
# Placeholders __QUEUEKEY__, __OFFSET__, __ENDIDX__ are replaced at call time via bytes.replace().
_SIDEKIQ_LIST_JOBS_TEMPLATE = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(8)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    q_key = __QUEUEKEY__
    offset = __OFFSET__
    end = __ENDIDX__
    rc(s, "ZCARD", q_key)
    total = rr(s, bf) or 0
    if q_key == "dead":
        rc(s, "ZREVRANGE", q_key, str(offset), str(end), "WITHSCORES")
    else:
        rc(s, "ZRANGE", q_key, str(offset), str(end), "WITHSCORES")
    items = rr(s, bf) or []
    jobs = []
    for i in range(0, len(items), 2):
        try:
            job = json.loads(items[i])
            score = float(items[i+1]) if i+1 < len(items) else 0.0
            jobs.append({"jid": job.get("jid",""), "class": job.get("class",""), "queue": job.get("queue",""), "args": str(job.get("args",[]))[:80], "enqueued_at": job.get("enqueued_at",0), "failed_at": job.get("failed_at",0), "error_message": (job.get("error_message","") or "")[:100], "score": score})
        except: pass
    s.close()
    print(json.dumps({"total": total, "jobs": jobs}))
except Exception as e:
    print(json.dumps({"error": str(e)[:120]}))
"""


def sidekiq_list_jobs(guest, service, queue_type, offset=0, limit=25):
    """Fetch a page of jobs from a Sidekiq sorted-set queue (dead/retry/schedule).

    Returns (jobs: list, total: int, error: str|None).
    """
    if queue_type not in ("dead", "retry", "schedule"):
        return [], 0, "Invalid queue type"
    script = _SIDEKIQ_LIST_JOBS_TEMPLATE
    script = script.replace(b"__QUEUEKEY__", repr(str(queue_type)).encode())
    script = script.replace(b"__OFFSET__", str(int(offset)).encode())
    script = script.replace(b"__ENDIDX__", str(int(offset) + int(limit) - 1).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return [], 0, err
    try:
        data = json.loads((out or "").strip())
        if "error" in data:
            return [], 0, data["error"]
        return data.get("jobs", []), int(data.get("total", 0)), None
    except Exception:
        return [], 0, f"Could not parse response: {(out or '')[:80]}"


# Pure-Python3 Redis script template to delete a single Sidekiq job by JID.
# Iterates the sorted set via ZSCAN to find and ZREM the matching member.
# Placeholders __QUEUEKEY__ and __JID__ are replaced at call time.
_SIDEKIQ_DELETE_JOB_TEMPLATE = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(8)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    q_key = __QUEUEKEY__
    target_jid = __JID__
    cursor = "0"
    found = None
    while True:
        rc(s, "ZSCAN", q_key, cursor, "COUNT", "200")
        result = rr(s, bf) or ["0", []]
        cursor = result[0] if result[0] else "0"
        items = result[1] or []
        for i in range(0, len(items), 2):
            try:
                if json.loads(items[i]).get("jid") == target_jid:
                    found = items[i]
                    break
            except: pass
        if found is not None or cursor == "0":
            break
    if found is not None:
        rc(s, "ZREM", q_key, found)
        n = rr(s, bf) or 0
        print("ok={}".format(n))
    else:
        print("error=job not found")
    s.close()
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_delete_job(guest, service, queue_type, jid):
    """Remove a single job from a Sidekiq sorted-set queue by JID.

    Returns (ok: bool, message: str).
    """
    if queue_type not in ("dead", "retry", "schedule"):
        return False, "Invalid queue type"
    if not _SIDEKIQ_JID_RE.match(jid):
        return False, "Invalid JID"
    script = _SIDEKIQ_DELETE_JOB_TEMPLATE
    script = script.replace(b"__QUEUEKEY__", repr(str(queue_type)).encode())
    script = script.replace(b"__JID__", repr(str(jid)).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            return True, f"Job deleted"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


# Pure-Python3 Redis script template to retry (re-enqueue) a single Sidekiq job by JID.
# Finds the job via ZSCAN, LPUSHes it back to its queue, then ZREMs it from the set.
# Placeholders __QUEUEKEY__ and __JID__ are replaced at call time.
_SIDEKIQ_RETRY_JOB_TEMPLATE = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(8)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    q_key = __QUEUEKEY__
    target_jid = __JID__
    cursor = "0"
    found_member = None
    found_job = None
    while True:
        rc(s, "ZSCAN", q_key, cursor, "COUNT", "200")
        result = rr(s, bf) or ["0", []]
        cursor = result[0] if result[0] else "0"
        items = result[1] or []
        for i in range(0, len(items), 2):
            try:
                job = json.loads(items[i])
                if job.get("jid") == target_jid:
                    found_member = items[i]
                    found_job = job
                    break
            except: pass
        if found_member is not None or cursor == "0":
            break
    if found_member is not None:
        queue = found_job.get("queue", "default")
        rc(s, "LPUSH", "queue:" + queue, found_member)
        rr(s, bf)
        rc(s, "ZREM", q_key, found_member)
        rr(s, bf)
        s.close()
        print("ok=1")
    else:
        s.close()
        print("error=job not found")
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_retry_job(guest, service, queue_type, jid):
    """Re-enqueue a single job from a Sidekiq sorted-set queue for immediate processing.

    Returns (ok: bool, message: str).
    """
    if queue_type not in ("dead", "retry", "schedule"):
        return False, "Invalid queue type"
    if not _SIDEKIQ_JID_RE.match(jid):
        return False, "Invalid JID"
    script = _SIDEKIQ_RETRY_JOB_TEMPLATE
    script = script.replace(b"__QUEUEKEY__", repr(str(queue_type)).encode())
    script = script.replace(b"__JID__", repr(str(jid)).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            return True, "Job re-queued for immediate processing"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


def _safe_unit_name(name):
    """Validate a systemd unit name to prevent shell injection."""
    if not name or not _VALID_UNIT_RE.match(name):
        raise ValueError(f"Invalid systemd unit name: {name!r}")
    return name

def _has_valid_ip(guest):
    """Check if a guest has a usable IP address (not dhcp/auto placeholders)."""
    ip = guest.ip_address
    return bool(ip) and ip.lower() not in ("dhcp", "dhcp6", "auto")


APT_CHECK_CMD = "apt-get update -qq 2>/dev/null && apt-get -s upgrade 2>/dev/null"
APT_LIST_CMD = "apt list --upgradable 2>/dev/null"
APT_SECURITY_CMD = "apt-get -s upgrade 2>/dev/null | grep -i security"


def parse_upgradable(output):
    """Parse 'apt list --upgradable' output into package dicts."""
    packages = []
    for line in output.strip().split("\n"):
        if "/" not in line or "Listing..." in line:
            continue
        try:
            # Format: package/source version arch [upgradable from: old_version]
            name_part, rest = line.split("/", 1)
            parts = rest.split()
            available_version = parts[1] if len(parts) > 1 else "unknown"
            current_version = "unknown"
            if "upgradable from:" in line:
                current_version = line.split("upgradable from: ")[-1].rstrip("]").strip()
            packages.append({
                "name": name_part.strip(),
                "current_version": current_version,
                "available_version": available_version,
            })
        except (IndexError, ValueError) as e:
            logger.debug(f"Could not parse line: {line} ({e})")
    return packages


def determine_severity(package_name, security_output):
    """Check if a package appears in security upgrade output."""
    if security_output and package_name in security_output:
        return "critical"
    return "normal"


def _execute_on_guest(guest):
    """Execute APT commands on a guest and return (upgradable_output, security_output, error)."""
    # Try SSH first if configured
    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            # Try default credential
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and _has_valid_ip(guest):
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    # Update package lists (needs root)
                    ssh.execute_sudo("apt-get update -qq 2>/dev/null", timeout=120)
                    # Get upgradable list
                    stdout, stderr, code = ssh.execute(APT_LIST_CMD, timeout=60)
                    if code == 0:
                        # Check for security updates
                        sec_out, _, _ = ssh.execute_sudo(APT_SECURITY_CMD, timeout=60)
                        return stdout, sec_out, None
                    if guest.connection_method == "ssh":
                        return None, None, f"SSH apt list failed: {stderr}"
            except Exception as e:
                if guest.connection_method == "ssh":
                    return None, None, f"SSH failed: {e}"
                logger.debug(f"SSH failed for {guest.name}, trying agent: {e}")

    # Try QEMU guest agent
    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            # Find the node this VM is on
            all_guests = client.get_all_guests()
            node = None
            for g in all_guests:
                if g.get("vmid") == guest.vmid:
                    node = g.get("node")
                    break

            if node:
                # Update apt
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq")
                # Get upgradable
                stdout, err = client.exec_guest_agent(node, guest.vmid, "apt list --upgradable 2>/dev/null")
                if err is None:
                    sec_out, _ = client.exec_guest_agent(node, guest.vmid,
                                                         "apt-get -s upgrade 2>/dev/null | grep -i security")
                    return stdout, sec_out, None
                return None, None, f"Agent exec failed: {err}"
            return None, None, f"Could not find VM {guest.vmid} on any node"
        except Exception as e:
            return None, None, f"Agent failed: {e}"

    return None, None, "No viable connection method available"


def _execute_command(guest, command, timeout=60, sudo=False):
    """Execute a single command on a guest via SSH or agent. Returns (stdout, error).

    If sudo=True, wraps the command with sudo when connected as a non-root user.
    """
    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and _has_valid_ip(guest):
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    if sudo:
                        stdout, stderr, code = ssh.execute_sudo(command, timeout=timeout)
                    else:
                        stdout, stderr, code = ssh.execute(command, timeout=timeout)
                    if code == 0:
                        return stdout, None
                    if guest.connection_method == "ssh":
                        return stdout, stderr or f"Exit code {code}"
            except Exception as e:
                if guest.connection_method == "ssh":
                    return None, f"SSH failed: {e}"
                logger.debug(f"SSH failed for {guest.name}, trying agent: {e}")

    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                stdout, err = client.exec_guest_agent(node, guest.vmid, command)
                return stdout, err
            return None, f"Could not find VM {guest.vmid} on any node"
        except Exception as e:
            return None, f"Agent failed: {e}"

    return None, "No viable connection method available"


def _map_systemctl_status(status_str):
    """Map systemctl is-active output to our status strings."""
    if status_str == "active":
        return "running"
    elif status_str == "inactive":
        return "stopped"
    elif status_str == "failed":
        return "failed"
    return "unknown"


def detect_services(guest):
    """Detect known services on a guest via systemctl. Called during scan."""
    now = datetime.now(timezone.utc)

    # Split services into fixed and glob patterns
    fixed_services = {}
    glob_services = {}
    for key, (display_name, unit_name, default_port) in GuestService.KNOWN_SERVICES.items():
        if "*" in unit_name:
            glob_services[key] = (display_name, unit_name, default_port)
        else:
            fixed_services[key] = (display_name, unit_name, default_port)

    # Check fixed services with a single systemctl call
    if fixed_services:
        unit_names = [info[1] for info in fixed_services.values()]
        cmd = "systemctl is-active " + " ".join(unit_names) + " 2>/dev/null"
        stdout, error = _execute_command(guest, cmd)

        if stdout or not error:
            lines = (stdout or "").strip().split("\n")
            for i, (key, (_display_name, unit_name, default_port)) in enumerate(fixed_services.items()):
                status_str = lines[i].strip() if i < len(lines) else "unknown"
                status = _map_systemctl_status(status_str)
                _upsert_service(guest, key, unit_name, default_port, status, now)

    # Discover glob-pattern services (e.g., mastodon-sidekiq*.service)
    for key, (_display_name, unit_pattern, default_port) in glob_services.items():
        cmd = f"systemctl list-units '{unit_pattern}' --no-legend --plain 2>/dev/null"
        stdout, error = _execute_command(guest, cmd)
        if not stdout:
            continue
        for line in stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) < 3:
                continue
            discovered_unit = parts[0]  # e.g. mastodon-sidekiq1.service
            active_state = parts[2]     # active/inactive/failed
            status = _map_systemctl_status(active_state)
            _upsert_service(guest, key, discovered_unit, default_port, status, now)

    db.session.commit()


def _upsert_service(guest, service_key, unit_name, default_port, status, now):
    """Create or update a GuestService record."""
    try:
        _safe_unit_name(unit_name)
    except ValueError:
        logger.warning(f"Skipping service with invalid unit name: {unit_name!r}")
        return
    existing = GuestService.query.filter_by(guest_id=guest.id, unit_name=unit_name).first()
    if status in ("running", "failed"):
        if existing:
            existing.status = status
            existing.last_checked = now
        else:
            svc = GuestService(
                guest_id=guest.id,
                service_name=service_key,
                unit_name=unit_name,
                port=default_port,
                status=status,
                last_checked=now,
                auto_detected=True,
            )
            db.session.add(svc)
    elif status == "stopped" and existing:
        existing.status = status
        existing.last_checked = now


def check_service_statuses(guest):
    """Lightweight status refresh for all services on a guest."""
    if not guest.services:
        return

    unit_names = [_safe_unit_name(svc.unit_name) for svc in guest.services]
    cmd = "systemctl is-active " + " ".join(unit_names) + " 2>/dev/null"
    stdout, error = _execute_command(guest, cmd)

    if error and not stdout:
        logger.debug(f"Service status check failed for {guest.name}: {error}")
        return

    lines = (stdout or "").strip().split("\n")
    now = datetime.now(timezone.utc)

    for i, svc in enumerate(guest.services):
        status_str = lines[i].strip() if i < len(lines) else "unknown"
        if status_str == "active":
            svc.status = "running"
        elif status_str == "inactive":
            svc.status = "stopped"
        elif status_str == "failed":
            svc.status = "failed"
        else:
            svc.status = "unknown"
        svc.last_checked = now

    db.session.commit()


def service_action(guest, service, action):
    """Execute start/stop/restart on a service. Returns (success, output)."""
    if action not in ("start", "stop", "restart"):
        return False, "Invalid action"

    try:
        unit = _safe_unit_name(service.unit_name)
    except ValueError as e:
        return False, str(e)

    cmd = f"systemctl {action} {unit}"
    stdout, error = _execute_command(guest, cmd, timeout=30, sudo=True)

    if error:
        return False, error

    # Refresh status after action
    status_out, _ = _execute_command(guest, f"systemctl is-active {unit} 2>/dev/null")
    now = datetime.now(timezone.utc)
    status_str = (status_out or "").strip()
    if status_str == "active":
        service.status = "running"
    elif status_str == "inactive":
        service.status = "stopped"
    elif status_str == "failed":
        service.status = "failed"
    else:
        service.status = "unknown"
    service.last_checked = now
    db.session.commit()

    return True, stdout or f"{action.capitalize()} command sent"


def get_service_logs(guest, service, lines=50):
    """Fetch recent journal logs for a service. Returns log text."""
    try:
        unit = _safe_unit_name(service.unit_name)
    except ValueError as e:
        return f"Error: {e}"
    lines = int(lines)
    cmd = f"journalctl -u {unit} -n {lines} --no-pager 2>/dev/null"
    stdout, error = _execute_command(guest, cmd, timeout=30)
    if error:
        return f"Error fetching logs: {error}"

    # postgresql.service is a meta/target unit on Debian/Ubuntu; its journal has
    # very few entries.  Fall back to the real cluster unit for useful log output.
    if service.service_name == "postgresql" and (
        not stdout or "No entries" in stdout or not stdout.strip()
    ):
        cluster_out, _ = _execute_command(
            guest,
            "systemctl list-units 'postgresql@*.service' --no-legend --plain 2>/dev/null",
            timeout=10,
        )
        if cluster_out:
            first_line = cluster_out.strip().split("\n")[0].strip()
            cluster_unit = first_line.split()[0] if first_line else ""
            if cluster_unit and _VALID_UNIT_RE.match(cluster_unit):
                cmd2 = f"journalctl -u {cluster_unit} -n {lines} --no-pager 2>/dev/null"
                stdout2, _ = _execute_command(guest, cmd2, timeout=30)
                if stdout2 and stdout2.strip():
                    return stdout2

    return stdout or "No log output"


def _parse_systemd_props(output):
    """Parse systemctl show output into a dict."""
    props = {}
    for line in (output or "").strip().split("\n"):
        if "=" in line:
            key, _, val = line.partition("=")
            props[key.strip()] = val.strip()
    return props


def _human_bytes(n):
    """Convert bytes to human-readable string."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _parse_redis_info(output):
    """Parse redis-cli info output into a dict."""
    info = {}
    for line in (output or "").strip().split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


def get_service_stats(guest, service):
    """Fetch service-specific stats via SSH. Returns a dict with stats and a 'type' key."""

    stype = service.service_name
    stats = {"type": stype, "error": None}

    # Common: get systemd resource usage
    unit = _safe_unit_name(service.unit_name)
    props_cmd = f"systemctl show {unit} --property=MemoryCurrent,CPUUsageNSec,MainPID,ActiveState,ActiveEnterTimestamp 2>/dev/null"
    props_out, _ = _execute_command(guest, props_cmd, timeout=15)
    props = _parse_systemd_props(props_out)

    mem_current = props.get("MemoryCurrent", "")
    if mem_current and mem_current not in ("[not set]", "infinity", ""):
        try:
            stats["memory_bytes"] = int(mem_current)
            stats["memory_human"] = _human_bytes(int(mem_current))
        except ValueError:
            pass

    cpu_ns = props.get("CPUUsageNSec", "")
    if cpu_ns and cpu_ns not in ("[not set]", ""):
        try:
            secs = int(cpu_ns) / 1_000_000_000
            if secs >= 3600:
                stats["cpu_time"] = f"{secs / 3600:.1f}h"
            elif secs >= 60:
                stats["cpu_time"] = f"{secs / 60:.1f}m"
            else:
                stats["cpu_time"] = f"{secs:.1f}s"
        except ValueError:
            pass

    main_pid = props.get("MainPID", "")
    stats["pid"] = main_pid if main_pid and main_pid != "0" else ""
    stats["active_state"] = props.get("ActiveState", "")
    active_enter = props.get("ActiveEnterTimestamp", "")
    if active_enter and active_enter not in ("n/a", ""):
        stats["started_at"] = active_enter

    # Service-specific stats
    try:
        if stype == "elasticsearch":
            stats.update(_stats_elasticsearch(guest, service))
        elif stype == "redis":
            stats.update(_stats_redis(guest, service))
        elif stype == "postgresql":
            stats.update(_stats_postgresql(guest))
        elif stype == "puma":
            stats.update(_stats_puma(guest, service))
        elif stype == "sidekiq":
            stats.update(_stats_sidekiq(guest, service))
        elif stype == "libretranslate":
            stats.update(_stats_libretranslate(guest, service))
    except Exception as e:
        logger.error(f"Error collecting {stype} stats for {guest.name}: {e}")
        stats["error"] = str(e)

    return stats


def _stats_elasticsearch(guest, service):
    """Collect Elasticsearch stats."""
    import json as _json
    port = service.port or 9200
    stats = {}

    # Cluster health
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_cluster/health 2>/dev/null", timeout=15)
    if out:
        try:
            health = _json.loads(out)
            stats["cluster_status"] = health.get("status", "unknown")
            stats["cluster_name"] = health.get("cluster_name", "")
            stats["node_count"] = health.get("number_of_nodes", 0)
            stats["active_shards"] = health.get("active_shards", 0)
            stats["relocating_shards"] = health.get("relocating_shards", 0)
            stats["unassigned_shards"] = health.get("unassigned_shards", 0)
        except _json.JSONDecodeError:
            pass

    # Cluster stats (doc count, store size)
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_cluster/stats 2>/dev/null", timeout=15)
    if out:
        try:
            cstats = _json.loads(out)
            indices = cstats.get("indices", {})
            stats["index_count"] = indices.get("count", 0)
            docs = indices.get("docs", {})
            stats["doc_count"] = docs.get("count", 0)
            store = indices.get("store", {})
            stats["store_size_bytes"] = store.get("size_in_bytes", 0)
            stats["store_size"] = _human_bytes(store.get("size_in_bytes", 0))
        except _json.JSONDecodeError:
            pass

    # JVM heap
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_nodes/stats/jvm 2>/dev/null", timeout=15)
    if out:
        try:
            jvm_data = _json.loads(out)
            nodes = jvm_data.get("nodes", {})
            total_heap_used = 0
            total_heap_max = 0
            for node_info in nodes.values():
                jvm = node_info.get("jvm", {}).get("mem", {})
                total_heap_used += jvm.get("heap_used_in_bytes", 0)
                total_heap_max += jvm.get("heap_max_in_bytes", 0)
            stats["jvm_heap_used"] = _human_bytes(total_heap_used)
            stats["jvm_heap_max"] = _human_bytes(total_heap_max)
            if total_heap_max > 0:
                stats["jvm_heap_percent"] = round(total_heap_used / total_heap_max * 100, 1)
        except _json.JSONDecodeError:
            pass

    # Per-index stats
    out, _ = _execute_command(guest, f"curl -s 'localhost:{port}/_cat/indices?format=json&h=index,health,docs.count,store.size' 2>/dev/null", timeout=15)
    if out:
        try:
            stats["indices"] = _json.loads(out)
        except _json.JSONDecodeError:
            pass

    return stats


def _stats_redis(guest, service):
    """Collect Redis stats."""
    stats = {}
    port = service.port or 6379

    # Single SSH call: detect password, then run redis-cli info all.
    #
    # Password detection order:
    #   1. requirepass in Redis server config files
    #   2. REDIS_PASSWORD in Mastodon .env.production (multiple common paths)
    #
    # REDISCLI_AUTH env var is used so the password never appears in the
    # process list via -a.  || true forces exit 0 so _execute_command in
    # auto connection mode (LXC containers) returns stdout rather than
    # discarding it and falling through to the QEMU guest agent.
    redis_script = (
        "_RP=\"\";"
        " for _F in /etc/redis/redis.conf /etc/redis/redis-server.conf /etc/redis.conf; do"
        "   _RP=$(grep -i \"^requirepass\" \"$_F\" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\"');"
        "   [ -n \"$_RP\" ] && break;"
        " done;"
        " [ -z \"$_RP\" ] && _RP=$(grep \"^REDIS_PASSWORD=\""
        " /home/mastodon/live/.env.production"
        " /var/www/mastodon/.env.production"
        " /opt/mastodon/.env.production"
        " 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"');"
        f" REDISCLI_AUTH=\"$_RP\" redis-cli -p {port} info all 2>/dev/null || true"
    )

    out, _ = _execute_command(guest, redis_script, timeout=30, sudo=True)
    info = _parse_redis_info(out)

    if info:
        # Memory
        stats["used_memory"] = info.get("used_memory_human", "")
        stats["used_memory_peak"] = info.get("used_memory_peak_human", "")
        stats["used_memory_bytes"] = info.get("used_memory", "0")
        stats["maxmemory"] = info.get("maxmemory_human", "0B")
        # Clients
        stats["connected_clients"] = info.get("connected_clients", "0")
        # Stats
        stats["ops_per_sec"] = info.get("instantaneous_ops_per_sec", "0")
        hits = int(info.get("keyspace_hits", 0) or 0)
        misses = int(info.get("keyspace_misses", 0) or 0)
        total = hits + misses
        stats["keyspace_hits"] = hits
        stats["keyspace_misses"] = misses
        stats["hit_ratio"] = f"{(hits / total * 100):.1f}%" if total > 0 else "N/A"
        stats["total_commands"] = info.get("total_commands_processed", "0")

    # Keyspace (always set, may be empty)
    keyspace = {}
    for key, val in info.items():
        if key.startswith("db"):
            keyspace[key] = val
    stats["keyspace"] = keyspace

    return stats


def _stats_postgresql(guest):
    """Collect PostgreSQL stats."""
    stats = {}

    # Database sizes
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT datname, pg_database_size(datname) FROM pg_database WHERE datistemplate = false\" 2>/dev/null",
        timeout=15, sudo=True)
    if out:
        databases = []
        for line in out.strip().split("\n"):
            parts = line.strip().split("|")
            if len(parts) == 2:
                databases.append({
                    "name": parts[0],
                    "size_bytes": int(parts[1]) if parts[1].isdigit() else 0,
                    "size": _human_bytes(int(parts[1]) if parts[1].isdigit() else 0),
                })
        stats["databases"] = databases

    # Active query count
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT count(*) FROM pg_stat_activity WHERE state = 'active'\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["active_queries"] = out.strip()

    # Active/non-idle query list with durations
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT datname, usename, state, "
        "round(extract(epoch from (now() - query_start))::numeric, 1), "
        "replace(replace(left(query, 200), chr(10), ' '), chr(13), ' ') "
        "FROM pg_stat_activity WHERE pid != pg_backend_pid() "
        "AND state IS NOT NULL AND state != 'idle' "
        "ORDER BY (now() - query_start) DESC NULLS LAST"
        "\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        query_list = []
        for line in out.strip().split("\n"):
            parts = line.strip().split("|", 4)
            if len(parts) == 5:
                try:
                    secs = float(parts[3])
                except ValueError:
                    secs = 0.0
                if secs >= 3600:
                    duration = f"{int(secs // 3600)}h {int((secs % 3600) // 60)}m"
                elif secs >= 60:
                    duration = f"{int(secs // 60)}m {int(secs % 60)}s"
                else:
                    duration = f"{secs:.1f}s"
                query_list.append({
                    "datname": parts[0] or "—",
                    "usename": parts[1] or "—",
                    "state": parts[2],
                    "duration": duration,
                    "duration_secs": secs,
                    "query": parts[4],
                })
        stats["active_query_list"] = query_list

    # Total connections
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT sum(numbackends) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["total_connections"] = out.strip()

    # Max connections
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SHOW max_connections\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["max_connections"] = out.strip()

    # Cache hit ratio
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT round(sum(blks_hit)::numeric / nullif(sum(blks_hit) + sum(blks_read), 0) * 100, 2) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out and out.strip():
        stats["cache_hit_ratio"] = f"{out.strip()}%"

    # Transactions
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT sum(xact_commit), sum(xact_rollback) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        parts = out.strip().split("|")
        if len(parts) == 2:
            stats["total_commits"] = parts[0].strip()
            stats["total_rollbacks"] = parts[1].strip()

    # postgresql.service is a meta/target unit on Debian/Ubuntu with no MainPID.
    # Discover the real cluster unit (e.g. postgresql@16-main.service) to get
    # accurate memory, CPU, and PID stats.
    cluster_out, _ = _execute_command(
        guest,
        "systemctl list-units 'postgresql@*.service' --no-legend --plain 2>/dev/null",
        timeout=10,
    )
    if cluster_out:
        first_line = cluster_out.strip().split("\n")[0].strip()
        cluster_unit = first_line.split()[0] if first_line else ""
        if cluster_unit and _VALID_UNIT_RE.match(cluster_unit):
            cprops_out, _ = _execute_command(
                guest,
                f"systemctl show {cluster_unit} --property=MemoryCurrent,CPUUsageNSec,MainPID 2>/dev/null",
                timeout=10,
            )
            cprops = _parse_systemd_props(cprops_out)

            mem = cprops.get("MemoryCurrent", "")
            if mem and mem not in ("[not set]", "infinity", ""):
                try:
                    stats["memory_bytes"] = int(mem)
                    stats["memory_human"] = _human_bytes(int(mem))
                except ValueError:
                    pass

            cpu_ns = cprops.get("CPUUsageNSec", "")
            if cpu_ns and cpu_ns not in ("[not set]", ""):
                try:
                    secs = int(cpu_ns) / 1_000_000_000
                    if secs >= 3600:
                        stats["cpu_time"] = f"{secs / 3600:.1f}h"
                    elif secs >= 60:
                        stats["cpu_time"] = f"{secs / 60:.1f}m"
                    else:
                        stats["cpu_time"] = f"{secs:.1f}s"
                except ValueError:
                    pass

            main_pid = cprops.get("MainPID", "")
            if main_pid and main_pid != "0":
                stats["pid"] = main_pid

    return stats


def _stats_puma(guest, service):
    """Collect Puma/mastodon-web stats."""
    stats = {}
    port = service.port or 3000

    # Health endpoint
    out, _ = _execute_command(guest, f"curl -s -o /dev/null -w '%{{http_code}}' localhost:{port}/health 2>/dev/null", timeout=10)
    if out:
        stats["health_status"] = "OK" if out.strip() == "200" else f"HTTP {out.strip()}"

    return stats


def _stats_sidekiq(guest, service):
    """Collect Sidekiq stats — per-instance systemd info plus aggregate queue stats from Redis."""
    stats = {}

    # Use a pure-Python3 Redis client (no redis-cli needed) — Sidekiq servers
    # connect to Redis via the Ruby gem so redis-cli is often absent.
    # The script is base64-encoded to avoid any shell quoting issues.
    _py_b64 = base64.b64encode(_SIDEKIQ_REDIS_SCRIPT).decode()
    redis_script = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"

    out, _ = _execute_command(guest, redis_script, timeout=30)

    queues = []
    kv = {}
    debug_kv = {}
    section = None
    for line in (out or "").split("\n"):
        line = line.strip()
        if line == "---queues---":
            section = "queues"
        elif line == "---stats---":
            section = "stats"
        elif line == "---debug---":
            section = "debug"
        elif section == "queues" and "=" in line:
            name, _, rest = line.partition("=")
            size_str, _, lat_str = rest.strip().partition("|")
            size = int(size_str) if size_str.isdigit() else 0
            try:
                lat_secs = float(lat_str) if lat_str else 0.0
            except ValueError:
                lat_secs = 0.0
            queues.append({
                "name": name.strip(),
                "size": size,
                "latency_secs": lat_secs,
                "latency": _format_elapsed(lat_secs) if lat_secs > 0 else ("< 1s" if size > 0 else "—"),
            })
        elif section == "stats" and "=" in line:
            key, _, val = line.partition("=")
            kv[key.strip()] = val.strip()
        elif section == "debug" and "=" in line:
            key, _, val = line.partition("=")
            debug_kv[key.strip()] = val.strip()

    stats["queues"] = queues
    stats["_debug"] = debug_kv  # connection params for troubleshooting (host/port/db/auth_set)
    stats["processed"] = kv.get("processed", "0") if kv.get("processed", "") not in ("(nil)", "", None) else "0"
    stats["failed"] = kv.get("failed", "0") if kv.get("failed", "") not in ("(nil)", "", None) else "0"
    stats["retry_size"] = kv.get("retry", "0") if (kv.get("retry", "") or "").isdigit() else "0"
    stats["dead_size"] = kv.get("dead", "0") if (kv.get("dead", "") or "").isdigit() else "0"
    stats["scheduled_size"] = kv.get("scheduled", "0") if (kv.get("scheduled", "") or "").isdigit() else "0"

    # Per-instance systemd stats — batched into a single SSH call
    sibling_services = GuestService.query.filter_by(guest_id=guest.id, service_name="sidekiq").all()
    instances = []
    if sibling_services:
        unit_names = []
        valid_svcs = []
        for svc in sibling_services:
            try:
                unit_names.append(_safe_unit_name(svc.unit_name))
                valid_svcs.append(svc)
            except ValueError:
                continue

        if unit_names:
            units_str = " ".join(unit_names)
            batch_cmd = (
                f"for _U in {units_str}; do"
                " echo \"---unit:$_U---\";"
                " systemctl show \"$_U\" --property=MemoryCurrent,CPUUsageNSec,ActiveState,MainPID 2>/dev/null || true;"
                " done"
            )
            batch_out, _ = _execute_command(guest, batch_cmd, timeout=20)
            # Split output by unit markers
            current_unit = None
            unit_props = {}
            for line in (batch_out or "").split("\n"):
                line = line.strip()
                if line.startswith("---unit:") and line.endswith("---"):
                    current_unit = line[8:-3]
                    unit_props[current_unit] = {}
                elif current_unit and "=" in line:
                    k, _, v = line.partition("=")
                    unit_props[current_unit][k.strip()] = v.strip()

            for svc, unit in zip(valid_svcs, unit_names, strict=False):
                p = unit_props.get(unit, {})
                mem = p.get("MemoryCurrent", "")
                mem_human = ""
                if mem and mem not in ("[not set]", "infinity", ""):
                    try:
                        mem_human = _human_bytes(int(mem))
                    except ValueError:
                        pass
                instances.append({
                    "unit_name": svc.unit_name,
                    "status": _map_systemctl_status(p.get("ActiveState", "unknown")),
                    "pid": p.get("MainPID", ""),
                    "memory": mem_human,
                })

    stats["instances"] = instances
    return stats


# Pure-Python3 script to health-check LibreTranslate.  Tries four candidate
# URLs in order (localhost + configured port, localhost:80, guest-IP + configured
# port, guest-IP:80) so it works regardless of whether a reverse proxy is in
# front, and without requiring curl on the target host.
# Placeholders __HOST__ and __PORT__ are replaced at call time.
_LT_FETCH_SCRIPT_TPL = b"""\
import urllib.request as _ur, sys as _sys
_h = '__HOST__'
_p = __PORT__
_seen = set()
for _url in [
    'http://localhost:{}/languages'.format(_p),
    'http://localhost:80/languages',
    'http://{}:{}/languages'.format(_h, _p),
    'http://{}:80/languages'.format(_h),
]:
    if _url in _seen:
        continue
    _seen.add(_url)
    try:
        _r = _ur.urlopen(_url, timeout=3)
        print(str(_r.status))
        print(_r.read().decode('utf-8', 'replace')[:16384])
        _sys.exit(0)
    except Exception:
        pass
print('0')
print('')
"""


def _stats_libretranslate(guest, service):
    """Collect LibreTranslate stats.

    Uses a base64-encoded Python3 script (no curl dependency) that tries
    localhost and the guest's own IP on both the configured port and port 80.
    """
    import json as _json
    stats = {}
    port = service.port or 5000
    host = guest.ip_address or "127.0.0.1"

    script = _LT_FETCH_SCRIPT_TPL
    script = script.replace(b"__HOST__", host.encode())
    script = script.replace(b"__PORT__", str(port).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null"

    out, _ = _execute_command(guest, cmd, timeout=20)
    if out:
        status_line, _, body = out.strip().partition('\n')
        status = status_line.strip()
        body = body.strip()

        stats["health_status"] = "OK" if status == "200" else f"HTTP {status}" if status not in ("", "0") else "unreachable"

        if body:
            try:
                langs = _json.loads(body)
                if isinstance(langs, list):
                    stats["languages_count"] = len(langs)
                    stats["languages"] = [
                        lang.get("name", lang.get("code", ""))
                        for lang in langs[:20]
                        if isinstance(lang, dict)
                    ]
            except Exception:
                pass
    else:
        stats["health_status"] = "unreachable"

    return stats


# --- LibreTranslate package management scripts ---
# _LT_PATH_SETUP is prepended to every script. It uses two strategies to add
# the argostranslate site-packages to sys.path regardless of where the
# LibreTranslate virtualenv lives:
#   1. Broad glob covering all common installation patterns
#   2. subprocess `find` fallback — only runs if the glob still can't locate
#      argostranslate, so there's no overhead in the normal case.
_LT_PATH_SETUP = b"""\
import sys, os, glob, json
for _pat in [
    '/home/*/venv/lib/python*/site-packages',
    '/home/*/.venv/lib/python*/site-packages',
    '/home/*/.local/lib/python*/site-packages',
    '/opt/*/venv/lib/python*/site-packages',
    '/opt/*/lib/python*/site-packages',
    '/root/.local/lib/python*/site-packages',
    '/root/.local/pipx/venvs/*/lib/python*/site-packages',
    '/srv/*/venv/lib/python*/site-packages',
    '/var/*/venv/lib/python*/site-packages',
    '/usr/local/lib/python*/dist-packages',
    '/usr/local/lib/python*/site-packages',
    '/usr/lib/python3/dist-packages',
]:
    for _p in glob.glob(_pat):
        if _p not in sys.path: sys.path.insert(0, _p)
try:
    import argostranslate as _at_probe
    del _at_probe
except ImportError:
    import subprocess as _sp
    try:
        _r = _sp.run(
            'find /home /opt /root /var /usr/local /usr/lib /srv -maxdepth 10 '
            '-name "argostranslate" -type d 2>/dev/null | head -1',
            shell=True, capture_output=True, text=True, timeout=15)
        _d = _r.stdout.strip()
        if _d and os.path.isfile(os.path.join(_d, '__init__.py')):
            _site = os.path.dirname(_d)
            if _site not in sys.path: sys.path.insert(0, _site)
    except Exception:
        pass
"""

_LT_LIST_INSTALLED_SCRIPT = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    # Compare against locally-cached available packages (no network call) to
    # detect outdated versions. If no local cache exists, outdated stays False.
    _avail_ver = {}
    try:
        _avail_ver = {(p.from_code, p.to_code): p.package_version
                      for p in _pkg.get_available_packages()}
    except Exception:
        pass
    _pkgs = []
    for p in _pkg.get_installed_packages():
        _ver = getattr(p, 'package_version', None)
        _avail = _avail_ver.get((p.from_code, p.to_code))
        _pkgs.append({
            'from_code': p.from_code, 'to_code': p.to_code,
            'from_name': p.from_name, 'to_name': p.to_name,
            'version': _ver,
            'outdated': bool(_avail and _ver and _avail != _ver),
        })
    print(json.dumps({'packages': _pkgs}))
except Exception as _e:
    print(json.dumps({'error': str(_e)}))
"""

_LT_LIST_AVAILABLE_SCRIPT = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    _pkg.update_package_index()
    _installed = {(p.from_code, p.to_code) for p in _pkg.get_installed_packages()}
    print(json.dumps({'packages': [
        {'from_code': p.from_code, 'to_code': p.to_code,
         'from_name': p.from_name, 'to_name': p.to_name,
         'installed': (p.from_code, p.to_code) in _installed}
        for p in _pkg.get_available_packages()
    ]}))
except Exception as _e:
    print(json.dumps({'error': str(_e)}))
"""

# Placeholders __FROM__ and __TO__ replaced at call time (validated as lang codes).
_LT_INSTALL_PACKAGE_SCRIPT_TPL = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    _pkg.update_package_index()
    _from, _to = '__FROM__', '__TO__'
    for _p in _pkg.get_available_packages():
        if _p.from_code == _from and _p.to_code == _to:
            _p.install()
            print(json.dumps({'ok': True, 'message': 'Installed {}->{}'.format(_from, _to)}))
            raise SystemExit
    print(json.dumps({'ok': False, 'message': 'Package not found: {}->{}'.format(_from, _to)}))
except SystemExit:
    pass
except Exception as _e:
    print(json.dumps({'ok': False, 'message': str(_e)}))
"""

_LT_UPDATE_ALL_SCRIPT = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    _pkg.update_package_index()
    _avail = {(p.from_code, p.to_code): p for p in _pkg.get_available_packages()}
    _n = 0
    for _inst in _pkg.get_installed_packages():
        _key = (_inst.from_code, _inst.to_code)
        if _key in _avail:
            _avail[_key].install()
            _n += 1
    print(json.dumps({'ok': True, 'updated': _n, 'message': 'Updated {} package(s)'.format(_n)}))
except Exception as _e:
    print(json.dumps({'ok': False, 'updated': 0, 'message': str(_e)}))
"""

_LANG_CODE_RE = re.compile(r'^[a-z]{2,8}$')


def _lt_run(guest, script_bytes, timeout=60):
    """Base64-encode a script and run it via SSH using system python3.

    argostranslate discovery is handled inside the script itself via
    _LT_PATH_SETUP (broad glob + find fallback).
    """
    _py_b64 = base64.b64encode(script_bytes).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null"
    out, err = _execute_command(guest, cmd, timeout=timeout)
    if err and not out:
        raise RuntimeError(err)
    return json.loads((out or "").strip())


def lt_list_installed(guest, service):
    """List installed LibreTranslate language packages. Returns (packages, error)."""
    try:
        data = _lt_run(guest, _LT_LIST_INSTALLED_SCRIPT, timeout=30)
        if "error" in data:
            return [], data["error"]
        return data.get("packages", []), None
    except Exception as e:
        return [], str(e)


def lt_list_available(guest, service):
    """Fetch available LibreTranslate packages from the Argos index. Returns (packages, error)."""
    try:
        data = _lt_run(guest, _LT_LIST_AVAILABLE_SCRIPT, timeout=60)
        if "error" in data:
            return [], data["error"]
        return data.get("packages", []), None
    except Exception as e:
        return [], str(e)


def lt_install_package(guest, service, from_code, to_code):
    """Install a single LibreTranslate language pair. Returns (ok, message)."""
    if not _LANG_CODE_RE.match(from_code) or not _LANG_CODE_RE.match(to_code):
        return False, "Invalid language code"
    script = _LT_INSTALL_PACKAGE_SCRIPT_TPL
    script = script.replace(b"__FROM__", from_code.encode())
    script = script.replace(b"__TO__", to_code.encode())
    try:
        data = _lt_run(guest, script, timeout=300)
        return data.get("ok", False), data.get("message", "Unknown error")
    except Exception as e:
        return False, str(e)


def lt_update_all_packages(guest, service):
    """Re-install the latest version of every installed language package. Returns (ok, message, count)."""
    try:
        data = _lt_run(guest, _LT_UPDATE_ALL_SCRIPT, timeout=600)
        return data.get("ok", False), data.get("message", "Unknown error"), data.get("updated", 0)
    except Exception as e:
        return False, str(e), 0


def check_reboot_required(guest):
    """Check if a guest needs a reboot (Debian/Ubuntu: /var/run/reboot-required)."""
    stdout, error = _execute_command(guest, "[ -f /var/run/reboot-required ] && echo yes || echo no")
    if not error and stdout:
        guest.reboot_required = stdout.strip() == "yes"
        db.session.commit()


def scan_guest(guest):
    """Scan a single guest for updates. Returns ScanResult."""
    logger.info(f"Scanning {guest.name} ({guest.guest_type})...")

    upgradable_output, security_output, error = _execute_on_guest(guest)

    now = datetime.now(timezone.utc)

    if error:
        logger.error(f"Scan failed for {guest.name}: {error}")
        result = ScanResult(
            guest_id=guest.id,
            scanned_at=now,
            total_updates=0,
            security_updates=0,
            status="error",
            error_message=error,
        )
        guest.status = "error"
        guest.last_scan = now
        db.session.add(result)
        db.session.commit()
        return result

    # Parse packages
    packages = parse_upgradable(upgradable_output or "")

    # Clear old pending updates for this guest
    UpdatePackage.query.filter_by(guest_id=guest.id, status="pending").delete()

    security_count = 0
    for pkg in packages:
        severity = determine_severity(pkg["name"], security_output)
        if severity == "critical":
            security_count += 1

        update = UpdatePackage(
            guest_id=guest.id,
            package_name=pkg["name"],
            current_version=pkg["current_version"],
            available_version=pkg["available_version"],
            severity=severity,
            discovered_at=now,
            status="pending",
        )
        db.session.add(update)

    result = ScanResult(
        guest_id=guest.id,
        scanned_at=now,
        total_updates=len(packages),
        security_updates=security_count,
        status="success",
    )

    guest.status = "updates-available" if packages else "up-to-date"
    guest.last_scan = now

    db.session.add(result)
    db.session.commit()

    logger.info(f"Scan complete for {guest.name}: {len(packages)} updates ({security_count} security)")

    # Auto-detect services during scan
    try:
        detect_services(guest)
    except Exception as e:
        logger.debug(f"Service detection failed for {guest.name}: {e}")

    # Check if guest needs a reboot
    try:
        check_reboot_required(guest)
    except Exception as e:
        logger.debug(f"Reboot check failed for {guest.name}: {e}")

    return result


def scan_all_guests():
    """Scan all enabled guests."""
    guests = Guest.query.filter_by(enabled=True).all()
    results = []
    for guest in guests:
        try:
            result = scan_guest(guest)
            results.append(result)
        except Exception as e:
            logger.error(f"Unexpected error scanning {guest.name}: {e}")
    return results


def apply_updates(guest, dist_upgrade=False):
    """Apply pending updates to a guest."""
    cmd = "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y" if dist_upgrade else "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"

    logger.info(f"Applying updates to {guest.name} (dist_upgrade={dist_upgrade})...")

    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential:
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    ssh.execute_sudo("apt-get update -qq", timeout=120)
                    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=600)
                    if code == 0:
                        # Mark all pending as applied
                        now = datetime.now(timezone.utc)
                        for pkg in guest.pending_updates():
                            pkg.status = "applied"
                            pkg.applied_at = now
                        guest.status = "up-to-date"
                        db.session.commit()
                        try:
                            check_reboot_required(guest)
                        except Exception:
                            pass
                        return True, stdout
                    return False, stderr
            except Exception as e:
                return False, str(e)

    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            all_guests = client.get_all_guests()
            node = None
            for g in all_guests:
                if g.get("vmid") == guest.vmid:
                    node = g.get("node")
                    break
            if node:
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq")
                stdout, err = client.exec_guest_agent(node, guest.vmid, cmd)
                if err is None:
                    now = datetime.now(timezone.utc)
                    for pkg in guest.pending_updates():
                        pkg.status = "applied"
                        pkg.applied_at = now
                    guest.status = "up-to-date"
                    db.session.commit()
                    try:
                        check_reboot_required(guest)
                    except Exception:
                        pass
                    return True, stdout
                return False, err
        except Exception as e:
            return False, str(e)

    return False, "No viable connection method"


# --- Mastodon Overview Stats ---

# Pure-Python3 Redis client script to collect INFO memory/stats/clients.
# Same connection discovery pattern as _SIDEKIQ_REDIS_SCRIPT.
_MASTODON_REDIS_INFO_SCRIPT = b"""\
import socket, urllib.parse as up

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    rc(s, "INFO", "memory")
    rc(s, "INFO", "stats")
    rc(s, "INFO", "clients")
    mem_info = rr(s, bf) or ""
    stats_info = rr(s, bf) or ""
    clients_info = rr(s, bf) or ""
    s.close()
    for line in (mem_info + "\\n" + stats_info + "\\n" + clients_info).splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            print(line)
except Exception as e:
    print("redis_error={}".format(str(e)[:120]))
"""


def _format_bytes(n):
    """Return a human-readable byte count string."""
    if n is None:
        return "N/A"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def get_mastodon_overview_stats(mastodon_guest, db_guest, app_dir="/home/mastodon/live", user="mastodon"):
    """Collect Mastodon instance overview statistics.

    Makes up to 3 SSH calls:
      1. grep .env.production on mastodon_guest for domain/db_name/registrations_mode
      2. Batched PostgreSQL UNION ALL for 13 metrics on db_guest
      3. Redis INFO (memory, stats, clients) on mastodon_guest

    Returns a dict with all metrics; partial results on failure with errors list.
    """
    result = {
        "domain": "",
        "db_name": "",
        "registrations_mode": "",
        "local_users": None,
        "active_users": None,
        "mau": None,
        "wau": None,
        "new_users_month": None,
        "local_statuses": None,
        "statuses_7d": None,
        "statuses_30d": None,
        "media_count": None,
        "media_size_bytes": None,
        "media_size_human": "N/A",
        "known_instances": None,
        "remote_accounts": None,
        "db_size_bytes": None,
        "db_size_human": "N/A",
        "redis_memory_human": "N/A",
        "redis_memory_peak_human": "N/A",
        "redis_clients": None,
        "redis_hit_rate": "N/A",
        "errors": [],
    }

    # --- Call 1: Parse .env.production ---
    if mastodon_guest:
        try:
            stdout, error = _execute_command(
                mastodon_guest,
                f"grep -E '^(LOCAL_DOMAIN|DB_NAME|REGISTRATIONS_MODE|SINGLE_USER_MODE)=' "
                f"{app_dir}/.env.production 2>/dev/null",
                timeout=15,
                sudo=True,
            )
            if stdout and not error:
                for line in stdout.splitlines():
                    line = line.strip()
                    if "=" in line:
                        k, _, v = line.partition("=")
                        k = k.strip()
                        v = v.strip().strip("\"'")
                        if k == "LOCAL_DOMAIN":
                            result["domain"] = v
                        elif k == "DB_NAME":
                            result["db_name"] = v
                        elif k == "REGISTRATIONS_MODE":
                            result["registrations_mode"] = v
            elif error:
                result["errors"].append(f"env parse: {error[:100]}")
        except Exception as e:
            result["errors"].append(f"env parse: {str(e)[:100]}")

    db_name = result["db_name"] or "mastodon_production"

    # --- Call 2: Batched PostgreSQL UNION ALL ---
    if db_guest:
        sql = (
            "SELECT key || '=' || val FROM ("
            "SELECT 'local_users',      count(*)::text FROM accounts WHERE domain IS NULL"
            " UNION ALL "
            "SELECT 'active_users',     count(*)::text FROM accounts a JOIN users u ON u.account_id = a.id WHERE a.domain IS NULL AND a.suspended_at IS NULL AND u.confirmed_at IS NOT NULL"
            " UNION ALL "
            "SELECT 'mau',              count(DISTINCT u.account_id)::text FROM users u WHERE u.current_sign_in_at > NOW() - INTERVAL '30 days'"
            " UNION ALL "
            "SELECT 'wau',              count(DISTINCT u.account_id)::text FROM users u WHERE u.current_sign_in_at > NOW() - INTERVAL '7 days'"
            " UNION ALL "
            "SELECT 'new_users_month',  count(*)::text FROM users WHERE created_at > NOW() - INTERVAL '30 days'"
            " UNION ALL "
            "SELECT 'local_statuses',   count(*)::text FROM statuses WHERE local = true"
            " UNION ALL "
            "SELECT 'statuses_7d',      count(*)::text FROM statuses WHERE local = true AND created_at > NOW() - INTERVAL '7 days'"
            " UNION ALL "
            "SELECT 'statuses_30d',     count(*)::text FROM statuses WHERE local = true AND created_at > NOW() - INTERVAL '30 days'"
            " UNION ALL "
            "SELECT 'known_instances',  count(*)::text FROM instances WHERE domain IS NOT NULL"
            " UNION ALL "
            "SELECT 'remote_accounts',  count(*)::text FROM accounts WHERE domain IS NOT NULL AND suspended_at IS NULL"
            " UNION ALL "
            "SELECT 'media_count',      count(*)::text FROM media_attachments WHERE account_id IN (SELECT id FROM accounts WHERE domain IS NULL) AND deleted_at IS NULL"
            " UNION ALL "
            "SELECT 'media_size_bytes', coalesce(sum(file_file_size + coalesce(thumbnail_file_size,0)),0)::text FROM media_attachments WHERE account_id IN (SELECT id FROM accounts WHERE domain IS NULL) AND deleted_at IS NULL"
            " UNION ALL "
            "SELECT 'db_size_bytes',    pg_database_size(current_database())::text"
            ") t(key, val)"
        )
        sql_escaped = sql.replace("'", "'\\''")
        cmd = f"sudo -u postgres psql -t -A -d {db_name} -c '{sql_escaped}'"
        try:
            stdout, error = _execute_command(db_guest, cmd, timeout=60)
            if stdout and not error:
                for line in stdout.splitlines():
                    line = line.strip()
                    if "=" in line:
                        k, _, v = line.partition("=")
                        k = k.strip()
                        v = v.strip()
                        if k in result and v.lstrip("-").isdigit():
                            result[k] = int(v)
                if result["media_size_bytes"] is not None:
                    result["media_size_human"] = _format_bytes(result["media_size_bytes"])
                if result["db_size_bytes"] is not None:
                    result["db_size_human"] = _format_bytes(result["db_size_bytes"])
            elif error:
                result["errors"].append(f"db stats: {error[:100]}")
        except Exception as e:
            result["errors"].append(f"db stats: {str(e)[:100]}")

    # --- Call 3: Redis INFO ---
    if mastodon_guest:
        try:
            _py_b64 = base64.b64encode(_MASTODON_REDIS_INFO_SCRIPT).decode()
            cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null"
            stdout, error = _execute_command(mastodon_guest, cmd, timeout=20)
            if stdout:
                redis_data = {}
                for line in stdout.splitlines():
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        k, _, v = line.partition(":")
                        redis_data[k.strip()] = v.strip()
                    elif "=" in line:
                        k, _, v = line.partition("=")
                        redis_data[k.strip()] = v.strip()

                used_mem = redis_data.get("used_memory")
                peak_mem = redis_data.get("used_memory_peak")
                if used_mem and used_mem.isdigit():
                    result["redis_memory_human"] = _format_bytes(int(used_mem))
                if peak_mem and peak_mem.isdigit():
                    result["redis_memory_peak_human"] = _format_bytes(int(peak_mem))

                clients = redis_data.get("connected_clients")
                if clients and clients.isdigit():
                    result["redis_clients"] = int(clients)

                hits = redis_data.get("keyspace_hits")
                misses = redis_data.get("keyspace_misses")
                if hits and misses and hits.isdigit() and misses.isdigit():
                    h, m = int(hits), int(misses)
                    total = h + m
                    result["redis_hit_rate"] = f"{h / total * 100:.1f}%" if total > 0 else "N/A"

                if "redis_error" in redis_data:
                    result["errors"].append(f"redis: {redis_data['redis_error']}")
        except Exception as e:
            result["errors"].append(f"redis: {str(e)[:100]}")

    return result
