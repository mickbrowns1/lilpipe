#!/usr/bin/env python3
"""Trickle: a local web UI that builds and runs real Vector pipelines and
tests DPM-style Lua serializers.

Standard library only (no pip install). Listens on 127.0.0.1 only.

    python3 server.py            # then open http://127.0.0.1:8790
    PORT=9000 python3 server.py  # different port

How a run works
---------------
1. The UI sends a linear pipeline: source -> steps -> destination.
2. Sources and Vector steps (filter, remap, sample, dedupe) run in the real
   `vector` binary. Every stage gets a hidden "tap" file sink so we can count
   events and bytes after each stage.
3. An optional final "Lua serializer" step runs your processEvent(record)
   function in a local Lua (LuaJIT) through lua_runner.lua, one record at a
   time. We then diff each input record against its output so you can see
   exactly what the serializer changed, and run OCSF sanity checks.
4. A "raw record" source with no Vector steps skips Vector entirely: the
   record goes straight to the serializer, like a DPM collector would hand it.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent
PIPE_DIR = HERE / "pipelines"
OUT_DIR = HERE / "output"
LOCAL = "127.0.0.1"                       # used for Vector's own temporary HTTP listener
HOST = os.environ.get("HOST", LOCAL)      # 0.0.0.0 inside Docker; the compose file only publishes it on 127.0.0.1
PORT = int(os.environ.get("PORT", "8790"))
IN_DOCKER = os.environ.get("IN_DOCKER") == "1"
EXTRA_HOSTS = [h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]

MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_CODE_BYTES = 1024 * 1024
MAX_RUN_SECONDS = 120
SAMPLE_LIMIT = 8
PRINT_LIMIT = 200
SER_EVENT_LIMIT = 2000      # most events sent through the serializer per run
SER_DIFF_RECORDS = 20       # records that get a full before/after diff
MAX_RECORDS = 5000
GEN_FORMATS = ["syslog", "json", "apache_common", "apache_error", "bsd_syslog", "shuffle"]
HTTP_FORMATS = ["text", "ndjson", "json"]

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RUN_LOCK = threading.Lock()


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def _first_executable(candidates):
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def find_vector():
    return _first_executable([os.environ.get("VECTOR_BIN"), shutil.which("vector"),
                              "/opt/homebrew/bin/vector", "/usr/local/bin/vector",
                              str(Path.home() / ".vector" / "bin" / "vector")])


def find_lua():
    return _first_executable([os.environ.get("LUA_BIN"), shutil.which("luajit"),
                              "/opt/homebrew/bin/luajit", "/usr/local/bin/luajit",
                              shutil.which("lua"), "/opt/homebrew/bin/lua", "/usr/local/bin/lua"])


def vector_version(vec):
    try:
        r = subprocess.run([vec, "--version"], capture_output=True, text=True, timeout=15)
        return ANSI.sub("", (r.stdout or r.stderr).strip())
    except Exception as exc:  # noqa: BLE001
        return "unknown (%s)" % exc


def clean_env():
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    return env


# ---------------------------------------------------------------------------
# Pipeline -> Vector config
# ---------------------------------------------------------------------------

def escape_dollars(obj):
    """Vector substitutes $VAR / ${VAR} in config text; $$ is a literal dollar."""
    if isinstance(obj, str):
        return obj.replace("$", "$$")
    if isinstance(obj, list):
        return [escape_dollars(x) for x in obj]
    if isinstance(obj, dict):
        return {k: escape_dollars(v) for k, v in obj.items()}
    return obj


def to_int(value, name, lo, hi, default):
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    if n < lo or n > hi:
        raise ApiError("%s must be between %d and %d." % (name, lo, hi))
    return n


def safe_filename(name, default="pipeline-output.ndjson"):
    name = re.sub(r"[^A-Za-z0-9._-]", "_", str(name or "").strip())
    name = name.lstrip(".")
    return name[:80] or default


def build_config(p, run_dir, http_port=8686):
    """Return (config dict or None, stages, meta). Does not read input files.

    config is None when the pipeline needs no Vector (raw records straight into
    a Lua serializer).
    """
    if not isinstance(p, dict):
        raise ApiError("Pipeline must be a JSON object.")
    src = p.get("source") or {}
    stype = src.get("type")
    meta = {"mode": None, "http_format": None, "saved_path": None, "sink": None, "lua": None}

    tlist = list(p.get("transforms") or [])
    lua_steps = [i for i, t in enumerate(tlist) if t.get("type") == "lua"]
    if lua_steps:
        if len(lua_steps) > 1 or lua_steps[0] != len(tlist) - 1:
            raise ApiError("The Lua serializer must be the last step, and there can be only one.")
        meta["lua"] = tlist[-1]
        tlist = tlist[:-1]

    s = None
    if stype == "generator":
        fmt = src.get("format", "syslog")
        if fmt not in GEN_FORMATS:
            raise ApiError("Unknown generator format: %s" % fmt)
        count = to_int(src.get("count"), "Event count", 1, 5_000_000, 1000)
        s = {"type": "demo_logs", "format": fmt, "count": count, "interval": 0.0}
        if fmt == "shuffle":
            lines = [l for l in str(src.get("lines", "")).splitlines() if l.strip()]
            if not lines:
                raise ApiError("The shuffle format needs at least one line of sample text.")
            s["lines"] = lines
        label = "Generator (%s)" % fmt
        meta["mode"] = "generator"
        meta["count"] = count
    elif stype == "file":
        s = {"type": "stdin"}
        label = "File"
        meta["mode"] = "stdin"
    elif stype == "record":
        label = "Raw records"
        if tlist:
            s = {"type": "stdin", "decoding": {"codec": "json"},
                 "framing": {"method": "newline_delimited"}}
            meta["mode"] = "stdin_json"
        else:
            meta["mode"] = "record"
    elif stype == "http":
        fmt = src.get("format", "ndjson")
        if fmt not in HTTP_FORMATS:
            raise ApiError("Unknown HTTP body format: %s" % fmt)
        if fmt == "text":
            decoding, framing = {"codec": "bytes"}, {"method": "newline_delimited"}
        elif fmt == "ndjson":
            decoding, framing = {"codec": "json"}, {"method": "newline_delimited"}
        else:
            decoding, framing = {"codec": "json"}, {"method": "bytes"}
        s = {"type": "http_server", "address": "127.0.0.1:%d" % http_port,
             "decoding": decoding, "framing": framing}
        label = "HTTP (%s)" % fmt
        meta["mode"] = "http"
        meta["http_format"] = fmt
    else:
        raise ApiError("Choose a source type (generator, file, raw record or http).")

    transforms = {}
    stages = [{"id": "source", "label": label, "kind": "source"}]
    prev = "source"
    for i, t in enumerate(tlist, 1):
        tid = "t%d" % i
        ty = t.get("type")
        if ty == "filter":
            cond = str(t.get("condition", "")).strip()
            if not cond:
                raise ApiError("Step %d (filter): the condition is empty." % i)
            transforms[tid] = {"type": "filter", "inputs": [prev], "condition": cond}
        elif ty == "remap":
            code = str(t.get("source", "")).strip()
            if not code:
                raise ApiError("Step %d (remap): the VRL is empty." % i)
            transforms[tid] = {"type": "remap", "inputs": [prev], "source": code}
        elif ty == "sample":
            n = to_int(t.get("n"), "Step %d sample N" % i, 1, 1_000_000, 10)
            transforms[tid] = {"type": "sample", "inputs": [prev], "ratio": 1.0 / n}
        elif ty == "dedupe":
            fields = [f.strip() for f in str(t.get("fields", "")).split(",") if f.strip()]
            node = {"type": "dedupe", "inputs": [prev]}
            if fields:
                node["fields"] = {"match": fields}
            transforms[tid] = node
        else:
            raise ApiError("Step %d: unknown transform type %r." % (i, ty))
        stages.append({"id": tid, "label": "%s" % ty, "kind": "transform"})
        prev = tid

    sink = p.get("sink") or {}
    sink_type = sink.get("type", "devnull")
    if sink_type not in ("devnull", "console", "file"):
        raise ApiError("Unknown destination type: %s" % sink_type)
    meta["sink"] = sink_type
    if sink_type == "file":
        meta["saved_path"] = str(OUT_DIR / safe_filename(sink.get("filename")))

    if s is None:  # raw records straight into the serializer
        return None, stages, meta

    sinks = {}
    # With a serializer, the real destination happens after it, in this server.
    if sink_type == "devnull" or meta["lua"]:
        sinks["destination"] = {"type": "blackhole", "inputs": [prev]}
    elif sink_type == "console":
        sinks["destination"] = {"type": "console", "inputs": [prev],
                                "encoding": {"codec": "json"}, "target": "stdout"}
    else:
        sinks["destination"] = {"type": "file", "inputs": [prev], "path": meta["saved_path"],
                                "encoding": {"codec": "json"}}

    for st in stages:
        sinks["tap_" + st["id"]] = {
            "type": "file", "inputs": [st["id"]],
            "path": str(Path(run_dir) / ("tap_%s.ndjson" % st["id"])),
            "encoding": {"codec": "json"},
        }

    cfg = {"data_dir": str(Path(run_dir) / "data"),
           "sources": {"source": s}, "transforms": transforms, "sinks": sinks}
    return escape_dollars(cfg), stages, meta


# ---------------------------------------------------------------------------
# Raw records and Lua helpers
# ---------------------------------------------------------------------------

def parse_records(text):
    text = (text or "").strip()
    if not text:
        raise ApiError("The raw record source is empty. Paste one JSON event, a JSON array, or one JSON object per line.")
    try:
        data = json.loads(text)
        recs = data if isinstance(data, list) else [data]
    except ValueError:
        recs = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                recs.append(json.loads(line))
            except ValueError:
                raise ApiError("Line %d of the raw records is not valid JSON." % n)
    if not recs:
        raise ApiError("No records found in the raw record source.")
    if len(recs) > MAX_RECORDS:
        raise ApiError("Too many records (max %d)." % MAX_RECORDS)
    for r in recs:
        if not isinstance(r, dict):
            raise ApiError("Each raw record must be a JSON object.")
    return recs


def lua_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 32 or o == 127:
            out.append("\\%03d" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)



# ---------------------------------------------------------------------------
# Serializer generator: build an OCSF processEvent from a sample record
# ---------------------------------------------------------------------------

def _norm(k):
    return re.sub(r"[^a-z0-9]", "", str(k).lower())

# normalised vendor field name -> (OCSF path, kind). kind: s string, n number
GEN_ALIASES = {}
def _alias(names, target, kind="s"):
    for n in names.split():
        GEN_ALIASES.setdefault(n, (target, kind))

_alias("srcip sourceip srcaddr sourceaddress clientip srchost sourceipaddress", "src_endpoint.ip")
_alias("srcport sourceport clientport", "src_endpoint.port", "n")
_alias("srccountry sourcecountry", "src_endpoint.location.country")
_alias("srcsite srchostname sourcehostname sitename", "src_endpoint.hostname")
_alias("srcmac sourcemac", "src_endpoint.mac")
_alias("dstip destip destinationip dstaddr destaddr destinationaddress serverip destinationipaddress", "dst_endpoint.ip")
_alias("dstport destport destinationport serverport", "dst_endpoint.port", "n")
_alias("dstcountry destcountry destinationcountry", "dst_endpoint.location.country")
_alias("dsthostname desthostname destinationhostname", "dst_endpoint.hostname")
_alias("protocol ipprotocol proto transport", "connection_info.protocol_name")
_alias("trafficdirection direction", "connection_info.direction")
_alias("username user usr accountname actor initiatedby", "actor.user.name")
_alias("useremail email", "actor.user.email_addr")
_alias("hostname host devicename computername", "device.hostname")
_alias("ostype os osname", "device.os.name")
_alias("rule rulename policy policyname", "firewall_rule.name")
_alias("ruleid policyid", "firewall_rule.uid")
_alias("threatname signaturename malwarename alertname detectionname", "finding_info.title")
_alias("threattype category", "finding_info.types[0]")
_alias("signatureid signature threatid sid detectionid", "finding_info.uid")
_alias("threatreference reference refurl", "finding_info.src_url")
_alias("url uri requesturl", "http_request.url.url_string")
_alias("domain fqdn", "http_request.url.hostname")
_alias("useragent", "http_request.user_agent")
_alias("method httpmethod", "http_request.http_method")
_alias("statuscode httpstatus responsecode", "http_response.code", "n")
_alias("bytesin bytesdownloaded rxbytes bytesreceived", "traffic.bytes_in", "n")
_alias("bytesout bytesuploaded txbytes bytessent", "traffic.bytes_out", "n")
_alias("filename", "file.name")
_alias("filehash sha256 hash md5", "file.hashes[0].value")
_alias("filepath", "file.path")
_alias("processname process", "process.name")
_alias("commandline cmdline", "process.cmd_line")
_alias("accountid tenantid customerid", "cloud.account.uid")
_alias("popname region", "cloud.region")
_alias("internalid eventid id uid guid", "metadata.uid")
_alias("eventcount count", "count", "n")
_alias("message msg description", "message")

GEN_TIME_KEYS = ["time", "timestamp", "eventtimestamp", "eventtime", "ts", "datetime", "createdat", "date"]
GEN_SEV_KEYS = ["risklevel", "severity", "risk", "level", "priority"]
GEN_ACTION_KEYS = ["action", "disposition", "verdict", "outcome"]

GEN_TEMPLATE = r"""-- OCSF serializer GENERATED by Trickle from a sample record.
-- Vendor: __VENDOR__   Class: __CLASS_NAME__ (__CLASS_UID__)
-- Review it: the field map below is a best guess from field names.
-- Edit MAP, CLASS settings and the enums, then press Run to see before and after.
-- Rules honored: no dollar-sigil tokens, single-line strings, ASCII comments.

local OCSF_VERSION = "__VERSION__"
local VENDOR_NAME  = __VENDOR_Q__
local PRODUCT_NAME = __PRODUCT_Q__
local PRODUCT_UID   = __PRODUCT_UID__
local CLASS_UID    = __CLASS_UID__
local CLASS_NAME   = "__CLASS_NAME__"
local CATEGORY_UID = __CAT_UID__
local CATEGORY_NAME = "__CAT_NAME__"
local FIXED_ACTIVITY_ID = __ACTIVITY__

-- vendor field -> OCSF dotted path. number = true converts to a number.
local MAP = {
__MAP__
}

-- Fields handled below, so they are not copied into unmapped.
local CONSUMED = {
__CONSUMED__
}

local TIME_FIELDS   = { __TIME_FIELDS__ }
local SEVERITY_FIELD = __SEV_FIELD__
local ACTION_FIELD   = __ACTION_FIELD__

local SEVERITY = { info = 1, informational = 1, low = 2, medium = 3, high = 4, critical = 5, fatal = 6 }

local function isEmpty(v)
    if v == nil or v == "" then return true end
    if type(v) == "table" and next(v) == nil then return true end
    return false
end

local function setNestedField(obj, path, value)
    if value == nil or path == nil or path == "" then return end
    local keys = {}
    for key in string.gmatch(path, "[^.]+") do
        if key and key ~= "" then table.insert(keys, key) end
    end
    if #keys == 0 then return end
    local current = obj
    for i = 1, #keys - 1 do
        local key = keys[i]
        local base = string.match(key, "(.-)%[(%d+)%]")
        if base then
            local index = tonumber(string.match(key, "%[(%d+)%]")) + 1
            if current[base] == nil then current[base] = {} end
            if current[base][index] == nil then current[base][index] = {} end
            current = current[base][index]
        else
            if current[key] == nil then current[key] = {} end
            current = current[key]
        end
    end
    local finalKey = keys[#keys]
    local base = string.match(finalKey, "(.-)%[(%d+)%]")
    if base then
        local index = tonumber(string.match(finalKey, "%[(%d+)%]")) + 1
        if current[base] == nil then current[base] = {} end
        current[base][index] = value
    else
        current[finalKey] = value
    end
end

-- ISO-8601 UTC to epoch milliseconds (no os.time, so no timezone surprises).
local function isoToMs(ts)
    local y, mo, d, h, mi, s = string.match(ts, "^(%d%d%d%d)-(%d%d)-(%d%d)[T ](%d%d):(%d%d):(%d%d)")
    if not y then return nil end
    local yy, mm, dd = tonumber(y), tonumber(mo), tonumber(d)
    if mm <= 2 then yy = yy - 1 end
    local era = math.floor(yy / 400)
    local yoe = yy - era * 400
    local mp = (mm + 9) % 12
    local doy = math.floor((153 * mp + 2) / 5) + dd - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    local secs = days * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(s)
    local frac = string.match(ts, "^%d%d%d%d%-%d%d%-%d%d[T ]%d%d:%d%d:%d%d%.(%d+)")
    local ms = 0
    if frac then ms = tonumber(string.sub(frac .. "000", 1, 3)) end
    return secs * 1000 + ms
end

local function toEpochMs(v)
    if v == nil or v == "" then return nil end
    local n = tonumber(v)
    if n then
        if n < 100000000000 then n = n * 1000 end
        return n
    end
    if type(v) == "string" then return isoToMs(v) end
    return nil
end

local function dispositionId(action)
    local a = string.lower(tostring(action or ""))
    if a == "allow" or a == "allowed" or a == "permit" then return 1
    elseif a == "block" or a == "blocked" or a == "deny" or a == "denied" then return 2
    elseif a == "drop" or a == "dropped" then return 6
    elseif a == "monitor" or a == "alert" or a == "detect" then return 15 end
    return 99
end

local function activityId(action)
    if FIXED_ACTIVITY_ID >= 0 then return FIXED_ACTIVITY_ID end
    local a = string.lower(tostring(action or ""))
    if a == "allow" or a == "allowed" or a == "permit" then return 1 end
    if a == "block" or a == "blocked" or a == "deny" or a == "denied" or a == "drop" then return 5 end
    return 6
end

function processEvent(event)
    if event == nil then return {} end
    local e = event
    if type(event.message) == "table" then e = event.message end
    local r = {}

    local action = nil
    if ACTION_FIELD then action = e[ACTION_FIELD] end
    local act = activityId(action)

    r.class_uid = CLASS_UID
    r.class_name = CLASS_NAME
    r.category_uid = CATEGORY_UID
    r.category_name = CATEGORY_NAME
    r.activity_id = act
    r.type_uid = CLASS_UID * 100 + act
    r.status_id = 1

    local sev = nil
    if SEVERITY_FIELD then sev = e[SEVERITY_FIELD] end
    r.severity_id = SEVERITY[string.lower(tostring(sev or ""))] or 0
    if not isEmpty(sev) then r.severity = tostring(sev) end

    if not isEmpty(action) then
        r.action = tostring(action)
        r.disposition_id = dispositionId(action)
    end

    for _, f in ipairs(TIME_FIELDS) do
        local ms = toEpochMs(e[f])
        if ms then r.time = ms; break end
    end

    setNestedField(r, "metadata.version", OCSF_VERSION)
    setNestedField(r, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(r, "metadata.product.name", PRODUCT_NAME)
    setNestedField(r, "dataSource.category", "security")
    setNestedField(r, "dataSource.vendor", VENDOR_NAME)
    setNestedField(r, "dataSource.name", PRODUCT_NAME)
    __FEATURE__

    if CLASS_UID == 2004 then setNestedField(r, "finding_info.product_uid", PRODUCT_UID) end

    local mapped = {}
    for _, m in ipairs(MAP) do
        mapped[m.source] = true
        local v = e[m.source]
        if not isEmpty(v) then
            if m.number then v = tonumber(v) or v end
            setNestedField(r, m.target, v)
        end
    end
__EXTRA__
    local obs = {}
    local function addObs(name, type_id, value)
        if not isEmpty(value) then table.insert(obs, { name = name, type_id = type_id, value = tostring(value) }) end
    end
    if r.src_endpoint then addObs("src_endpoint.ip", 2, r.src_endpoint.ip) end
    if r.dst_endpoint then addObs("dst_endpoint.ip", 2, r.dst_endpoint.ip) end
    if r.http_request and r.http_request.url then
        addObs("http_request.url.hostname", 1, r.http_request.url.hostname)
        addObs("http_request.url.url_string", 6, r.http_request.url.url_string)
    end
    if r.actor and r.actor.user then addObs("actor.user.name", 4, r.actor.user.name) end
    if r.file and r.file.hashes and r.file.hashes[1] then addObs("file.hashes", 8, r.file.hashes[1].value) end
    if #obs > 0 then r.observables = obs end

    for k, v in pairs(e) do
        if not mapped[k] and not CONSUMED[k] and not isEmpty(v) then
            setNestedField(r, "unmapped." .. k, v)
        end
    end
    return r
end
"""

GEN_MITRE_EXTRA = r"""
    local function listOf(v)
        if isEmpty(v) then return {} end
        if type(v) == "table" then return v end
        return { v }
    end
    local tactics = listOf(e[__TAC__])
    local techs = listOf(e[__TEC__])
    local n = math.max(#tactics, #techs)
    for i = 1, n do
        local base = "finding_info.attacks[" .. (i - 1) .. "]"
        if tactics[i] then setNestedField(r, base .. ".tactic.name", tostring(tactics[i])) end
        if techs[i] then setNestedField(r, base .. ".technique.name", tostring(techs[i])) end
    end
"""


def generate_serializer(text, vendor="", product="", version=""):
    recs = parse_records(text)
    keys = []
    for r in recs:
        for k in r:
            if k not in keys:
                keys.append(k)
    by_norm = {}
    for k in keys:
        by_norm.setdefault(_norm(k), k)

    def pick(options):
        for o in options:
            if o in by_norm:
                return by_norm[o]
        return None

    time_keys = [by_norm[n] for n in GEN_TIME_KEYS if n in by_norm]
    sev_key = pick(GEN_SEV_KEYS)
    act_key = pick(GEN_ACTION_KEYS)
    tac_key = next((k for k in keys if "mitre" in _norm(k) and "tactic" in _norm(k)), None)
    tec_key = next((k for k in keys if "mitre" in _norm(k) and "technique" in _norm(k) and "sub" not in _norm(k)), None)
    mitre_keys = [k for k in keys if "mitre" in _norm(k)]

    consumed = set(time_keys) | {k for k in (sev_key, act_key) if k} | set(mitre_keys)
    maps, used_targets = [], set()
    for k in keys:
        if k in consumed:
            continue
        hit = GEN_ALIASES.get(_norm(k))
        if hit and hit[0] not in used_targets:
            used_targets.add(hit[0])
            maps.append((k, hit[0], hit[1] == "n"))
            if hit[0] == "finding_info.title":
                maps.append((k, "malware[0].name", False))
    mapped_names = {m[0] for m in maps}

    nset = {m[1] for m in maps}
    has = lambda p: any(t.startswith(p) for t in nset)
    if has("finding_info") or tac_key:
        cls, cname, cat, catname, activity = 2004, "Detection Finding", 2, "Findings", 1
    elif has("http_request"):
        cls, cname, cat, catname, activity = 4002, "HTTP Activity", 4, "Network Activity", 0
    elif has("src_endpoint") or has("dst_endpoint"):
        cls, cname, cat, catname, activity = 4001, "Network Activity", 4, "Network Activity", -1
    else:
        cls, cname, cat, catname, activity = 0, "Base Event", 0, "Uncategorized", 0

    def q(s):
        return lua_str(s)

    map_lines = []
    for src, tgt, num in maps:
        map_lines.append("    { source = %s, target = %s%s }," % (q(src), q(tgt), ", number = true" if num else ""))
    cons_lines = ["    [%s] = true," % q(k) for k in sorted(consumed)]

    code = GEN_TEMPLATE
    extra = ""
    if tac_key or tec_key:
        extra = GEN_MITRE_EXTRA.replace("__TAC__", q(tac_key) if tac_key else "nil").replace("__TEC__", q(tec_key) if tec_key else "nil")
    vendor = (vendor or "Vendor").strip() or "Vendor"
    product = (product or vendor).strip() or vendor
    version = (version or "").strip()
    if not re.match(r"^\d+\.\d+\.\d+(-dev)?$", version):
        version = "1.8.0"
    et_key, st_key = by_norm.get("eventtype"), by_norm.get("eventsubtype")
    if et_key and st_key:
        feature = 'setNestedField(r, "metadata.product.feature.name", tostring(e[%s] or "") .. " / " .. tostring(e[%s] or ""))' % (q(et_key), q(st_key))
    elif et_key or st_key:
        feature = 'setNestedField(r, "metadata.product.feature.name", tostring(e[%s]))' % q(et_key or st_key)
    else:
        feature = "-- no event_type field found, so no feature name"
    uid = re.sub(r"[^a-z0-9]+", "_", product.lower()).strip("_") or "vendor"
    for a, b in [("__FEATURE__", feature), ("__PRODUCT_UID__", q(uid)), ("__VERSION__", version), ("__VENDOR_Q__", q(vendor)), ("__PRODUCT_Q__", q(product)), ("__VENDOR__", re.sub(r"[^\x20-\x7e]", "", vendor)),
                 ("__CLASS_NAME__", cname), ("__CLASS_UID__", str(cls)), ("__CAT_UID__", str(cat)),
                 ("__CAT_NAME__", catname), ("__ACTIVITY__", str(activity)),
                 ("__MAP__", "\n".join(map_lines)), ("__CONSUMED__", "\n".join(cons_lines)),
                 ("__TIME_FIELDS__", ", ".join(q(k) for k in time_keys)),
                 ("__SEV_FIELD__", q(sev_key) if sev_key else "nil"),
                 ("__ACTION_FIELD__", q(act_key) if act_key else "nil"),
                 ("__EXTRA__", extra)]:
        code = code.replace(a, b)
    unmapped = [k for k in keys if k not in mapped_names and k not in consumed]
    return {"code": code, "class_name": cname, "class_uid": cls,
            "mapped": [{"source": m[0], "target": m[1]} for m in maps],
            "handled": sorted(consumed), "unmapped": unmapped}


def to_lua(v):
    if v is None:
        return "nil"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return lua_str(v)
    if isinstance(v, list):
        return "{" + ",".join(to_lua(x) for x in v) + "}"
    if isinstance(v, dict):
        return "{" + ",".join("[%s]=%s" % (lua_str(str(k)), to_lua(x))
                              for k, x in v.items() if x is not None) + "}"
    return lua_str(str(v))


def load_serializer_code(step):
    path = str(step.get("path", "")).strip()
    if path:
        fp = Path(path).expanduser()
        if not fp.is_file():
            raise ApiError("Serializer file not found: %s" % path)
        if fp.stat().st_size > MAX_CODE_BYTES:
            raise ApiError("Serializer file is larger than 1 MB.")
        return fp.read_text(encoding="utf-8", errors="replace")
    code = str(step.get("code", ""))
    if not code.strip():
        raise ApiError("The Lua serializer step is empty. Paste your serializer or give a file path.")
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        raise ApiError("Serializer code is larger than 1 MB.")
    return code


def lint_lua(code):
    """Console-validator and config-loader traps (dpm-lua-creation rules 6, 7, 10)."""
    lines = code.splitlines()
    findings = []

    def add(rule, detail, nums):
        if nums:
            findings.append({"rule": rule, "detail": detail, "lines": nums[:12]})

    def hits(pattern, code_only=True):
        rx = re.compile(pattern)
        res = []
        for n, l in enumerate(lines, 1):
            if code_only and re.match(r"^\s*--", l):
                continue
            if rx.search(l):
                res.append(n)
        return res

    add("trailing string concatenation", "The console validator rejects strings continued with .. at the end of a line. Keep each string on one line.", hits(r"\.\.[ \t]*$"))
    add("assignment value on the next line", "The console validator reads an empty right-hand side as 'expected a value'.", hits(r"[^=~<>]=[ \t]*$"))
    add("apostrophe in a comment", "A stray apostrophe in a comment can trip the console lexer. Use plain ASCII.", [n for n, l in enumerate(lines, 1) if re.match(r"^\s*--.*'", l)])
    add("Lua 5.3+ syntax", "The console validator is Lua 5.1 flavoured: no //, bit operators, goto or hex literals.", sorted(set(hits(r"[^:]//") + hits(r"<<") + hits(r">>") + hits(r"0[xX][0-9a-fA-F]") + hits(r"\bgoto\b"))))
    add("$identifier in source", "The dataplane config loader treats $name as a required environment variable, even in comments.", hits(r"\$[A-Za-z_]", code_only=False))
    if not re.search(r"function\s+processEvent\b|processEvent\s*=", code):
        findings.append({"rule": "no processEvent", "detail": "Define a global function processEvent(record).", "lines": []})
    missing = [k for k in ("dataSource.category", "dataSource.vendor", "dataSource.name") if k not in code]
    if missing:
        findings.append({"rule": "dataSource fields missing",
                         "detail": "Serializers should stamp dataSource.category, dataSource.vendor and dataSource.name next to metadata.product.* so events appear in XDR search. Not found in the code: %s." % ", ".join(missing),
                         "lines": []})
    return findings


# ---------------------------------------------------------------------------
# Diff and OCSF checks
# ---------------------------------------------------------------------------

def flatten(obj, prefix=""):
    leaves = {}

    def put(path, v):
        if isinstance(v, dict) and v:
            leaves.update(flatten(v, path))
        elif isinstance(v, list) and v:
            leaves.update(flatten(v, path))
        else:
            leaves[path] = v

    if isinstance(obj, dict):
        for k, v in obj.items():
            put(("%s.%s" % (prefix, k)) if prefix else str(k), v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            put("%s[%d]" % (prefix, i), v)
    return leaves


def norm(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v == int(v) and abs(v) < 1e15:
        return str(int(v))
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    return str(v)


def type_name(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    return "object" if isinstance(v, dict) else "array"


KIND_ORDER = ["moved", "changed", "retyped", "unmapped", "dropped", "added", "empty", "unchanged"]


def diff_record(inp, out):
    """Compare a raw record with the serializer output.

    Matching is by value, so it is a good guide, not proof: when a value was
    transformed (for example an ISO time turned into epoch milliseconds) it
    shows up as dropped plus added.
    """
    fi, fo = flatten(inp), flatten(out)
    by_val = {}
    for q, w in fo.items():
        by_val.setdefault(norm(w), []).append(q)
    claimed = set()
    rows = []
    for p, v in fi.items():
        nv = norm(v)
        if p in fo:
            claimed.add(p)
            same = norm(fo[p]) == nv
            if same and type_name(v) == type_name(fo[p]):
                kind = "unchanged"
            elif same:
                kind = "retyped"
            else:
                kind = "changed"
            rows.append({"kind": kind, "path": p, "from": v, "to": fo[p], "out": [p]})
            continue
        if nv in (None, "", "{}", "[]"):
            # An empty input field is often carried along (typically under unmapped).
            twins = [q for q, w in fo.items() if norm(w) in (None, "", "{}", "[]")
                     and (q == "unmapped." + p or q.split(".")[-1] == p.split(".")[-1])]
            if twins:
                claimed.update(twins)
                rows.append({"kind": "unmapped" if all(q.startswith("unmapped") for q in twins) else "moved",
                             "path": p, "from": v, "to": fo[twins[0]], "out": twins[:4], "retyped": False})
            else:
                rows.append({"kind": "empty", "path": p, "from": v})
            continue
        cands = by_val.get(nv, [])
        if cands:
            last = p.split(".")[-1]
            cands = sorted(cands, key=lambda q: (q.split(".")[-1] != last, q.startswith("unmapped"), q))
            claimed.update(cands)
            all_unmapped = all(q.startswith("unmapped") for q in cands)
            retyped = type_name(v) != type_name(fo[cands[0]])
            rows.append({"kind": "unmapped" if all_unmapped else "moved", "path": p, "from": v,
                         "to": fo[cands[0]], "out": cands[:4], "retyped": retyped})
        else:
            rows.append({"kind": "dropped", "path": p, "from": v})
    for q, w in fo.items():
        if q not in claimed:
            rows.append({"kind": "added", "path": q, "to": w})
    rows.sort(key=lambda r: (KIND_ORDER.index(r["kind"]), r["path"]))
    summary = {}
    for r in rows:
        summary[r["kind"]] = summary.get(r["kind"], 0) + 1
    return {"rows": rows, "summary": summary}


def ocsf_checks(out):
    f = flatten(out)

    def g(path):
        return f.get(path)

    def present(*paths):
        return all(g(x) not in (None, "") for x in paths)

    checks = []
    checks.append(("class_uid, category_uid and activity_id are set",
                   present("class_uid", "category_uid", "activity_id")))
    cu, au, tu = g("class_uid"), g("activity_id"), g("type_uid")
    ok_type = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (cu, au, tu)) and tu == cu * 100 + au
    checks.append(("type_uid = class_uid x 100 + activity_id", bool(ok_type)))
    t = g("time")
    checks.append(("time is a number in epoch milliseconds",
                   isinstance(t, (int, float)) and not isinstance(t, bool) and 1e11 <= t < 1e14))
    checks.append(("metadata.version is set", present("metadata.version")))
    checks.append(("metadata.product.vendor_name and name are set",
                   present("metadata.product.vendor_name", "metadata.product.name")))
    checks.append(("dataSource.category, vendor and name are set (XDR search)",
                   present("dataSource.category", "dataSource.vendor", "dataSource.name")))
    checks.append(("dataSource vendor and name mirror metadata.product",
                   present("dataSource.vendor", "dataSource.name") and
                   g("dataSource.vendor") == g("metadata.product.vendor_name") and
                   g("dataSource.name") == g("metadata.product.name")))
    return checks


# ---------------------------------------------------------------------------
# Running things
# ---------------------------------------------------------------------------

def strip_tail(path, n=60):
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return []
    lines = [ANSI.sub("", l).rstrip() for l in text.splitlines() if l.strip()]
    return lines[-n:]


def read_tap(path, keep_events=0):
    events = nbytes = 0
    samples = []
    kept = []
    if not Path(path).exists():
        return 0, 0, samples, kept
    with open(path, "rb") as f:
        for line in f:
            if not line.strip():
                continue
            events += 1
            nbytes += len(line)
            if len(samples) < SAMPLE_LIMIT:
                samples.append(line.decode("utf-8", "replace").strip())
            if len(kept) < keep_events:
                try:
                    kept.append(json.loads(line))
                except ValueError:
                    pass
    return events, nbytes, samples, kept


def free_port():
    with socket.socket() as s:
        s.bind((LOCAL, 0))
        return s.getsockname()[1]


def load_file_input(src):
    path = str(src.get("path", "")).strip()
    if path:
        fp = Path(path).expanduser()
        if not fp.is_file():
            raise ApiError("File not found: %s" % path)
        if fp.stat().st_size > MAX_INPUT_BYTES:
            raise ApiError("File is larger than %d MB." % (MAX_INPUT_BYTES // 1024 // 1024))
        data = fp.read_bytes()
    else:
        data = str(src.get("text", "")).encode("utf-8")
    if not data.strip():
        raise ApiError("The file source has no input. Give it a path or paste some log lines.")
    if not data.endswith(b"\n"):
        data += b"\n"
    return data


def http_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def wait_for_port(port, proc, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection((LOCAL, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def check_serializer_loads(code, lua, run_dir):
    """Load the serializer in a throwaway run with no records. Returns an error string or None."""
    ser = Path(run_dir) / "serializer.lua"
    rec = Path(run_dir) / "records.lua"
    ser.write_text(code, encoding="utf-8")
    rec.write_text("return {}", encoding="utf-8")
    r = subprocess.run([lua, str(HERE / "lua_runner.lua"), str(ser), str(rec)],
                       capture_output=True, text=True, timeout=60, env=clean_env(), cwd=str(run_dir))
    for line in r.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("fatal"):
            return tidy(obj["fatal"])
        if obj.get("loaded"):
            return None
    return tidy((r.stderr or "The Lua interpreter produced no output.").strip()[:1500])


def validate_pipeline(p):
    run_dir = Path(tempfile.mkdtemp(prefix="pipelab_"))
    try:
        cfg, _stages, meta = build_config(p, run_dir, http_port=free_port())
        parts = []
        ok = True
        if cfg is not None:
            vec = find_vector()
            if not vec:
                raise ApiError("Vector is not installed yet.", 409)
            (run_dir / "data").mkdir()
            cfg_path = run_dir / "vector.json"
            cfg_path.write_text(json.dumps(cfg, indent=2))
            r = subprocess.run([vec, "validate", str(cfg_path)], capture_output=True,
                               text=True, timeout=60, env=clean_env())
            ok = r.returncode == 0
            parts.append(ANSI.sub("", (r.stdout or "") + (r.stderr or "")).strip())
        else:
            parts.append("No Vector steps: the raw record goes straight to the serializer.")
        if meta["lua"]:
            code = load_serializer_code(meta["lua"])
            lua = find_lua()
            if not lua:
                raise ApiError("No Lua interpreter found. Install one with: brew install luajit", 409)
            err = check_serializer_loads(code, lua, run_dir)
            if err:
                ok = False
                parts.append("Lua serializer: " + err)
            else:
                parts.append("Lua serializer: loads and defines processEvent.")
            for f in lint_lua(code):
                parts.append("Lint (%s)%s: %s" % (f["rule"], (" lines " + ", ".join(map(str, f["lines"]))) if f["lines"] else "", f["detail"]))
        return {"ok": ok, "output": "\n".join(x for x in parts if x)}
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def stage_from_events(st, events):
    lines = [json.dumps(e) for e in events]
    return dict(st, events=len(lines), bytes=sum(len(l) + 1 for l in lines),
                samples=lines[:SAMPLE_LIMIT])


def execute_vector(vec, cfg, stages, meta, p, run_dir, port):
    """Run Vector for the source and Vector steps. Returns a result dict."""
    cfg_path = run_dir / "vector.json"
    cfg_path.write_text(json.dumps(cfg, indent=2))
    (run_dir / "data").mkdir(exist_ok=True)

    input_bytes = None
    http_body = None
    if meta["mode"] == "stdin":
        input_bytes = load_file_input(p["source"])
    elif meta["mode"] == "stdin_json":
        recs = parse_records(p["source"].get("text", ""))
        input_bytes = ("\n".join(json.dumps(r) for r in recs) + "\n").encode("utf-8")
    elif meta["mode"] == "http":
        http_body = str(p["source"].get("body", ""))
        if not http_body.strip():
            raise ApiError("The HTTP source has no body to send. Paste some events.")
        if not http_body.endswith("\n"):
            http_body += "\n"
        if len(http_body.encode()) > MAX_INPUT_BYTES:
            raise ApiError("HTTP body is larger than %d MB." % (MAX_INPUT_BYTES // 1024 // 1024))

    if meta["saved_path"] and not meta["lua"]:
        OUT_DIR.mkdir(exist_ok=True)
        try:
            Path(meta["saved_path"]).unlink()
        except FileNotFoundError:
            pass

    v = subprocess.run([vec, "validate", str(cfg_path)], capture_output=True,
                       text=True, timeout=60, env=clean_env())
    if v.returncode != 0:
        msg = ANSI.sub("", (v.stdout or "") + (v.stderr or "")).strip()
        return {"ok": False, "stage": "validate", "error": msg or "Vector rejected the config."}

    out_f = open(run_dir / "stdout.log", "wb")
    err_f = open(run_dir / "stderr.log", "wb")
    started = time.time()
    proc = subprocess.Popen(
        [vec, "--config", str(cfg_path)],
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=out_f, stderr=err_f, env=clean_env())

    feed_done_at = started
    grace = 10.0
    if meta["mode"] == "generator":
        grace = 15.0 + meta.get("count", 0) / 20000.0
    elif input_bytes is not None:
        def feed():
            try:
                proc.stdin.write(input_bytes)
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
        threading.Thread(target=feed, daemon=True).start()
        grace = 15.0 + len(input_bytes) / 1_000_000.0 * 4
    elif meta["mode"] == "http":
        if not wait_for_port(port, proc):
            proc.terminate()
            proc.wait(timeout=20)
            out_f.close()
            err_f.close()
            return {"ok": False, "stage": "start",
                    "error": "Vector did not start listening on the HTTP port.",
                    "log": strip_tail(run_dir / "stderr.log")}
        ctype = "application/json" if meta["http_format"] != "text" else "text/plain"
        req = urllib.request.Request("http://127.0.0.1:%d/" % port, data=http_body.encode(),
                                     method="POST", headers={"Content-Type": ctype})
        try:
            http_opener().open(req, timeout=30).read()
        except Exception as exc:  # noqa: BLE001
            proc.terminate()
            proc.wait(timeout=20)
            out_f.close()
            err_f.close()
            return {"ok": False, "stage": "send",
                    "error": "Vector refused the HTTP request: %s" % exc,
                    "log": strip_tail(run_dir / "stderr.log")}
        feed_done_at = time.time()
        grace = 3.0 + len(http_body) / 1_000_000.0 * 2

    timed_out = False
    stopped_early = False
    while True:
        if proc.poll() is not None:
            break
        now = time.time()
        if now - started > MAX_RUN_SECONDS:
            timed_out = True
            break
        if now - feed_done_at >= grace:
            stopped_early = True  # listeners never exit on their own
            break
        time.sleep(0.2)

    if proc.poll() is None:
        proc.terminate()  # graceful: lets the file sinks flush
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    out_f.close()
    err_f.close()
    duration = time.time() - started

    results = []
    last_events = []
    for idx, st in enumerate(stages):
        is_last = idx == len(stages) - 1
        ev, nb, samples, kept = read_tap(run_dir / ("tap_%s.ndjson" % st["id"]),
                                         SER_EVENT_LIMIT if (is_last and meta["lua"]) else 0)
        if is_last:
            last_events = kept
        results.append(dict(st, events=ev, bytes=nb, samples=samples))

    printed = None
    if meta["sink"] == "console" and not meta["lua"]:
        lines = [l for l in (run_dir / "stdout.log").read_text(errors="replace").splitlines() if l.strip()]
        printed = {"events": len(lines), "lines": lines[:PRINT_LIMIT]}

    saved = None
    if meta["saved_path"] and not meta["lua"] and Path(meta["saved_path"]).exists():
        sp = Path(meta["saved_path"])
        saved = {"path": str(sp), "bytes": sp.stat().st_size}

    log = strip_tail(run_dir / "stderr.log", 80)
    problems = [l for l in log if re.search(r"\b(ERROR|WARN)\b", l)]
    ok = (proc.returncode in (0, -15, 143, -9)) or stopped_early
    return {
        "ok": ok, "stage": "run", "duration": round(duration, 2),
        "exit_code": proc.returncode, "timed_out": timed_out, "stopped_early": stopped_early,
        "vector_version": vector_version(vec), "stages": results,
        "printed": printed, "saved": saved, "log": log, "problems": problems[:30],
        "error": None if ok else "Vector exited with code %s. See the Vector log tab." % proc.returncode,
        "last_events": last_events,
    }


def tidy(msg):
    """Hide the temporary run folder in Lua error messages."""
    return re.sub(r"[^\s:'\"]*serializer\.lua", "serializer.lua", str(msg))


def run_serializer(code, events, lua, run_dir):
    truncated = len(events) > SER_EVENT_LIMIT
    events = events[:SER_EVENT_LIMIT]
    ser = run_dir / "serializer.lua"
    rec = run_dir / "records.lua"
    ser.write_text(code, encoding="utf-8")
    rec.write_text("return " + to_lua(events), encoding="utf-8")
    try:
        r = subprocess.run([lua, str(HERE / "lua_runner.lua"), str(ser), str(rec)],
                           capture_output=True, text=True, timeout=120, env=clean_env(), cwd=str(run_dir))
    except subprocess.TimeoutExpired:
        return {"ok": False, "fatal": "The serializer took longer than 120 seconds and was stopped."}

    by_i = {}
    noise = []
    for line in r.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            if line.strip():
                noise.append(line)
            continue
        if obj.get("fatal"):
            return {"ok": False, "fatal": tidy(obj["fatal"]), "lint": lint_lua(code)}
        if "i" in obj:
            by_i[obj["i"]] = obj
    if not by_i and events:
        return {"ok": False, "fatal": tidy((r.stderr or "The Lua interpreter produced no results.").strip()[:1500]),
                "lint": lint_lua(code)}

    records = []
    outputs = []
    check_acc = {}
    errors = dropped = 0
    for idx, ev in enumerate(events):
        o = by_i.get(idx + 1)
        entry = {"index": idx + 1, "input": ev if idx < SER_DIFF_RECORDS else None}
        if o is None:
            entry.update(ok=False, error="No result came back for this record.")
            errors += 1
        elif o.get("error"):
            entry.update(ok=False, error=tidy(o["error"]), logs=o.get("logs") or [])
            errors += 1
        elif o.get("dropped"):
            entry.update(ok=True, dropped=True, logs=o.get("logs") or [])
            dropped += 1
        else:
            out = o.get("out") or {}
            outputs.append(out)
            entry.update(ok=True, logs=o.get("logs") or [])
            if idx < SER_DIFF_RECORDS:
                entry["output"] = out
                entry["diff"] = diff_record(ev, out)
            for name, passed in ocsf_checks(out):
                c = check_acc.setdefault(name, {"name": name, "passed": 0, "failed": 0, "first_fail": None})
                if passed:
                    c["passed"] += 1
                else:
                    c["failed"] += 1
                    if c["first_fail"] is None:
                        c["first_fail"] = idx + 1
        records.append(entry)
    checks = list(check_acc.values())
    return {
        "ok": True, "fatal": None, "total": len(events), "errors": errors, "dropped": dropped,
        "truncated": truncated, "checks": checks, "records": records[:SER_DIFF_RECORDS + 200],
        "lint": lint_lua(code), "stdout": noise[:20], "stderr": (r.stderr or "").strip()[:800],
        "outputs": outputs,
    }


def find_busted():
    return _first_executable([os.environ.get("BUSTED_BIN"), shutil.which("busted"),
                              str(Path.home() / ".luarocks" / "bin" / "busted"),
                              "/opt/homebrew/bin/busted", "/usr/local/bin/busted"])


def run_busted(p):
    """Run spec_live/generic_spec.lua (Busted) against the pipeline's serializer and raw records."""
    busted = find_busted()
    if not busted:
        raise ApiError("Busted is not installed. In Docker it is built in (rebuild with docker compose up -d --build). "
                       "On your Mac: brew install luajit luarocks, then luarocks --lua-version 5.1 "
                       "--lua-dir=\"$(brew --prefix luajit)\" --local install busted", 409)
    step = None
    for t in (p.get("transforms") or []):
        if t.get("type") == "lua":
            step = t
    if not step:
        raise ApiError("Add a Lua serializer step first.")
    src = p.get("source") or {}
    if src.get("type") != "record":
        raise ApiError("Busted checks run against the Raw record(s) source. Set the Source to Raw record(s).")
    recs = parse_records(src.get("text", ""))[:SER_EVENT_LIMIT]
    code = load_serializer_code(step)
    run_dir = Path(tempfile.mkdtemp(prefix="pipelab_busted_"))
    try:
        ser = run_dir / "serializer.lua"
        rec = run_dir / "records.lua"
        ser.write_text(code, encoding="utf-8")
        rec.write_text("return " + to_lua(recs), encoding="utf-8")
        env = clean_env()
        env["SERIALIZER_PATH"] = str(ser)
        env["SAMPLE_PATH"] = str(rec)
        try:
            r = subprocess.run([busted, "--output=TAP", str(HERE / "spec_live" / "generic_spec.lua")],
                               capture_output=True, text=True, timeout=120, env=env, cwd=str(run_dir))
        except subprocess.TimeoutExpired:
            raise ApiError("Busted took longer than 120 seconds and was stopped.")
        raw = tidy(ANSI.sub("", (r.stdout or "") + (r.stderr or "")))
        tests, cur = [], None
        for line in raw.splitlines():
            m = re.match(r"^(not ok|ok)\s+\d+\s*-?\s*(.*)$", line)
            if m:
                cur = {"ok": m.group(1) == "ok", "name": m.group(2), "detail": ""}
                tests.append(cur)
            elif cur is not None and line.startswith("#") and not cur["ok"]:
                cur["detail"] += line.lstrip("# ").rstrip() + "\n"
        passed = sum(1 for t in tests if t["ok"])
        failed = len(tests) - passed
        crashed = (not tests) and r.returncode != 0
        return {"ok": failed == 0 and not crashed and bool(tests), "passed": passed, "failed": failed,
                "tests": tests, "records": len(recs), "raw": raw[:6000] if (crashed or failed) else ""}
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def run_pipeline(p):
    if not RUN_LOCK.acquire(blocking=False):
        raise ApiError("Another run is still in progress.", 409)
    run_dir = Path(tempfile.mkdtemp(prefix="pipelab_"))
    try:
        port = free_port()
        cfg, stages, meta = build_config(p, run_dir, http_port=port)

        code = lua = None
        if meta["lua"]:
            code = load_serializer_code(meta["lua"])
            lua = find_lua()
            if not lua:
                raise ApiError("No Lua interpreter found. Install one with: brew install luajit", 409)

        if cfg is None:  # raw records straight into the serializer
            recs = parse_records(p["source"].get("text", ""))
            res = {"ok": True, "stage": "run", "duration": 0.0, "exit_code": None, "timed_out": False,
                   "stopped_early": False, "vector_version": None,
                   "stages": [stage_from_events(stages[0], recs)], "printed": None, "saved": None,
                   "log": [], "problems": [], "error": None, "last_events": recs}
        else:
            vec = find_vector()
            if not vec:
                raise ApiError("Vector is not installed yet.", 409)
            res = execute_vector(vec, cfg, stages, meta, p, run_dir, port)
            if not res.get("ok"):
                res.pop("last_events", None)
                return res

        events = res.pop("last_events", [])
        if meta["lua"]:
            started = time.time()
            ser = run_serializer(code, events, lua, run_dir)
            ser["duration"] = round(time.time() - started, 2)
            if not ser.get("ok"):
                return {"ok": False, "stage": "serializer", "error": ser.get("fatal") or "Serializer failed.",
                        "lint": ser.get("lint", []), "log": res.get("log", [])}
            outputs = ser.pop("outputs")
            lines = [json.dumps(o) for o in outputs]
            res["stages"].append({"id": "serializer", "label": "lua serializer", "kind": "transform",
                                  "events": len(lines), "bytes": sum(len(l) + 1 for l in lines),
                                  "samples": lines[:SAMPLE_LIMIT]})
            if meta["sink"] == "console":
                res["printed"] = {"events": len(lines), "lines": lines[:PRINT_LIMIT]}
            elif meta["sink"] == "file":
                OUT_DIR.mkdir(exist_ok=True)
                sp = Path(meta["saved_path"])
                sp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
                res["saved"] = {"path": str(sp), "bytes": sp.stat().st_size}
            res["serializer"] = ser
        return res
    finally:
        RUN_LOCK.release()
        shutil.rmtree(run_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Saved pipelines
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.,()&+-]{0,59}$")


def pipeline_path(name):
    if not NAME_RE.match(name or ""):
        raise ApiError("Pipeline names can use letters, numbers, spaces and . , _ - ( ) & + (max 60). Slashes and other symbols are not allowed because the name becomes a file name.")
    return PIPE_DIR / (name + ".json")


def list_pipelines():
    PIPE_DIR.mkdir(exist_ok=True)
    return [{"name": f.stem, "updated": int(f.stat().st_mtime)} for f in sorted(PIPE_DIR.glob("*.json"))]


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "PipelineLab/2.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _allowed_host(self):
        host = (self.headers.get("Host") or "").lower()
        ok = {"127.0.0.1:%d" % PORT, "localhost:%d" % PORT} | set(EXTRA_HOSTS)
        if host not in ok:
            return False
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in {"http://" + h for h in ok}:
            return False
        return True

    def _send(self, status, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj))

    def _read_json(self):
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ApiError("Content-Type must be application/json.", 415)
        n = int(self.headers.get("Content-Length") or 0)
        if n > 2 * MAX_INPUT_BYTES:
            raise ApiError("Request too large.", 413)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError("Request body is not valid JSON.")

    def _dispatch(self, method):
        if not self._allowed_host():
            return self._json(403, {"error": "Forbidden host or origin."})
        path = self.path.split("?", 1)[0]
        try:
            if method == "GET" and path in ("/", "/index.html"):
                return self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            if method == "GET" and path == "/api/status":
                vec, lua = find_vector(), find_lua()
                return self._json(200, {
                    "vector": bool(vec), "version": vector_version(vec) if vec else None,
                    "lua": bool(lua), "lua_path": lua, "docker": IN_DOCKER, "busted": bool(find_busted()),
                    "install": "brew trust vectordotdev/brew && brew tap vectordotdev/brew && brew install vector",
                    "install_lua": "brew install luajit"})
            if method == "GET" and path == "/api/pipelines":
                return self._json(200, list_pipelines())
            m = re.match(r"^/api/pipelines/(.+)$", path)
            if m:
                name = unquote(m.group(1))
                f = pipeline_path(name)
                if method == "GET":
                    if not f.exists():
                        raise ApiError("No such pipeline.", 404)
                    return self._send(200, f.read_text())
                if method == "PUT":
                    body = self._read_json()
                    PIPE_DIR.mkdir(exist_ok=True)
                    body["name"] = name
                    f.write_text(json.dumps(body, indent=2))
                    return self._json(200, {"ok": True})
                if method == "DELETE":
                    if f.exists():
                        f.unlink()
                    return self._json(200, {"ok": True})
            if method == "POST" and path == "/api/config":
                cfg, _s, meta = build_config(self._read_json(), "<run-dir>", http_port=8686)
                note = None
                if cfg is None:
                    note = "No Vector config: with a raw record source and no Vector steps, the record goes straight to the Lua serializer."
                elif meta["lua"]:
                    note = "The Lua serializer is not part of this config. It runs after Vector, in lua_runner.lua, and the destination applies to its output."
                return self._json(200, {"config": cfg, "note": note})
            if method == "POST" and path == "/api/generate":
                b = self._read_json()
                return self._json(200, generate_serializer(b.get("text", ""), b.get("vendor", ""), b.get("product", ""), b.get("version", "")))
            if method == "POST" and path == "/api/busted":
                return self._json(200, run_busted(self._read_json()))
            if method == "POST" and path == "/api/validate":
                return self._json(200, validate_pipeline(self._read_json()))
            if method == "POST" and path == "/api/run":
                return self._json(200, run_pipeline(self._read_json()))
            raise ApiError("Not found.", 404)
        except ApiError as exc:
            return self._json(exc.status, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write("Unhandled error: %r\n" % exc)
            return self._json(500, {"error": "Internal error: %s" % exc})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def cli_generate(argv):
    """python3 server.py --generate sample.json [Vendor] [version] -> prints Lua (used by the Busted specs)."""
    text = Path(argv[0]).read_text()
    vendor = argv[1] if len(argv) > 1 else ""
    version = argv[2] if len(argv) > 2 else ""
    sys.stdout.write(generate_serializer(text, vendor, vendor, version)["code"])


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--generate":
        return cli_generate(sys.argv[2:])
    PIPE_DIR.mkdir(exist_ok=True)
    try:
        httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        sys.exit("Could not listen on %s:%d (%s). Try PORT=9000 python3 server.py" % (HOST, PORT, exc))
    vec, lua = find_vector(), find_lua()
    print("Trickle running at http://127.0.0.1:%d (listening on %s)" % (PORT, HOST))
    print("Vector: %s" % (vector_version(vec) if vec else "NOT FOUND. Install with: brew trust vectordotdev/brew && brew tap vectordotdev/brew && brew install vector"))
    print("Lua:    %s" % (lua if lua else "NOT FOUND (needed for the serializer step). Install with: brew install luajit"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
