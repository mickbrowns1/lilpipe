"""Non-JSON log formats for Trickle Auto Detect.

Each format has a Python parser (used to detect and to preview) and a Lua mirror
(embedded in the generated serializer). Both must return the same flat fields.

Formats: PAN-OS CSV, XML events, Apache/Nginx access, header-row tables
(CSV, TSV, pipe, space, W3C, Zeek) and a small grok-style pattern language.
"""
import calendar
import csv
import io
import re
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# PAN-OS (Palo Alto) syslog: comma separated, log type in the 4th column.
# Column order from the PAN-OS Syslog Field Descriptions. "-" is a FUTURE_USE column.
# https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions
# ---------------------------------------------------------------------------
_TRAFFIC = """- receive_time serial type subtype - time_generated src dst natsrc natdst rule srcuser dstuser app vsys from to
inbound_if outbound_if logset - sessionid repeatcnt sport dport natsport natdport flags proto action bytes bytes_sent
bytes_received packets start elapsed category - seqno actionflags srcloc dstloc - pkts_sent pkts_received
session_end_reason dg_hier_level_1 dg_hier_level_2 dg_hier_level_3 dg_hier_level_4 vsys_name device_name action_source
src_uuid dst_uuid tunnelid monitortag parent_session_id parent_start_time tunnel assoc_id chunks chunks_sent
chunks_received rule_uuid http2_connection link_change_count policy_id link_switches sdwan_cluster sdwan_device_type
sdwan_cluster_type sdwan_site dynusergroup_name xff_ip src_category src_profile src_model src_vendor src_osfamily
src_osversion src_host src_mac dst_category dst_profile dst_model dst_vendor dst_osfamily dst_osversion dst_host
dst_mac container_id pod_namespace pod_name src_edl dst_edl hostid serialnumber src_dag dst_dag session_owner
high_res_timestamp nssai_sst nssai_sd subcategory_of_app category_of_app technology_of_app risk_of_app
characteristic_of_app container_of_app tunneled_app is_saas_of_app sanctioned_state_of_app offloaded flow_type
cluster_name ai_traffic ai_fwd_error k8s_cluster_id tcp_rtt_c2s tcp_rtt_s2c total_n_ooseq_c2s total_n_ooseq_s2c
tcp_retransit_cnt_c2s tcp_retransit_cnt_s2c tcp_zero_window_cnt_c2s tcp_zero_window_cnt_s2c src_adv_dev_id
dst_adv_dev_id"""

_THREAT = """- receive_time serial type subtype - time_generated src dst natsrc natdst rule srcuser dstuser app vsys from to
inbound_if outbound_if logset - sessionid repeatcnt sport dport natsport natdport flags proto action misc threatid
category severity direction seqno actionflags srcloc dstloc - contenttype pcap_id filedigest cloud url_idx user_agent
filetype xff referer sender subject recipient reportid dg_hier_level_1 dg_hier_level_2 dg_hier_level_3
dg_hier_level_4 vsys_name device_name - src_uuid dst_uuid http_method tunnel_id monitortag parent_session_id
parent_start_time tunnel thr_category contentver - assoc_id ppid http_headers url_category_list rule_uuid
http2_connection dynusergroup_name xff_ip src_category src_profile src_model src_vendor src_osfamily src_osversion
src_host src_mac dst_category dst_profile dst_model dst_vendor dst_osfamily dst_osversion dst_host dst_mac
container_id pod_namespace pod_name src_edl dst_edl hostid serialnumber domain_edl src_dag dst_dag partial_hash
high_res_timestamp reason justification nssai_sst subcategory_of_app category_of_app technology_of_app risk_of_app
characteristic_of_app container_of_app tunneled_app is_saas_of_app sanctioned_state_of_app cloud_reportid flow_type
cluster_name"""

_GENERIC = "- receive_time serial type subtype - time_generated"


def _cols(s):
    return ["" if c == "-" else c for c in s.split()]


PANOS_SETS = {"traffic": _cols(_TRAFFIC), "threat": _cols(_THREAT), "generic": _cols(_GENERIC)}
# log type column value -> column set. URL is the old name for URL Filtering, which shares the Threat layout.
PANOS_TYPES = {"TRAFFIC": "traffic", "THREAT": "threat", "URL": "threat", "WILDFIRE": "threat", "DATA": "threat",
               "SYSTEM": "generic", "CONFIG": "generic", "GLOBALPROTECT": "generic", "USERID": "generic",
               "DECRYPTION": "generic", "HIPMATCH": "generic", "AUTHENTICATION": "generic", "SCTP": "generic",
               "TUNNEL": "generic", "CORRELATION": "generic", "IPTAG": "generic", "AUDIT": "generic"}


def split_csv(line):
    try:
        rows = list(csv.reader([line], strict=False))
    except csv.Error:
        return None
    return rows[0] if rows else None


def parse_panos(payload):
    fields = split_csv(payload.strip())
    if not fields or len(fields) < 8:
        return None
    for i in range(2, 6):
        if i < len(fields) and fields[i].strip().upper() in PANOS_TYPES:
            break
    else:
        return None
    off = i - 3                                   # the type is column 3 (0 based) in every PAN-OS layout
    cols = PANOS_SETS[PANOS_TYPES[fields[i].strip().upper()]]
    rec = {}
    for pos, val in enumerate(fields):
        j = pos - off
        if j < 0 or val == "":
            continue
        name = cols[j] if j < len(cols) else "field%d" % j
        if name:
            rec[name] = val
    return rec


def panos_lua_cols(ptype):
    """Lua table text for the column set used by this log type (plus its aliases)."""
    key = PANOS_TYPES.get((ptype or "").upper(), "generic")
    cols = PANOS_SETS[key]
    names = sorted(t for t, k in PANOS_TYPES.items() if k == key)
    return key, names, cols


# ---------------------------------------------------------------------------
# XML events (Windows event XML, generic). Elements become dotted paths, the root name is dropped,
# attributes become path.attr, and <Data Name="x"> becomes parentpath.x.
# ---------------------------------------------------------------------------
def _tag(t):
    return t.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def parse_xml(payload):
    p = payload.strip()
    if not re.match(r"^<[A-Za-z_?!]", p) or not p.endswith(">"):
        return None
    try:
        root = ET.fromstring(p)
    except ET.ParseError:
        return None
    rec = {}

    def put(k, v):
        if k and v is not None and v != "":
            rec[k] = v

    def walk(el, key):
        name = _tag(el.tag)
        attrs = {_tag(k): v for k, v in el.attrib.items()}
        if name == "Data" and attrs.get("Name"):
            pass                                   # key was already built from the Name attribute
        for an, av in attrs.items():
            if name == "Data" and an == "Name":
                continue
            put((key + "." if key else "") + an, av)
        text = (el.text or "").strip()
        if text:
            put(key, text)
        for ch in el:
            cname = _tag(ch.tag)
            cattrs = {_tag(k): v for k, v in ch.attrib.items()}
            if cname == "Data" and cattrs.get("Name"):
                ckey = (key + "." if key else "") + cattrs["Name"]
            else:
                ckey = (key + "." if key else "") + cname
            walk(ch, ckey)

    walk(root, "")
    return rec if rec else None


# ---------------------------------------------------------------------------
# Apache / Nginx access log (common and combined)
# ---------------------------------------------------------------------------
APACHE_RE = re.compile(r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) ?(\S*)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?')
_MON = {m.lower(): i for i, m in enumerate(calendar.month_abbr) if m}


def apache_time_ms(ts):
    m = re.match(r"^(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+) ([+-])(\d\d)(\d\d)", ts)
    if not m or m.group(2).lower() not in _MON:
        return None
    d, mon, y, h, mi, s = int(m.group(1)), _MON[m.group(2).lower()], int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6))
    ms = calendar.timegm((y, mon, d, h, mi, s)) * 1000
    off = (int(m.group(8)) * 3600 + int(m.group(9)) * 60) * 1000
    return ms - off if m.group(7) == "+" else ms + off


def parse_apache(payload):
    m = APACHE_RE.match(payload.strip())
    if not m:
        return None
    rec = {"client_ip": m.group(1), "method": m.group(5), "url": m.group(6), "status": m.group(8)}
    if m.group(2) != "-":
        rec["ident"] = m.group(2)
    if m.group(3) != "-":
        rec["remote_user"] = m.group(3)
    t = apache_time_ms(m.group(4))
    if t is not None:
        rec["time"] = t
    if m.group(7):
        rec["protocol"] = m.group(7)
    if m.group(9) != "-":
        rec["bytes"] = m.group(9)
    if m.group(10) not in (None, "-", ""):
        rec["referer"] = m.group(10)
    if m.group(11) not in (None, "-", ""):
        rec["user_agent"] = m.group(11)
    return rec


# ---------------------------------------------------------------------------
# Header-row tables: CSV, TSV, pipe, semicolon, space, W3C (#Fields:) and Zeek (#fields)
# ---------------------------------------------------------------------------
_IDENT = re.compile(r"^[A-Za-z_@][\w .@\-/()]*$")


def _split_by(line, delim):
    if delim == ",":
        return split_csv(line) or []
    if delim == " ":
        return line.split()
    return line.split(delim)


def table_header(lines):
    """Return {"cols","delim","kind","skip"} when the first lines look like a header plus rows, else None."""
    for n, line in enumerate(lines[:20]):
        m = re.match(r"^#\s*fields:?[ \t]?(.*)$", line, re.I)
        if m:
            rest = m.group(1).strip("\r\n")
            delim = "\t" if "\t" in rest else " "
            cols = [c for c in rest.split(delim) if c]
            if len(cols) >= 2:
                skip = {i for i, l in enumerate(lines) if l.startswith("#")}
                return {"cols": cols, "delim": delim, "kind": "w3c", "skip": skip}
    if len(lines) < 2:
        return None
    for delim in (",", "\t", "|", ";", " "):
        hdr = _split_by(lines[0], delim)
        if len(hdr) < 3 or not all(_IDENT.match(h.strip()) for h in hdr):
            continue
        if all(re.match(r"^\d+$", h.strip()) for h in hdr):
            continue
        rows = lines[1:4]
        if all(len(_split_by(r, delim)) == len(hdr) for r in rows):
            return {"cols": [h.strip() for h in hdr], "delim": delim, "kind": "table", "skip": {0}}
    return None


def parse_table(line, cols, delim):
    if line.startswith("#"):
        return None
    parts = _split_by(line, delim)
    if len(parts) < 2:
        return None
    if parts[0].strip() == cols[0] and len(parts) > 1 and parts[1].strip() == (cols[1] if len(cols) > 1 else ""):
        return None
    rec = {}
    for c, v in zip(cols, parts):
        if v != "" and v != "-":
            rec[c] = v
    if "date" in rec and "time" in rec:               # W3C logs split the timestamp in two columns
        rec["time"] = rec.pop("date") + " " + rec["time"]
    return rec if rec else None


# ---------------------------------------------------------------------------
# Grok-lite: %{TYPE:field} tokens plus literal text. Compiles to a Python regex and a Lua pattern.
# ---------------------------------------------------------------------------
GROK_TYPES = {
    "INT": (r"[+-]?\d+", "[+-]?%d+"),
    "NUMBER": (r"[+-]?\d+(?:\.\d+)?", "[+-]?%d+%.?%d*"),
    "WORD": (r"\w+", "[%w_]+"),
    "NOTSPACE": (r"\S+", "%S+"),
    "DATA": (r".*?", ".-"),
    "GREEDYDATA": (r".*", ".*"),
    "IP": (r"\d{1,3}(?:\.\d{1,3}){3}", "%d+%.%d+%.%d+%.%d+"),
    "TIMESTAMP_ISO8601": (r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?", "%d%d%d%d%-%d%d%-%d%d[T ]%d%d:%d%d:%d%d[%.,]?%d*"),
    "HTTPDATE": (r"\d+/\w+/\d+:\d+:\d+:\d+ [+-]\d{4}", "%d+/%a+/%d+:%d+:%d+:%d+ [+-]%d%d%d%d"),
    "QUOTED": (r'"[^"]*"', '"[^"]*"'),
}


def _lua_lit(s):
    return "".join(c if c.isalnum() or c == " " else "%" + c for c in s)


def compile_grok(pattern):
    """Return (python_regex, lua_pattern, names). Raises ValueError with a readable message."""
    pat = (pattern or "").strip()
    if not pat:
        raise ValueError("Enter a pattern, for example %{IP:client} %{WORD:method} %{GREEDYDATA:rest}")
    py, lua, names, pos = ["^"], ["^"], [], 0
    for m in re.finditer(r"%\{([A-Z0-9_]+)(?::([A-Za-z_][\w.\-]*))?\}", pat):
        lit = pat[pos:m.start()]
        py.append(re.escape(lit))
        lua.append(_lua_lit(lit))
        t = m.group(1)
        if t not in GROK_TYPES:
            raise ValueError("Unknown pattern type %s. Available: %s" % (t, ", ".join(sorted(GROK_TYPES))))
        pre, lpre = GROK_TYPES[t]
        if m.group(2):
            names.append(m.group(2))
            py.append("(" + pre + ")")
            lua.append("(" + lpre + ")")
        else:
            py.append("(?:" + pre + ")")
            lua.append(lpre)
        pos = m.end()
    tail = pat[pos:]
    py.append(re.escape(tail))
    lua.append(_lua_lit(tail))
    if not names:
        raise ValueError("Name at least one field, for example %{IP:client}")
    py.append("$")
    lua.append("$")
    return "".join(py), "".join(lua), names


def parse_grok(line, regex, names):
    m = re.match(regex, line.strip())
    if not m:
        return None
    rec = {}
    for n, v in zip(names, m.groups()):
        if v is not None and v != "":
            rec[n] = v.strip('"') if v[:1] == '"' and v[-1:] == '"' else v
    return rec if rec else None


# ---------------------------------------------------------------------------
# Lua mirrors. Each LUA_* piece defines local functions; the generator stitches them together.
# No dollar sigils, no apostrophes in comments, single-line strings.
# ---------------------------------------------------------------------------
LUA_SPLIT = r"""
-- Split a comma separated line, honoring double quotes and doubled quotes inside them.
local function splitCsv(line)
    local out = {}
    local QUOTE = string.char(34)
    local len = string.len(line)
    local pos = 1
    while pos <= len + 1 do
        if string.sub(line, pos, pos) == QUOTE then
            local buf = {}
            pos = pos + 1
            while pos <= len do
                local ch = string.sub(line, pos, pos)
                if ch == QUOTE then
                    if string.sub(line, pos + 1, pos + 1) == QUOTE then
                        table.insert(buf, QUOTE)
                        pos = pos + 2
                    else
                        pos = pos + 1
                        break
                    end
                else
                    table.insert(buf, ch)
                    pos = pos + 1
                end
            end
            table.insert(out, table.concat(buf))
            if string.sub(line, pos, pos) == "," then pos = pos + 1 else pos = len + 2 end
        else
            local nxt = string.find(line, ",", pos, true)
            if nxt then
                table.insert(out, string.sub(line, pos, nxt - 1))
                pos = nxt + 1
            else
                table.insert(out, string.sub(line, pos))
                pos = len + 2
            end
        end
    end
    return out
end

local function splitPlain(line, delim)
    local out = {}
    local pos = 1
    while true do
        local nxt = string.find(line, delim, pos, true)
        if not nxt then
            table.insert(out, string.sub(line, pos))
            break
        end
        table.insert(out, string.sub(line, pos, nxt - 1))
        pos = nxt + string.len(delim)
    end
    return out
end
"""


def lua_panos(ptype, lua_str):
    key, names, cols = panos_lua_cols(ptype)
    colsrc = ", ".join(lua_str(c) for c in cols)
    typesrc = ", ".join("[%s] = true" % lua_str(n) for n in names)
    return LUA_SPLIT + """
-- Palo Alto PAN-OS syslog: comma separated, the log type (%s) sits in column 4.
-- Empty columns are FUTURE_USE or unset, so they are skipped.
local PANOS_TYPES = { %s }
local PANOS_COLS = { %s }

local function parsePanos(payload)
    local fields = splitCsv(payload)
    if #fields < 8 then return nil end
    local at = nil
    for i = 3, 6 do
        local t = fields[i]
        if t and PANOS_TYPES[string.upper(t)] then at = i; break end
    end
    if not at then return nil end
    local off = at - 4
    local rec = {}
    for pos = 1, #fields do
        local j = pos - off
        local v = fields[pos]
        if j >= 1 and v ~= "" then
            local name = PANOS_COLS[j]
            if name == nil then name = "field" .. (j - 1) end
            if name ~= "" then rec[name] = v end
        end
    end
    return rec
end
""" % (key.upper(), typesrc, colsrc)


LUA_XML = r"""
-- XML events: elements become dotted paths without the root name, attributes become path.attr,
-- and a Data element with a Name attribute becomes parentpath.Name (Windows event style).
local function xmlText(s)
    s = string.gsub(s, "&lt;", "<")
    s = string.gsub(s, "&gt;", ">")
    s = string.gsub(s, "&quot;", string.char(34))
    s = string.gsub(s, "&apos;", string.char(39))
    s = string.gsub(s, "&amp;", "&")
    return s
end

local function xmlLocal(name)
    return (string.match(name, "([^:]+)$"))
end

local function parseXml(payload)
    local first = string.match(payload, "^%s*<(.)")
    if not first or not string.match(first, "[%a_?!]") then return nil end
    local rec = {}
    local stack = {}
    local acc = ""
    local pos = 1
    local len = string.len(payload)
    local count = 0
    local function put(k, v)
        if k ~= "" and v ~= nil and v ~= "" then rec[k] = v; count = count + 1 end
    end
    while pos <= len do
        local lt = string.find(payload, "<", pos, true)
        if not lt then break end
        acc = acc .. string.sub(payload, pos, lt - 1)
        if string.sub(payload, lt, lt + 3) == "<!--" then
            local e = string.find(payload, "-->", lt, true)
            if not e then return nil end
            pos = e + 3
        elseif string.sub(payload, lt, lt + 8) == "<![CDATA[" then
            local e = string.find(payload, "]]>", lt, true)
            if not e then return nil end
            acc = acc .. string.sub(payload, lt + 9, e - 1)
            pos = e + 3
        elseif string.sub(payload, lt, lt + 1) == "<?" then
            local e = string.find(payload, "?>", lt, true)
            if not e then return nil end
            pos = e + 2
        elseif string.sub(payload, lt, lt + 1) == "</" then
            local gt = string.find(payload, ">", lt, true)
            if not gt then return nil end
            local top = table.remove(stack)
            if not top then return nil end
            local text = string.gsub(acc, "^%s+", "")
            text = string.gsub(text, "%s+$", "")
            put(top.key, xmlText(text))
            acc = ""
            pos = gt + 1
        else
            local gt = string.find(payload, ">", lt, true)
            if not gt then return nil end
            local inner = string.sub(payload, lt + 1, gt - 1)
            local selfClose = string.sub(inner, -1) == "/"
            if selfClose then inner = string.sub(inner, 1, -2) end
            local rawName = string.match(inner, "^([%w_:%.%-]+)")
            if not rawName then return nil end
            local name = xmlLocal(rawName)
            local attrs = {}
            local order = {}
            local attrText = string.sub(inner, string.len(rawName) + 1)
            for an, av in string.gmatch(attrText, "([%w_:%.%-]+)%s*=%s*\"([^\"]*)\"") do
                if string.sub(an, 1, 5) ~= "xmlns" then
                    local l = xmlLocal(an)
                    attrs[l] = av
                    table.insert(order, l)
                end
            end
            for an, av in string.gmatch(attrText, "([%w_:%.%-]+)%s*=%s*'([^']*)'") do
                if string.sub(an, 1, 5) ~= "xmlns" then
                    local l = xmlLocal(an)
                    attrs[l] = av
                    table.insert(order, l)
                end
            end
            local parentKey = ""
            if #stack > 0 then parentKey = stack[#stack].key end
            local prefix = parentKey
            if prefix ~= "" then prefix = prefix .. "." end
            local key
            if #stack == 0 then
                key = ""
            elseif name == "Data" and attrs.Name and attrs.Name ~= "" then
                key = prefix .. attrs.Name
            else
                key = prefix .. name
            end
            local ap = key
            if ap ~= "" then ap = ap .. "." end
            for _, an in ipairs(order) do
                if not (name == "Data" and an == "Name") then put(ap .. an, xmlText(attrs[an])) end
            end
            acc = ""
            if selfClose then
                -- no text, nothing to push
            else
                table.insert(stack, { key = key })
            end
            pos = gt + 1
        end
    end
    if count == 0 then return nil end
    return rec
end
"""


def lua_apache(lua_str):
    return r"""
-- Apache or Nginx access log (common and combined formats). Returns the time as epoch milliseconds.
local function parseApache(payload)
    local ip, ident, user, ts, method, url, proto, status, size, rest = string.match(payload, "^(%S+) (%S+) (%S+) %[([^%]]+)%] \"(%S+) (%S+) ?(%S*)\" (%d+) (%S+)(.*)$")
    if not ip then return nil end
    local rec = { client_ip = ip, method = method, url = url, status = status }
    if ident ~= "-" then rec.ident = ident end
    if user ~= "-" then rec.remote_user = user end
    local d, mon, y, h, mi, s, sign, oh, om = string.match(ts, "^(%d+)/(%a+)/(%d+):(%d+):(%d+):(%d+) ([+-])(%d%d)(%d%d)")
    if d and MONTHS[string.lower(mon)] then
        local ms = civilMs(tonumber(y), MONTHS[string.lower(mon)], tonumber(d), tonumber(h), tonumber(mi), tonumber(s))
        local off = (tonumber(oh) * 3600 + tonumber(om) * 60) * 1000
        if sign == "+" then ms = ms - off else ms = ms + off end
        rec.time = ms
    end
    if proto ~= "" then rec.protocol = proto end
    if size ~= "-" then rec.bytes = size end
    local ref, ua = string.match(rest, "^ \"([^\"]*)\" \"([^\"]*)\"")
    if ref and ref ~= "-" and ref ~= "" then rec.referer = ref end
    if ua and ua ~= "-" and ua ~= "" then rec.user_agent = ua end
    return rec
end
"""


def lua_table(cols, delim, lua_str):
    colsrc = ", ".join(lua_str(c) for c in cols)
    return LUA_SPLIT + """
-- Header-row table. The column names below came from the header line of the sample.
local TABLE_COLS = { %s }
local TABLE_DELIM = %s

local function parseTable(payload)
    if string.sub(payload, 1, 1) == "#" then return nil end
    local parts
    if TABLE_DELIM == "," then
        parts = splitCsv(payload)
    elseif TABLE_DELIM == " " then
        parts = {}
        for tok in string.gmatch(payload, "%%S+") do table.insert(parts, tok) end
    else
        parts = splitPlain(payload, TABLE_DELIM)
    end
    if #parts < 2 then return nil end
    if parts[1] == TABLE_COLS[1] and parts[2] == TABLE_COLS[2] then return nil end
    local rec = {}
    local count = 0
    for i, c in ipairs(TABLE_COLS) do
        local v = parts[i]
        if v ~= nil and v ~= "" and v ~= "-" then rec[c] = v; count = count + 1 end
    end
    if count == 0 then return nil end
    if rec.date and rec.time then
        rec.time = rec.date .. " " .. rec.time
        rec.date = nil
    end
    return rec
end
""" % (colsrc, lua_str(delim))


def lua_grok(lua_pat, names, lua_str):
    namesrc = ", ".join(lua_str(n) for n in names)
    return """
-- Custom pattern. The Lua pattern below was compiled from the grok-style text you entered.
local GROK_PATTERN = %s
local GROK_NAMES = { %s }

local function parseGrok(payload)
    local caps = { string.match(payload, GROK_PATTERN) }
    if #caps == 0 then return nil end
    local rec = {}
    for i, n in ipairs(GROK_NAMES) do
        local v = caps[i]
        if v ~= nil and v ~= "" then rec[n] = v end
    end
    return rec
end
""" % (lua_str(lua_pat), namesrc)
