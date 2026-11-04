-- Cato Networks eventsFeed (Security / IPS) -> OCSF 1.8.0 serializer.
-- Pipeline processor stage: one raw Cato record in, one OCSF object out.
--
-- Class choice: Security events with a threat_name or signature are mapped to
-- Detection Finding (2004). Security events without one are Network Activity
-- (4001). Anything else is Base Event (0). Change CLASS below to switch.
--
-- Rules honored: no dollar-sigil tokens, single-line strings, plain ASCII
-- comments, no trailing string continuation, Lua 5.1 syntax only.

local OCSF_VERSION = "1.8.0"
local VENDOR_NAME  = "Cato Networks"
local PRODUCT_NAME = "Cato SASE"

-- Cato field -> OCSF dotted path. Arrays use [0].
local FIELD_MAPPINGS = {
    THREAT = {
        { source = "src_ip",         target = "src_endpoint.ip" },
        { source = "src_port",       target = "src_endpoint.port", number = true },
        { source = "src_country",    target = "src_endpoint.location.country" },
        { source = "src_site",       target = "src_endpoint.hostname" },
        { source = "dest_ip",        target = "dst_endpoint.ip" },
        { source = "dest_port",      target = "dst_endpoint.port", number = true },
        { source = "ip_protocol",    target = "connection_info.protocol_name" },
        { source = "traffic_direction", target = "connection_info.direction" },
        { source = "os_type",        target = "device.os.name" },
        { source = "rule",           target = "firewall_rule.name" },
        { source = "rule_id",        target = "firewall_rule.uid" },
        { source = "threat_name",    target = "finding_info.title" },
        { source = "threat_type",    target = "finding_info.types[0]" },
        { source = "signature_id",   target = "finding_info.uid" },
        { source = "threat_reference", target = "finding_info.src_url" },
        { source = "threat_name",    target = "malware[0].name" },
        { source = "event_count",    target = "count", number = true },
        { source = "internalId",     target = "metadata.uid" },
        { source = "account_id",     target = "cloud.account.uid" },
        { source = "pop_name",       target = "cloud.region" },
    },
    NETWORK = {
        { source = "src_ip",         target = "src_endpoint.ip" },
        { source = "src_port",       target = "src_endpoint.port", number = true },
        { source = "src_country",    target = "src_endpoint.location.country" },
        { source = "src_site",       target = "src_endpoint.hostname" },
        { source = "dest_ip",        target = "dst_endpoint.ip" },
        { source = "dest_port",      target = "dst_endpoint.port", number = true },
        { source = "ip_protocol",    target = "connection_info.protocol_name" },
        { source = "traffic_direction", target = "connection_info.direction" },
        { source = "os_type",        target = "device.os.name" },
        { source = "rule",           target = "firewall_rule.name" },
        { source = "rule_id",        target = "firewall_rule.uid" },
        { source = "event_count",    target = "count", number = true },
        { source = "internalId",     target = "metadata.uid" },
        { source = "account_id",     target = "cloud.account.uid" },
        { source = "pop_name",       target = "cloud.region" },
    },
    GENERIC = {},
}

-- Fields consumed by the constant section or helpers (not unmapped).
local CONSUMED = {
    time = true, event_time = true, event_timestamp = true,
    action = true, risk_level = true,
    mitre_attack_tactics = true, mitre_attack_techniques = true,
    mitre_attack_subtechniques = true,
}

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

local function isEmpty(v)
    if v == nil or v == "" then return true end
    if type(v) == "table" and next(v) == nil then return true end
    return false
end

-- Time: epoch ms (number or digit string, seconds are scaled up) or ISO-8601 UTC.
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

local SEVERITY = { info = 1, informational = 1, low = 2, medium = 3, high = 4, critical = 5 }

local function getSeverityId(level)
    return SEVERITY[string.lower(tostring(level or ""))] or 0
end

local function getDispositionId(action)
    local a = string.lower(tostring(action or ""))
    if a == "allow" or a == "allowed" then return 1
    elseif a == "block" or a == "blocked" or a == "deny" or a == "denied" then return 2
    elseif a == "drop" or a == "dropped" then return 6
    elseif a == "monitor" or a == "alert" then return 15 end
    return 99
end

local DIRECTION = { inbound = 1, outbound = 2 }

local function resolveType(e)
    local et = e.event_type or ""
    if et == "Security" then
        if not isEmpty(e.threat_name) or not isEmpty(e.signature_id) then return "THREAT" end
        return "NETWORK"
    end
    if et == "Internet Access" or et == "WAN" then return "NETWORK" end
    return "GENERIC"
end

local CLASS      = { THREAT = 2004, NETWORK = 4001, GENERIC = 0 }
local CLASS_NAME = { THREAT = "Detection Finding", NETWORK = "Network Activity", GENERIC = "Base Event" }
local CAT        = { THREAT = 2, NETWORK = 4, GENERIC = 0 }
local CAT_NAME   = { [2] = "Findings", [4] = "Network Activity", [0] = "Uncategorized" }

local function getActivityId(t, action)
    if t == "THREAT" then return 1 end
    if t == "NETWORK" then
        local a = string.lower(tostring(action or ""))
        if a == "allow" or a == "allowed" then return 1 end
        if a == "block" or a == "blocked" or a == "deny" or a == "drop" then return 5 end
        return 6
    end
    return 0
end

local function listOf(v)
    if isEmpty(v) then return {} end
    if type(v) == "table" then return v end
    return { v }
end

local function addObservable(obs, name, type_id, value)
    if not isEmpty(value) then
        table.insert(obs, { name = name, type_id = type_id, value = tostring(value) })
    end
end

function processEvent(event)
    if event == nil then return {} end
    local e = event
    if type(event.message) == "table" then e = event.message end

    local t = resolveType(e)
    local class_uid = CLASS[t]
    local cat_uid = CAT[t]
    local activity_id = getActivityId(t, e.action)
    local r = {}

    setNestedField(r, "class_uid", class_uid)
    setNestedField(r, "class_name", CLASS_NAME[t])
    setNestedField(r, "category_uid", cat_uid)
    setNestedField(r, "category_name", CAT_NAME[cat_uid])
    setNestedField(r, "activity_id", activity_id)
    setNestedField(r, "type_uid", class_uid * 100 + activity_id)
    setNestedField(r, "severity_id", getSeverityId(e.risk_level))
    if not isEmpty(e.risk_level) then setNestedField(r, "severity", e.risk_level) end
    setNestedField(r, "status_id", 1)
    if not isEmpty(e.action) then
        setNestedField(r, "action", e.action)
        setNestedField(r, "disposition_id", getDispositionId(e.action))
    end

    -- time: prefer the epoch field, fall back to the ISO fields
    local ms = toEpochMs(e.time) or toEpochMs(e.event_timestamp) or toEpochMs(e.event_time)
    if ms then setNestedField(r, "time", ms) end

    -- metadata and dataSource (dataSource mirrors metadata.product for XDR search)
    setNestedField(r, "metadata.version", OCSF_VERSION)
    setNestedField(r, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(r, "metadata.product.name", PRODUCT_NAME)
    setNestedField(r, "dataSource.category", "security")
    setNestedField(r, "dataSource.vendor", VENDOR_NAME)
    setNestedField(r, "dataSource.name", PRODUCT_NAME)
    setNestedField(r, "metadata.product.feature.name", tostring(e.event_type or "") .. " / " .. tostring(e.event_sub_type or ""))
    if t == "THREAT" then setNestedField(r, "finding_info.product_uid", "cato_sase") end

    -- direction id
    local dir = DIRECTION[string.lower(tostring(e.traffic_direction or ""))]
    if dir then setNestedField(r, "connection_info.direction_id", dir) end

    -- field mappings
    local maps = FIELD_MAPPINGS[t] or FIELD_MAPPINGS.GENERIC
    local mapped = {}
    for _, m in ipairs(maps) do
        mapped[m.source] = true
        local v = e[m.source]
        if not isEmpty(v) then
            if m.number then v = tonumber(v) or v end
            setNestedField(r, m.target, v)
        end
    end

    -- MITRE ATT&CK (threat findings only; empty arrays are skipped)
    if t == "THREAT" then
        local tactics = listOf(e.mitre_attack_tactics)
        local techs = listOf(e.mitre_attack_techniques)
        local subs = listOf(e.mitre_attack_subtechniques)
        local n = math.max(#tactics, #techs, #subs)
        for i = 1, n do
            local base = "finding_info.attacks[" .. (i - 1) .. "]"
            if tactics[i] then setNestedField(r, base .. ".tactic.name", tostring(tactics[i])) end
            if techs[i] then setNestedField(r, base .. ".technique.name", tostring(techs[i])) end
            if subs[i] then setNestedField(r, base .. ".sub_technique.name", tostring(subs[i])) end
        end
    end

    -- observables
    local obs = {}
    addObservable(obs, "src_endpoint.ip", 2, e.src_ip)
    addObservable(obs, "dst_endpoint.ip", 2, e.dest_ip)
    addObservable(obs, "src_endpoint.hostname", 1, e.src_site)
    if #obs > 0 then r.observables = obs end

    -- unmapped: everything not mapped or consumed, lossless
    for k, v in pairs(e) do
        if not mapped[k] and not CONSUMED[k] and not isEmpty(v) then
            setNestedField(r, "unmapped." .. k, v)
        end
    end

    return r
end
