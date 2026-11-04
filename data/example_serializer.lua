-- Starter serializer (edit me). Input: one raw record table. Output: a flat OCSF table.
-- Runs here on LuaJIT, not inside the DPM runtime, so only json and log modules exist.
local VENDOR_NAME = "Cato Networks"
local PRODUCT_NAME = "Cato SASE"
local OCSF_VERSION = "1.1.0"

-- Raw fields this serializer maps. Everything else is kept under unmapped.
local MAPPED = { src_ip = true, dest_ip = true, src_port = true, dest_port = true,
                 ip_protocol = true, action = true, risk_level = true, time = true }

local SEVERITY = { Low = 2, Medium = 3, High = 4, Critical = 5 }

function processEvent(record)
    local out = {}
    out["class_uid"] = 4001
    out["category_uid"] = 4
    out["activity_id"] = 6
    out["type_uid"] = 4001 * 100 + 6
    out["time"] = tonumber(record.time) or 0
    out["severity_id"] = SEVERITY[record.risk_level] or 0
    out["action"] = record.action
    out["src_endpoint.ip"] = record.src_ip
    out["src_endpoint.port"] = tonumber(record.src_port)
    out["dst_endpoint.ip"] = record.dest_ip
    out["dst_endpoint.port"] = tonumber(record.dest_port)
    out["connection_info.protocol_name"] = record.ip_protocol

    out["metadata.version"] = OCSF_VERSION
    out["metadata.product.vendor_name"] = VENDOR_NAME
    out["metadata.product.name"] = PRODUCT_NAME
    out["dataSource.category"] = "security"
    out["dataSource.vendor"] = VENDOR_NAME
    out["dataSource.name"] = PRODUCT_NAME

    local unmapped = {}
    for k, v in pairs(record) do
        if not MAPPED[k] then unmapped[k] = v end
    end
    out["unmapped"] = unmapped
    return out
end
