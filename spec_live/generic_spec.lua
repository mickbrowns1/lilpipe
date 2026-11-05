-- Generic checks run by the Trickle "Run Busted" button. OCSF-specific checks run only when the
-- serializer produces OCSF events (class_uid or type_uid present); otherwise they are skipped.
-- Inputs come from the environment: SERIALIZER_PATH (the Lua serializer) and
-- SAMPLE_PATH (a Lua file that returns an array of raw records).

local SER = assert(os.getenv("SERIALIZER_PATH"), "SERIALIZER_PATH not set")
local SAMPLE = assert(os.getenv("SAMPLE_PATH"), "SAMPLE_PATH not set")

processEvent = nil
assert(loadfile(SER))()
local process = assert(processEvent, "serializer did not define processEvent")
processEvent = nil
local records = assert(loadfile(SAMPLE))()

-- flatten a table to leaf values, skipping a top-level key
local function leaves(t, skip, out, prefix)
    out = out or {}
    prefix = prefix or ""
    for k, v in pairs(t) do
        if not (prefix == "" and k == skip) then
            if type(v) == "table" then leaves(v, skip, out, prefix .. tostring(k) .. ".")
            else out[prefix .. tostring(k)] = v end
        end
    end
    return out
end

-- value at a dotted path: nested tables, literal dotted keys ("dataSource.name"), or a mix
local function get(t, path)
    if type(t) ~= "table" then return nil end
    if t[path] ~= nil then return t[path] end
    local pos = 1
    while true do
        local dot = string.find(path, ".", pos, true)
        if not dot then return nil end
        local head, rest = string.sub(path, 1, dot - 1), string.sub(path, dot + 1)
        if type(t[head]) == "table" then
            local v = get(t[head], rest)
            if v ~= nil then return v end
        end
        pos = dot + 1
    end
end

local ocsf = false
for _, rec in ipairs(records) do
    local ok, o = pcall(process, rec)
    if ok and type(o) == "table" and (o.class_uid ~= nil or o.type_uid ~= nil) then ocsf = true; break end
end

-- schema-specific checks are skipped, not failed, when the output is not OCSF
local function ocsf_it(name, fn)
    if ocsf then it(name, fn) else pending(name .. " (skipped: output is not OCSF)") end
end

for i, rec in ipairs(records) do
    describe("record " .. i, function()
        local out
        setup(function() out = process(rec) end)

        it("returns a table", function() assert.is_table(out) end)

        ocsf_it("sets class_uid, category_uid and activity_id as numbers", function()
            assert.is_number(out.class_uid)
            assert.is_number(out.category_uid)
            assert.is_number(out.activity_id)
        end)

        ocsf_it("type_uid equals class_uid * 100 + activity_id", function()
            assert.are.equal(out.class_uid * 100 + out.activity_id, out.type_uid)
        end)

        ocsf_it("time is a number in epoch milliseconds", function()
            assert.is_number(out.time, "time missing or not a number")
            assert.is_true(out.time > 100000000000, "time looks like seconds, not milliseconds")
        end)

        ocsf_it("severity_id is a number", function() assert.is_number(out.severity_id) end)

        ocsf_it("metadata.version is set", function()
            assert.is_table(out.metadata)
            assert.is_string(out.metadata.version)
        end)

        ocsf_it("metadata.product.vendor_name and name are set", function()
            local p = out.metadata and out.metadata.product
            assert.is_table(p, "metadata.product missing")
            assert.is_truthy(p.vendor_name ~= nil and p.vendor_name ~= "")
            assert.is_truthy(p.name ~= nil and p.name ~= "")
        end)

        ocsf_it("dataSource.* is set and mirrors metadata.product.*", function()
            assert.is_truthy(get(out, "dataSource.name"), "dataSource missing (needed for XDR search)")
            local cat = get(out, "dataSource.category")
            assert.is_truthy(cat ~= nil and cat ~= "", "dataSource.category missing")
            assert.are.equal(get(out, "metadata.product.vendor_name"), get(out, "dataSource.vendor"))
            assert.are.equal(get(out, "metadata.product.name"), get(out, "dataSource.name"))
        end)

        if not ocsf then
            it("dataSource.name is set (detections match on it)", function()
                local n = get(out, "dataSource.name")
                assert.is_truthy(n ~= nil and n ~= "", "dataSource.name missing")
            end)
        end

        it("does not keep the original message (no raw_data)", function()
            assert.is_nil(get(out, "raw_data"), "raw_data should not be set: drop the original message after parsing")
        end)

        it("does not copy values already mapped into other fields into unmapped", function()
            local mapped, unm = {}, {}
            for k, v in pairs(leaves(out)) do
                if string.sub(k, 1, 9) == "unmapped." then unm[k] = v
                elseif type(v) == "string" and #v >= 4 then mapped[v] = true end
            end
            for k, v in pairs(unm) do
                if type(v) == "string" and #v >= 4 and mapped[v] then
                    error(k .. " duplicates a value already in a mapped field (" .. v .. ")")
                end
            end
        end)
    end)
end

describe("edge cases", function()
    it("does not crash on an empty record", function()
        assert.is_true(pcall(process, {}))
    end)
end)
