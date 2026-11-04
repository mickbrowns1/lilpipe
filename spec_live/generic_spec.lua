-- Generic OCSF checks run by the Trickle "Run Busted" button.
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

for i, rec in ipairs(records) do
    describe("record " .. i, function()
        local out
        setup(function() out = process(rec) end)

        it("returns a table", function() assert.is_table(out) end)

        it("sets class_uid, category_uid and activity_id as numbers", function()
            assert.is_number(out.class_uid)
            assert.is_number(out.category_uid)
            assert.is_number(out.activity_id)
        end)

        it("type_uid equals class_uid * 100 + activity_id", function()
            assert.are.equal(out.class_uid * 100 + out.activity_id, out.type_uid)
        end)

        it("time is a number in epoch milliseconds", function()
            assert.is_number(out.time, "time missing or not a number")
            assert.is_true(out.time > 100000000000, "time looks like seconds, not milliseconds")
        end)

        it("severity_id is a number", function() assert.is_number(out.severity_id) end)

        it("metadata.version is set", function()
            assert.is_table(out.metadata)
            assert.is_string(out.metadata.version)
        end)

        it("metadata.product.vendor_name and name are set", function()
            local p = out.metadata and out.metadata.product
            assert.is_table(p, "metadata.product missing")
            assert.is_truthy(p.vendor_name ~= nil and p.vendor_name ~= "")
            assert.is_truthy(p.name ~= nil and p.name ~= "")
        end)

        it("dataSource.* is set and mirrors metadata.product.*", function()
            local ds = out.dataSource
            assert.is_table(ds, "dataSource missing (needed for XDR search)")
            assert.is_truthy(ds.category ~= nil and ds.category ~= "")
            assert.are.equal(out.metadata.product.vendor_name, ds.vendor)
            assert.are.equal(out.metadata.product.name, ds.name)
        end)

        it("does not copy values already mapped into OCSF fields into unmapped", function()
            if type(out.unmapped) ~= "table" then return end
            local mapped = {}
            for _, v in pairs(leaves(out, "unmapped")) do
                if type(v) == "string" and #v >= 4 then mapped[v] = true end
            end
            for k, v in pairs(leaves(out.unmapped)) do
                if type(v) == "string" and #v >= 4 and mapped[v] then
                    error("unmapped." .. k .. " duplicates a value already in an OCSF field (" .. v .. ")")
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
