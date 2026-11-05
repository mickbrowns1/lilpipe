-- Busted specs for OCSF serializers. Run from the project root:  busted spec
-- Checks the Pipeline Lab generator output on a Cato sample record.

local SAMPLE_PATH = "spec/fixtures_cato_event.json"

local function read(path)
    local f = assert(io.open(path, "r"))
    local s = f:read("*a")
    f:close()
    return s
end

-- Tiny JSON object reader: the fixture is a flat object of string values.
local function load_sample()
    local t = {}
    for k, v in string.gmatch(read(SAMPLE_PATH), '"([^"]+)"%s*:%s*"([^"]*)"') do t[k] = v end
    return t
end

-- Load a serializer file and return its processEvent without leaking the global.
local function load_serializer(path)
    local chunk = assert(loadfile(path))
    processEvent = nil
    chunk()
    local fn = assert(processEvent, "serializer did not define processEvent")
    processEvent = nil
    return fn
end

local function generated_path()
    local out = os.tmpname()
    local cmd = string.format('python3 server.py --generate %s "Cato Networks" > %s', SAMPLE_PATH, out)
    assert(os.execute(cmd) == 0 or os.execute(cmd) == true, "generator failed")
    return out
end

local targets = {
    { name = "generated from the sample record",  path = generated_path() },
}

for _, target in ipairs(targets) do
    describe(target.name, function()
        local process, out
        setup(function()
            process = load_serializer(target.path)
            out = process(load_sample())
        end)

        it("classifies the IPS event as a Detection Finding", function()
            assert.are.equal(2004, out.class_uid)
            assert.are.equal(2, out.category_uid)
            assert.are.equal("Detection Finding", out.class_name)
        end)

        it("computes type_uid = class_uid * 100 + activity_id", function()
            assert.are.equal(out.class_uid * 100 + out.activity_id, out.type_uid)
        end)

        it("sets time as epoch milliseconds (number)", function()
            assert.are.equal("number", type(out.time))
            assert.are.equal(1650596005910, out.time)
        end)

        it("stamps OCSF 1.8.0", function()
            assert.are.equal("1.8.0", out.metadata.version)
        end)

        it("mirrors metadata.product.* into dataSource.*", function()
            assert.are.equal(out.metadata.product.vendor_name, out.dataSource.vendor)
            assert.are.equal(out.metadata.product.name, out.dataSource.name)
            assert.are.equal("security", out.dataSource.category)
            assert.is_truthy(out.dataSource.vendor ~= "")
        end)

        it("maps severity and disposition", function()
            assert.are.equal(3, out.severity_id)
            assert.are.equal("Medium", out.severity)
            assert.are.equal(2, out.disposition_id)
        end)

        it("maps endpoints with numeric ports", function()
            assert.are.equal("203.0.113.9", out.src_endpoint.ip)
            assert.are.equal(47046, out.src_endpoint.port)
            assert.are.equal("10.1.2.3", out.dst_endpoint.ip)
            assert.are.equal(445, out.dst_endpoint.port)
        end)

        it("fills finding_info and malware", function()
            assert.are.equal("ET SCAN SMB", out.finding_info.title)
            assert.are.equal("Scan", out.finding_info.types[1])
            assert.are.equal("2024897", out.finding_info.uid)
            assert.are.equal("ET SCAN SMB", out.malware[1].name)
            assert.is_truthy(out.finding_info.product_uid)
        end)

        it("names the feature as event_type / event_sub_type", function()
            assert.are.equal("Security / IPS", out.metadata.product.feature.name)
        end)

        it("lists the IPs as observables", function()
            local seen = {}
            for _, o in ipairs(out.observables) do seen[o.value] = o.type_id end
            assert.are.equal(2, seen["203.0.113.9"])
            assert.are.equal(2, seen["10.1.2.3"])
        end)

        it("does not keep the original message or raw_data", function()
            assert.is_nil(out.raw_data)
        end)

        it("keeps only true leftovers under unmapped", function()
            assert.are.equal("false", out.unmapped.src_is_site_or_vpn)
            assert.are.equal("false", out.unmapped.dest_is_site_or_vpn)
            assert.are.equal("IPS", out.unmapped.event_sub_type)
            -- values already placed in OCSF fields must NOT be duplicated
            for _, k in ipairs({ "action", "risk_level", "time", "event_time",
                                 "src_ip", "dest_ip", "src_port", "dest_port",
                                 "threat_name", "rule", "ip_protocol" }) do
                assert.is_nil(out.unmapped[k], k .. " leaked into unmapped")
            end
        end)

        it("does not crash on an empty record and still stamps required fields", function()
            local o = process({})
            assert.is_table(o)
            assert.are.equal("1.8.0", o.metadata.version)
            assert.is_table(o.dataSource)
        end)

        it("accepts an ISO time when no epoch field is present", function()
            local ev = load_sample()
            ev.time = nil
            assert.are.equal(1650596005000, process(ev).time)
        end)
    end)
end
