-- lua_runner.lua: loads a DPM serializer and runs processEvent on each record.
--
-- Usage:  luajit lua_runner.lua serializer.lua records.lua
--   serializer.lua  defines a global function processEvent(record) -> table
--   records.lua     a Lua file that returns an array of record tables
--
-- Output: one JSON object per line on stdout.
--   {"loaded":true}                          the serializer loaded fine
--   {"fatal":"..."}                          it could not be loaded
--   {"i":1,"out":{...},"logs":[...]}         result for record 1
--   {"i":1,"error":"...","logs":[...]}       processEvent raised an error
--   {"i":1,"dropped":true,"logs":[...]}      processEvent returned nil
--
-- Works on Lua 5.1 / LuaJIT (and later). This runs on your Mac, not in the DPM
-- runtime: modules that only exist there (hmac, codec, ...) are not available.

local ser_path, rec_path = arg[1], arg[2]

-- In the real runtime JSON null arrives as userdata. io.stdout is userdata too.
local NULL = io.stdout

-- ---------------------------------------------------------------- encode ---

local ESC = { ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }

local function esc_str(s)
  local body = s:gsub('[%c"\\]', function(c)
    return ESC[c] or string.format("\\u%04x", c:byte())
  end)
  return '"' .. body .. '"'
end

local function is_array(t)
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" or k < 1 or k ~= math.floor(k) then return false end
    n = n + 1
  end
  if n == 0 then return false end
  for i = 1, n do
    if t[i] == nil then return false end
  end
  return true
end

local encode
function encode(v, depth)
  depth = depth or 0
  if depth > 60 then error("table is nested too deeply (or has a cycle)") end
  local tv = type(v)
  if tv == "string" then
    return esc_str(v)
  elseif tv == "number" then
    if v ~= v or v == math.huge or v == -math.huge then return "null" end
    if v == math.floor(v) and math.abs(v) < 1e15 then return string.format("%.0f", v) end
    return string.format("%.14g", v)
  elseif tv == "boolean" then
    return tostring(v)
  elseif tv == "table" then
    if is_array(v) then
      local o = {}
      for i = 1, #v do o[i] = encode(v[i], depth + 1) end
      return "[" .. table.concat(o, ",") .. "]"
    end
    local keys = {}
    for k in pairs(v) do keys[#keys + 1] = k end
    table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
    local o = {}
    for _, k in ipairs(keys) do
      o[#o + 1] = esc_str(tostring(k)) .. ":" .. encode(v[k], depth + 1)
    end
    return "{" .. table.concat(o, ",") .. "}"
  end
  return "null" -- nil, userdata (JSON null), functions
end

-- ---------------------------------------------------------------- decode ---

local function u8(cp)
  if cp < 128 then
    return string.char(cp)
  elseif cp < 2048 then
    return string.char(192 + math.floor(cp / 64), 128 + cp % 64)
  elseif cp < 65536 then
    return string.char(224 + math.floor(cp / 4096), 128 + math.floor(cp / 64) % 64, 128 + cp % 64)
  end
  return string.char(240 + math.floor(cp / 262144), 128 + math.floor(cp / 4096) % 64,
                     128 + math.floor(cp / 64) % 64, 128 + cp % 64)
end

local SIMPLE = { b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }

local function decode(s)
  local i = 1
  local function ws() i = s:find("%S", i) or (#s + 1) end

  local function pstr()
    local j = i + 1
    local o = {}
    while true do
      local c = s:sub(j, j)
      if c == "" then error("unterminated string") end
      if c == '"' then
        i = j + 1
        return table.concat(o)
      end
      if c == "\\" then
        local n = s:sub(j + 1, j + 1)
        if n == "u" then
          local cp = tonumber(s:sub(j + 2, j + 5), 16) or 63
          j = j + 6
          if cp >= 55296 and cp <= 56319 and s:sub(j, j + 1) == "\\u" then
            local lo = tonumber(s:sub(j + 2, j + 5), 16)
            if lo and lo >= 56320 and lo <= 57343 then
              cp = 65536 + (cp - 55296) * 1024 + (lo - 56320)
              j = j + 6
            end
          end
          o[#o + 1] = u8(cp)
        else
          o[#o + 1] = SIMPLE[n] or n
          j = j + 2
        end
      else
        o[#o + 1] = c
        j = j + 1
      end
    end
  end

  local value
  function value()
    ws()
    local c = s:sub(i, i)
    if c == "{" then
      i = i + 1
      local t = {}
      ws()
      if s:sub(i, i) == "}" then i = i + 1; return t end
      while true do
        ws()
        local k = pstr()
        ws()
        if s:sub(i, i) ~= ":" then error("expected ':' at position " .. i) end
        i = i + 1
        t[k] = value()
        ws()
        local d = s:sub(i, i)
        i = i + 1
        if d == "}" then return t end
        if d ~= "," then error("expected ',' or '}' at position " .. (i - 1)) end
      end
    elseif c == "[" then
      i = i + 1
      local t = {}
      ws()
      if s:sub(i, i) == "]" then i = i + 1; return t end
      while true do
        t[#t + 1] = value()
        ws()
        local d = s:sub(i, i)
        i = i + 1
        if d == "]" then return t end
        if d ~= "," then error("expected ',' or ']' at position " .. (i - 1)) end
      end
    elseif c == '"' then
      return pstr()
    elseif s:sub(i, i + 3) == "null" then
      i = i + 4
      return NULL
    elseif s:sub(i, i + 3) == "true" then
      i = i + 4
      return true
    elseif s:sub(i, i + 4) == "false" then
      i = i + 5
      return false
    end
    local num = s:match("^-?%d+%.?%d*[eE]?[+-]?%d*", i)
    if not num or num == "" then error("unexpected character at position " .. i) end
    i = i + #num
    return tonumber(num)
  end

  local v = value()
  ws()
  if i <= #s then error("unexpected data after the JSON value at position " .. i) end
  return v
end

-- ------------------------------------------------------------ module stubs ---

local logs = {}
local function logger(level)
  return function(m) logs[#logs + 1] = level .. ": " .. tostring(m) end
end
package.loaded["json"] = { encode = encode, decode = decode, null = NULL }
package.loaded["log"] = { debug = logger("debug"), info = logger("info"), warn = logger("warn"), error = logger("error") }

local function emit_line(t)
  local ok, line = pcall(encode, t)
  if not ok then
    line = encode({ i = t.i, error = "Could not turn the result into JSON: " .. tostring(line) })
  end
  io.stdout:write(line, "\n")
  io.stdout:flush()
end

-- ------------------------------------------------------------------- main ---

local ok, err = pcall(dofile, ser_path)
if not ok then
  emit_line({ fatal = "Could not load the serializer: " .. tostring(err) })
  return
end
if type(processEvent) ~= "function" then
  emit_line({ fatal = "The serializer must define a global function processEvent(record)." })
  return
end

local ok2, records = pcall(dofile, rec_path)
if not ok2 or type(records) ~= "table" then
  emit_line({ fatal = "Internal error reading the input records: " .. tostring(records) })
  return
end

emit_line({ loaded = true })

for i, rec in ipairs(records) do
  for k in pairs(logs) do logs[k] = nil end
  local ok3, res = pcall(processEvent, rec)
  if not ok3 then
    emit_line({ i = i, error = tostring(res), logs = logs })
  elseif res == nil then
    emit_line({ i = i, dropped = true, logs = logs })
  elseif type(res) ~= "table" then
    emit_line({ i = i, error = "processEvent returned a " .. type(res) .. ", expected a table", logs = logs })
  else
    emit_line({ i = i, out = res, logs = logs })
  end
end
