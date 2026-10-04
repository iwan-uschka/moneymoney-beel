-- Offline tests for Beel.lua. Run from the repo root: lua tests/run.lua
--
-- Stubs the MoneyMoney API (Connection, JSON, MM, LocalStorage, constants)
-- and replays synthetic responses shaped like the ones app.beel.com and
-- privy.app.beel.com returned in a recorded browser session (2026-10-04).

local SCRIPT = "Beel.lua"

-- ─────────────────────────────────────────────────────────────────────────────
-- Minimal JSON decoder (stand-in for MoneyMoney's JSON())
-- ─────────────────────────────────────────────────────────────────────────────

local function json_decode(s)
  local pos = 1
  local function ws() pos = s:find("[^ \t\r\n]", pos) or #s + 1 end
  local value
  local function str()
    local out = {}
    pos = pos + 1
    while true do
      local c = s:sub(pos, pos)
      if c == "" then error("unterminated string") end
      if c == '"' then pos = pos + 1; break end
      if c == "\\" then
        local n = s:sub(pos + 1, pos + 1)
        local map = {n = "\n", t = "\t", r = "\r", b = "\b", f = "\f", ['"'] = '"', ["\\"] = "\\", ["/"] = "/"}
        if n == "u" then
          out[#out + 1] = utf8.char(tonumber(s:sub(pos + 2, pos + 5), 16))
          pos = pos + 6
        else
          out[#out + 1] = map[n]
          pos = pos + 2
        end
      else
        out[#out + 1] = c
        pos = pos + 1
      end
    end
    return table.concat(out)
  end
  function value()
    ws()
    local c = s:sub(pos, pos)
    if c == "{" then
      local t = {}
      pos = pos + 1; ws()
      if s:sub(pos, pos) == "}" then pos = pos + 1; return t end
      while true do
        ws(); local k = str(); ws()
        assert(s:sub(pos, pos) == ":", "expected :"); pos = pos + 1
        t[k] = value(); ws()
        local d = s:sub(pos, pos); pos = pos + 1
        if d == "}" then return t end
        assert(d == ",", "expected , in object")
      end
    elseif c == "[" then
      local t = {}
      pos = pos + 1; ws()
      if s:sub(pos, pos) == "]" then pos = pos + 1; return t end
      while true do
        t[#t + 1] = value(); ws()
        local d = s:sub(pos, pos); pos = pos + 1
        if d == "]" then return t end
        assert(d == ",", "expected , in array")
      end
    elseif c == '"' then return str()
    elseif s:sub(pos, pos + 3) == "true" then pos = pos + 4; return true
    elseif s:sub(pos, pos + 4) == "false" then pos = pos + 5; return false
    elseif s:sub(pos, pos + 3) == "null" then pos = pos + 4; return nil
    else
      local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
      if not num or num == "" then error("bad json at " .. pos) end
      pos = pos + #num
      return tonumber(num)
    end
  end
  local v = value()
  ws()
  if pos <= #s then error("trailing data") end
  return v
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function b64encode(data)
  return ((data:gsub(".", function(x)
    local r, b = "", x:byte()
    for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
    if #x < 6 then return "" end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
    return B64:sub(c + 1, c + 1)
  end) .. ({"", "==", "="})[#data % 3 + 1])
end

local function b64decode(data)
  data = data:gsub("[^" .. B64 .. "=]", "")
  return (data:gsub(".", function(x)
    if x == "=" then return "" end
    local r, f = "", (B64:find(x, 1, true) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
    if #x ~= 8 then return "" end
    local c = 0
    for i = 1, 8 do c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0) end
    return string.char(c)
  end))
end

local function b64url(s) return (b64encode(s):gsub("+", "-"):gsub("/", "_"):gsub("=", "")) end

local function make_jwt(exp)
  return b64url('{"alg":"ES256","typ":"JWT"}') .. "."
      .. b64url('{"sid":"s","iss":"privy.io","sub":"did:privy:test","exp":' .. exp .. '}')
      .. ".c2ln"
end

local function urldecode(s)
  return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Sandbox: loads Beel.lua into a fresh environment with a fake server
-- ─────────────────────────────────────────────────────────────────────────────

local LOGIN_FAILED = {"LoginFailed"}

-- routes: list of {match = "<plain substring of url>", respond = function(req) -> body}
-- Unmatched requests fail the test. `now` pins os.time() for exact boundaries.
local function sandbox(routes, storage, now)
  local env = setmetatable({}, {__index = _G})
  if now then
    env.os = setmetatable({time = function(t) return t and os.time(t) or now end}, {__index = os})
  end
  local log = {requests = {}, cookies = {}}

  local conn = {}
  function conn:request(method, url, body, ctype, headers)
    local req = {method = method, url = url, body = body, ctype = ctype, headers = headers or {}}
    log.requests[#log.requests + 1] = req
    for _, r in ipairs(routes) do
      if url:find(r.match, 1, true) then return r.respond(req) end
    end
    error("unexpected request: " .. method .. " " .. url)
  end
  function conn:setCookie(c) log.cookies[#log.cookies + 1] = c end

  env.Connection = function() return conn end
  env.JSON = function(s)
    return {dictionary = function() return json_decode(s) end}
  end
  env.MM = {
    urlencode = function(s)
      return (s:gsub("[^%w%-_%.~]", function(c) return string.format("%%%02X", c:byte()) end))
    end,
    base64decode = b64decode,
  }
  env.LocalStorage = storage or {}
  env.ProtocolWebBanking = "WebBanking"
  env.AccountTypePortfolio = "AccountTypePortfolio"
  env.LoginFailed = LOGIN_FAILED
  env.WebBanking = function(t) env.__webbanking = t end

  local chunk = assert(loadfile(SCRIPT, "t", env))
  chunk()
  return env, log
end

local function requests_to(log, fragment)
  local n = 0
  for _, r in ipairs(log.requests) do
    if r.url:find(fragment, 1, true) then n = n + 1 end
  end
  return n
end

local function trpc_input(req)
  return json_decode(urldecode(req.url:match("input=(.*)$")))["0"]["json"]
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Fixtures (synthetic; shapes from the recorded session)
-- ─────────────────────────────────────────────────────────────────────────────

local EMAIL = "investor@example.org"

local function trpc_ok(json) return '[{"result":{"data":{"json":' .. json .. '}}}]' end

local function trpc_err(code, http, message)
  return '[{"error":{"json":{"message":"' .. message .. '","code":-32001,"data":{"code":"'
      .. code .. '","httpStatus":' .. http .. '}}}}]'
end

local ME = trpc_ok('{"customerId":"11111111-2222-4333-8444-555555555555","email":"' .. EMAIL
  .. '","name":"Erika","surname":"Mustermann","type":"Investor"}')

-- shares_json / price_json replace the shareAmount / pricePerToken JSON values
-- verbatim, for malformed or non-string inputs.
local function item(t)
  local price_json = t.price_json or string.format('"{\\"tickerName\\":\\"%s\\",\\"value\\":\\"%s\\"}"',
    t.ticker or "€", t.price or "21000")
  local shares_json = t.shares_json or string.format("%q", t.shares or "23809523809523809523")
  return string.format('{"companyName":%q,"itemId":%q,"pricePerToken":%s,"productType":%q,'
    .. '"shareAmount":%s,"status":%q,"tokenTickerName":%q}',
    t.company or "Muster Bau GmbH", t.id or "item-1", price_json,
    t.product or "PrivateOffer", shares_json, t.status or "Accepted", t.token or "MUB01")
end

local function list_page(items, total)
  return trpc_ok('{"records":[' .. table.concat(items, ",") .. '],"totalCount":' .. total .. '}')
end

local function privy_auth_ok(exp)
  return '{"user":{"id":"did:privy:test"},"token":"' .. make_jwt(exp)
      .. '","identity_token":"id.tok.en","refresh_token":"deprecated","is_new_user":false}'
end

local function standard_routes(overrides)
  overrides = overrides or {}
  return {
    {match = "/passwordless/init", respond = overrides.init or function() return '{"success":true}' end},
    {match = "/passwordless/authenticate", respond = overrides.auth or function()
      return privy_auth_ok(os.time() + 3600) end},
    {match = "customer.getMe", respond = overrides.me or function() return ME end},
    {match = "investor.getFundraiseListItems", respond = overrides.list or function()
      return list_page({item{}}, 1) end},
  }
end

local function login(env)
  local challenge = env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "unused"}, true)
  assert(type(challenge) == "table", "expected challenge, got " .. tostring(challenge))
  return env.InitializeSession2("WebBanking", "beel", 2, {"123456"}, true)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Tests
-- ─────────────────────────────────────────────────────────────────────────────

local tests = {}
local function test(name, fn) tests[#tests + 1] = {name = name, fn = fn} end

local function eq(actual, expected, what)
  if actual ~= expected then
    error((what or "value") .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual), 2)
  end
end

-- Relative tolerance, so tiny expected values (5e-18) are checked as strictly
-- as large ones; an expected 0 gets a small absolute tolerance instead.
local function near(actual, expected, what)
  local tol = expected == 0 and 1e-12 or 1e-9 * math.abs(expected)
  if type(actual) ~= "number" or math.abs(actual - expected) > tol then
    error((what or "value") .. ": expected ~" .. tostring(expected) .. ", got " .. tostring(actual), 2)
  end
end

local function contains(s, fragment, what)
  if type(s) ~= "string" or not s:find(fragment, 1, true) then
    error((what or "string") .. ": expected to contain '" .. fragment .. "', got " .. tostring(s), 2)
  end
end

-- breaks-if: SupportsBank stops comparing bankCode (the extension claims every bank)
test("SupportsBank accepts only the beel service", function()
  local env = sandbox({})
  eq(env.SupportsBank("WebBanking", "beel"), true)
  eq(env.SupportsBank("WebBanking", "Umweltbank"), false)
  eq(env.__webbanking.services[1], "beel")
end)

test("step 1 requests a code from Privy and returns a code challenge", function()
  local env, log = sandbox(standard_routes())
  local c = env.InitializeSession2("WebBanking", "beel", 1, {"  Investor@Example.org ", "x"}, true)
  eq(type(c), "table")
  eq(c.label, "Code")
  contains(c.challenge, EMAIL)
  local req = log.requests[1]
  eq(req.method, "POST")
  eq(req.body, '{"email":"' .. EMAIL .. '"}', "init body (trimmed, lower-cased)")
  eq(req.ctype, "application/json")
  eq(req.headers["privy-app-id"], "cm8epvw1k00dkuxlpmreca9n2")
  eq(req.headers["Origin"], "https://app.beel.com")
  eq(requests_to(log, "customer.getMe"), 0, "no cached token, so no getMe probe")
end)

test("step 2 exchanges the code, sets privy cookies and caches the token", function()
  local storage = {}
  local env, log = sandbox(standard_routes(), storage)
  eq(login(env), nil, "login result")
  local auth
  for _, r in ipairs(log.requests) do
    if r.url:find("/passwordless/authenticate", 1, true) then auth = r end
  end
  eq(auth.body, '{"email":"' .. EMAIL .. '","code":"123456","mode":"login-or-sign-up"}')
  contains(log.cookies[1], "privy-token=" .. storage.privyToken)
  contains(log.cookies[1], "Domain=app.beel.com")
  contains(log.cookies[2], "privy-id-token=id.tok.en")
  eq(storage.privyEmail, EMAIL)
  eq(storage.privyIdToken, "id.tok.en")
end)

test("code with surrounding/inner spaces is accepted", function()
  local env, log = sandbox(standard_routes())
  env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)
  eq(env.InitializeSession2("WebBanking", "beel", 2, {" 123 456 "}, true), nil)
  contains(log.requests[#log.requests - 1].body, '"code":"123456"')
end)

-- breaks-if: the email format check in step 1 is removed (Privy gets called with garbage)
test("step 1 rejects a username that is not an email, without network", function()
  local env, log = sandbox(standard_routes())
  contains(env.InitializeSession2("WebBanking", "beel", 1, {"erika", "x"}, true), "E-Mail-Adresse")
  contains(env.InitializeSession2("WebBanking", "beel", 1, {"", "x"}, true), "E-Mail-Adresse")
  contains(env.InitializeSession2("WebBanking", "beel", 1, {nil, "x"}, true), "E-Mail-Adresse")
  eq(#log.requests, 0)
end)

-- breaks-if: the 6-digit check is loosened (e.g. %d+), spending Privy's 5-requests-per-window rate limit on typos
test("step 2 rejects codes that are not exactly 6 digits, without network", function()
  for _, bad in ipairs({"12345", "1234567", "12a456", "", "١٢٣٤٥٦"}) do
    local env, log = sandbox(standard_routes())
    env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)
    local before = #log.requests
    contains(env.InitializeSession2("WebBanking", "beel", 2, {bad}, true), "6 Ziffern", "code '" .. bad .. "'")
    eq(#log.requests, before, "no request for code '" .. bad .. "'")
  end
end)

-- breaks-if: step 2 stops checking dict.token and treats any Privy response as success
test("step 2 reports Privy's error for a wrong code and caches nothing", function()
  local storage = {}
  local env, log = sandbox(standard_routes{
    auth = function() return '{"error":"Invalid code"}' end,
  }, storage)
  env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)
  local r = env.InitializeSession2("WebBanking", "beel", 2, {"000000"}, true)
  contains(r, "Invalid code")
  eq(storage.privyToken, nil)
  eq(#log.cookies, 0)
end)

-- breaks-if: the is_new_user guard is dropped (a typo'd email silently creates a Privy account)
test("step 2 refuses a freshly created Privy user", function()
  local env = sandbox(standard_routes{
    auth = function() return '{"token":"' .. make_jwt(os.time() + 3600) .. '","is_new_user":true}' end,
  })
  env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)
  contains(env.InitializeSession2("WebBanking", "beel", 2, {"123456"}, true), "kein beel-Konto")
end)

-- breaks-if: privy_post stops wrapping connection:request in pcall (raw transport error leaks)
test("Privy transport failure becomes a readable error", function()
  local env = sandbox(standard_routes{init = function() error("timeout") end})
  local ok, err = pcall(env.InitializeSession2, "WebBanking", "beel", 1, {EMAIL, "x"}, true)
  eq(ok, false)
  contains(err, "Verbindung zu Privy fehlgeschlagen")
end)

-- breaks-if: privy_post drops the non-JSON check (JSON parse error surfaces instead)
test("Privy HTML/non-JSON answer becomes a readable error", function()
  local env = sandbox(standard_routes{init = function() return "<html>blocked</html>" end})
  local ok, err = pcall(env.InitializeSession2, "WebBanking", "beel", 1, {EMAIL, "x"}, true)
  eq(ok, false)
  contains(err, "kein JSON")
end)

-- breaks-if: the success flag of passwordless/init is ignored
test("step 1 reports a rejected code request", function()
  local env = sandbox(standard_routes{init = function() return '{"error":"Too many requests"}' end})
  contains(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true), "Too many requests")
end)

-- breaks-if: step 2 skips the getMe check and caches a token beel does not accept
test("step 2 fails when beel rejects the Privy token", function()
  local storage = {}
  local env = sandbox(standard_routes{
    me = function() return trpc_err("UNAUTHORIZED", 401, "Not logged in") end,
  }, storage)
  local r = login(env)
  contains(r, "nicht akzeptiert")
  contains(r, "Not logged in")
  eq(storage.privyToken, nil)
end)

test("a valid cached token skips the email code", function()
  local token = make_jwt(os.time() + 3600)
  local storage = {privyToken = token, privyIdToken = "id", privyEmail = EMAIL}
  local env, log = sandbox(standard_routes(), storage)
  eq(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, false), nil)
  eq(requests_to(log, "/passwordless/"), 0)
  contains(log.cookies[1], "privy-token=" .. token)
end)

-- breaks-if: try_cached_session stops comparing privyEmail (another account's token gets reused)
test("a cached token for a different email is not used", function()
  local storage = {privyToken = make_jwt(os.time() + 3600), privyEmail = "other@example.org"}
  local env, log = sandbox(standard_routes(), storage)
  eq(type(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)), "table")
  eq(requests_to(log, "customer.getMe"), 0)
  eq(requests_to(log, "/passwordless/init"), 1)
end)

-- breaks-if: the TOKEN_MIN_REMAINING margin is removed (token expires mid-sync)
test("a cached token that expires within 5 minutes is discarded", function()
  local now = 1800000000
  local storage = {privyToken = make_jwt(now + 299), privyEmail = EMAIL}
  local env, log = sandbox(standard_routes(), storage, now)
  eq(type(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)), "table")
  eq(requests_to(log, "customer.getMe"), 0)
  eq(storage.privyToken, nil, "expired token cleared")
end)

-- breaks-if: the remaining-validity check becomes "<=" (a token with exactly 300 s left is dropped)
test("a cached token with exactly 5 minutes left is used (boundary)", function()
  local now = 1800000000
  local storage = {privyToken = make_jwt(now + 300), privyEmail = EMAIL}
  local env = sandbox(standard_routes(), storage, now)
  eq(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true), nil)
end)

-- breaks-if: jwt_exp errors on malformed tokens instead of returning nil
test("a malformed cached token is discarded", function()
  local storage = {privyToken = "not-a-jwt", privyEmail = EMAIL}
  local env = sandbox(standard_routes(), storage)
  eq(type(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)), "table")
  eq(storage.privyToken, nil)
end)

-- breaks-if: a cached token beel rejects is kept instead of falling back to a new code
test("a cached token beel rejects falls back to the email code", function()
  local storage = {privyToken = make_jwt(os.time() + 3600), privyEmail = EMAIL}
  local env, log = sandbox(standard_routes{
    me = function() return trpc_err("UNAUTHORIZED", 401, "Not logged in") end,
  }, storage)
  eq(type(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)), "table")
  eq(requests_to(log, "/passwordless/init"), 1)
  eq(storage.privyToken, nil)
end)

-- breaks-if: try_cached_session clears the token on any getMe failure, not only UNAUTHORIZED
test("a network error while probing a cached token keeps the token", function()
  local token = make_jwt(os.time() + 3600)
  local storage = {privyToken = token, privyEmail = EMAIL}
  local env = sandbox(standard_routes{me = function() error("timeout") end}, storage)
  eq(type(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true)), "table")
  eq(storage.privyToken, token)
end)

-- breaks-if: ListAccounts stops clearing the cached token when getMe answers UNAUTHORIZED
test("ListAccounts clears the cached token when beel rejects it", function()
  local storage = {privyToken = make_jwt(os.time() + 3600), privyEmail = EMAIL}
  local env = sandbox(standard_routes{
    me = function() return trpc_err("UNAUTHORIZED", 401, "Not logged in") end,
  }, storage)
  local ok, err = pcall(env.ListAccounts, {})
  eq(ok, false)
  contains(err, "Not logged in")
  eq(storage.privyToken, nil)
end)

-- breaks-if: trpc_query returns nil, nil for a result without data.json again
test("a tRPC result without data errors with a readable message", function()
  local env = sandbox(standard_routes{list = function() return '[{"result":{"data":null}}]' end})
  login(env)
  local ok, err = pcall(env.RefreshAccount, {}, nil)
  eq(ok, false)
  contains(err, "leere tRPC-Antwort")
end)

-- breaks-if: the interactive == false guard is removed (background sync triggers an email)
test("non-interactive sync without a usable token sends no email", function()
  local env, log = sandbox(standard_routes())
  contains(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, false), "manuell")
  eq(requests_to(log, "/passwordless/init"), 0)
end)

-- breaks-if: the g_email guard in step 2 is removed (Privy gets "email":"" or the script crashes)
test("step 2 without step 1 asks to restart the login, without network", function()
  local env, log = sandbox(standard_routes())
  contains(env.InitializeSession2("WebBanking", "beel", 2, {"123456"}, true), "erneut starten")
  eq(#log.requests, 0)
end)

test("ListAccounts loads the customer itself when the session was reused elsewhere", function()
  local env, log = sandbox(standard_routes())
  local accounts = env.ListAccounts({})
  eq(accounts[1].accountNumber, "11111111-2222-4333-8444-555555555555")
  eq(requests_to(log, "customer.getMe"), 1)
end)

test("ListAccounts returns one portfolio account for the customer", function()
  local env = sandbox(standard_routes())
  login(env)
  local accounts = env.ListAccounts({})
  eq(#accounts, 1)
  eq(accounts[1].accountNumber, "11111111-2222-4333-8444-555555555555")
  eq(accounts[1].owner, "Erika Mustermann")
  eq(accounts[1].portfolio, true)
  eq(accounts[1].type, "AccountTypePortfolio")
  eq(accounts[1].currency, "EUR")
end)

test("RefreshAccount converts 18-decimal tokens and 2-decimal euro prices", function()
  local env, log = sandbox(standard_routes())
  login(env)
  local r = env.RefreshAccount({}, nil)
  eq(#r.securities, 1)
  local s = r.securities[1]
  eq(s.name, "Muster Bau GmbH (MUB01)")
  eq(s.securityNumber, "MUB01")
  near(s.quantity, 23.809523809523809523, "quantity")
  near(s.price, 210, "price")
  eq(s.currencyOfPrice, "EUR")
  near(s.purchasePrice, 210, "purchasePrice")
  near(s.amount, 5000, "amount")
  near(r.balance, 5000, "balance")
  eq(r.currency, "EUR")
  local input
  for _, q in ipairs(log.requests) do
    if q.url:find("getFundraiseListItems", 1, true) then input = trpc_input(q) end
  end
  eq(input.paginationAndSearchInput.pageSize, 50)
  eq(input.paginationAndSearchInput.pageIndex, 0)
  eq(input.statusFilter, "all")
end)

test("token amount boundaries: fewer digits than decimals, exactly 18, zero", function()
  local env = sandbox(standard_routes{list = function()
    return list_page({
      item{id = "a", shares = "5"},
      item{id = "b", shares = "500000000000000000"},
      item{id = "c", shares = "1000000000000000000"},
      item{id = "d", shares = "0"},
    }, 4)
  end})
  login(env)
  local s = env.RefreshAccount({}, nil).securities
  near(s[1].quantity, 5e-18, "5 units")
  near(s[2].quantity, 0.5, "18 digits")
  near(s[3].quantity, 1, "19 digits")
  eq(s[4].quantity, 0, "zero")
end)

test("a numeric or negative shareAmount still converts", function()
  local env = sandbox(standard_routes{list = function()
    return list_page({
      item{id = "n", shares_json = "1000000000000000000"},
      item{id = "m", shares = "-2000000000000000000"},
    }, 2)
  end})
  login(env)
  local s = env.RefreshAccount({}, nil).securities
  near(s[1].quantity, 1, "JSON number")
  near(s[2].quantity, -2, "negative string")
end)

-- breaks-if: the "^%-?%d+$" check in fixed_to_number is removed (garbage parses as a quantity)
test("malformed amounts and prices leave the position unvalued", function()
  local env = sandbox(standard_routes{list = function()
    return list_page({
      item{id = "d", shares = "1.5"},
      item{id = "a", shares = "abc"},
      item{id = "p", price_json = '"not json"'},
    }, 3)
  end})
  login(env)
  local r = env.RefreshAccount({}, nil)
  eq(r.securities[1].quantity, nil, "decimal string")
  eq(r.securities[1].amount, nil)
  eq(r.securities[2].quantity, nil, "letters")
  eq(r.securities[3].price, nil, "garbage pricePerToken")
  eq(r.securities[3].amount, nil)
  eq(r.balance, 0)
end)

-- breaks-if: unknown tickers (currency nil) are counted into the EUR balance again
test("an unknown price ticker uses 2 decimals and stays out of the EUR balance", function()
  local env = sandbox(standard_routes{list = function()
    return list_page({item{ticker = "CHF", price = "12345", shares = "1000000000000000000"}}, 1)
  end})
  login(env)
  local r = env.RefreshAccount({}, nil)
  near(r.securities[1].price, 123.45, "2 decimals")
  eq(r.securities[1].currencyOfPrice, nil)
  eq(r.securities[1].amount, nil)
  eq(r.balance, 0)
end)

-- breaks-if: amount is set for non-EUR prices (the currency check in security_from_item is removed)
test("stablecoin prices use their own decimals and stay out of the EUR balance", function()
  local env = sandbox(standard_routes{list = function()
    return list_page({
      item{id = "u", ticker = "USDC", price = "2500000", shares = "2000000000000000000"},
      item{id = "e", ticker = "EURe", price = "3000000000000000000", shares = "1000000000000000000"},
    }, 2)
  end})
  login(env)
  local r = env.RefreshAccount({}, nil)
  near(r.securities[1].price, 2.5, "USDC 6 decimals")
  eq(r.securities[1].currencyOfPrice, "USD")
  eq(r.securities[1].amount, nil, "no EUR amount for USD price")
  near(r.securities[2].price, 3, "EURe 18 decimals")
  eq(r.securities[2].currencyOfPrice, "EUR")
  near(r.balance, 3, "balance counts EUR positions only")
end)

-- breaks-if: HOLDING_STATUSES filtering is removed (pending/cancelled offers show up as holdings)
test("only held items become securities", function()
  local env = sandbox(standard_routes{list = function()
    return list_page({
      item{id = "1", status = "Accepted"},
      item{id = "2", status = "Pending"},
      item{id = "3", status = "Cancelled"},
      item{id = "4", status = "Successful", product = "PublicFundraising", company = "Public AG"},
      item{id = "5", status = "Burned"},
      item{id = "6", status = "RejectedByInvestor"},
    }, 6)
  end})
  login(env)
  local s = env.RefreshAccount({}, nil).securities
  eq(#s, 2)
  eq(s[2].name, "Public AG (MUB01)")
end)

test("pagination fetches the next page when totalCount exceeds 50", function()
  local pages = {}
  local env, log = sandbox(standard_routes{list = function(req)
    local p = trpc_input(req).paginationAndSearchInput.pageIndex
    pages[#pages + 1] = p
    local items = {}
    local n = (p == 0) and 50 or 1
    for i = 1, n do items[i] = item{id = p .. "-" .. i} end
    return list_page(items, 51)
  end})
  login(env)
  eq(#env.RefreshAccount({}, nil).securities, 51)
  eq(#pages, 2)
  eq(pages[2], 1)
end)

test("pagination stops after one page when totalCount is exactly 50", function()
  local calls = 0
  local env = sandbox(standard_routes{list = function()
    calls = calls + 1
    local items = {}
    for i = 1, 50 do items[i] = item{id = tostring(i)} end
    return list_page(items, 50)
  end})
  login(env)
  eq(#env.RefreshAccount({}, nil).securities, 50)
  eq(calls, 1)
end)

-- breaks-if: the "#records == 0" break is removed (an inflated totalCount loops until MAX_PAGES)
test("pagination stops on an empty page even if totalCount claims more", function()
  local calls = 0
  local env = sandbox(standard_routes{list = function(req)
    calls = calls + 1
    if trpc_input(req).paginationAndSearchInput.pageIndex == 0 then
      return list_page({item{}}, 999)
    end
    return list_page({}, 999)
  end})
  login(env)
  eq(#env.RefreshAccount({}, nil).securities, 1)
  eq(calls, 2)
end)

-- breaks-if: MAX_PAGES bound is removed (a server repeating full pages loops forever)
test("pagination is capped at 40 pages", function()
  local calls = 0
  local env = sandbox(standard_routes{list = function()
    calls = calls + 1
    return list_page({item{}}, 1000000)
  end})
  login(env)
  env.RefreshAccount({}, nil)
  eq(calls, 40)
end)

test("no investments yields an empty portfolio", function()
  local env = sandbox(standard_routes{list = function() return list_page({}, 0) end})
  login(env)
  local r = env.RefreshAccount({}, nil)
  eq(#r.securities, 0)
  eq(r.balance, 0)
end)

-- breaks-if: fetch_list_items stops checking the tRPC error / stops clearing the cached token
test("an expired session on the list call errors and clears the cached token", function()
  local storage = {}
  local env = sandbox(standard_routes{list = function()
    return trpc_err("UNAUTHORIZED", 401, "Session expired")
  end}, storage)
  login(env)
  local ok, err = pcall(env.RefreshAccount, {}, nil)
  eq(ok, false)
  contains(err, "Session expired")
  eq(storage.privyToken, nil)
end)

-- breaks-if: trpc_query stops guarding against non-JSON bodies
test("a non-JSON list response errors readably and keeps the token", function()
  local storage = {}
  local env = sandbox(standard_routes{list = function() return "<html>502</html>" end}, storage)
  login(env)
  local ok, err = pcall(env.RefreshAccount, {}, nil)
  eq(ok, false)
  contains(err, "keine gültige tRPC-Antwort")
  eq(type(storage.privyToken), "string", "non-auth failure keeps the token")
end)

-- breaks-if: trpc_query stops wrapping connection:request in pcall
test("a transport error on the list call errors readably and keeps the token", function()
  local storage = {}
  local env = sandbox(standard_routes{list = function() error("HTTP 503") end}, storage)
  login(env)
  local ok, err = pcall(env.RefreshAccount, {}, nil)
  eq(ok, false)
  contains(err, "HTTP 503")
  eq(type(storage.privyToken), "string")
end)

-- breaks-if: is_unauthorized drops the FORBIDDEN code or the "401" message fallback
test("FORBIDDEN and a transport 401 also clear the cached token", function()
  local cases = {
    function() return trpc_err("FORBIDDEN", 403, "Forbidden") end,
    function() error("HTTP 401 Unauthorized") end,
  }
  for i, respond in ipairs(cases) do
    local storage = {}
    local env = sandbox(standard_routes{list = respond}, storage)
    login(env)
    eq(pcall(env.RefreshAccount, {}, nil), false, "case " .. i)
    eq(storage.privyToken, nil, "case " .. i .. " token")
  end
end)

-- breaks-if: is_unauthorized matches every tRPC error code (a server error logs the user out)
test("a tRPC server error keeps the cached token", function()
  local storage = {}
  local env = sandbox(standard_routes{list = function()
    return trpc_err("INTERNAL_SERVER_ERROR", 500, "boom")
  end}, storage)
  login(env)
  local ok, err = pcall(env.RefreshAccount, {}, nil)
  eq(ok, false)
  contains(err, "boom")
  eq(type(storage.privyToken), "string")
end)

-- breaks-if: EndSession stops clearing g_email / g_me (stale session state leaks into the next sync)
test("EndSession resets session state but keeps the cached token", function()
  local env, log = sandbox(standard_routes(), {})
  login(env)
  env.EndSession()
  contains(env.InitializeSession2("WebBanking", "beel", 2, {"123456"}, true), "erneut starten",
           "g_email cleared")
  env.ListAccounts({})
  eq(requests_to(log, "customer.getMe"), 2, "g_me cleared, so ListAccounts reloads it")
  env.EndSession()
  -- The cached token survives, so step 1 reuses it with a fresh getMe probe.
  eq(env.InitializeSession2("WebBanking", "beel", 1, {EMAIL, "x"}, true), nil)
  eq(requests_to(log, "/passwordless/init"), 1, "no second email")
  eq(requests_to(log, "customer.getMe"), 3)
end)

-- ─────────────────────────────────────────────────────────────────────────────

local failed = 0
for _, t in ipairs(tests) do
  local ok, err = pcall(t.fn)
  if ok then
    print("ok   " .. t.name)
  else
    failed = failed + 1
    print("FAIL " .. t.name .. "\n     " .. tostring(err))
  end
end
print(string.format("\n%d tests, %d failed", #tests, failed))
os.exit(failed == 0 and 0 or 1)
