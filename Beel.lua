-- MoneyMoney Extension: beel (formerly tokenize.it)
--
-- beel authenticates through Privy (privy.app.beel.com) with a passwordless
-- email login: Privy mails a 6-digit code, the code is exchanged for a Privy
-- access token, and the beel web app's tRPC API accepts that token as the
-- `privy-token` cookie. The extension asks for the code in MoneyMoney's
-- two-step login dialog.
--
-- Privy tokens are valid for one hour. The extension keeps the last token in
-- LocalStorage and reuses it while it is valid, so syncs within that hour need
-- no new code.

local BASE       = "https://app.beel.com"
local PRIVY_BASE = "https://privy.app.beel.com"
local COOKIE_DOMAIN = "app.beel.com"

-- Public identifiers of beel's Privy app, as sent by app.beel.com.
local PRIVY_APP_ID    = "cm8epvw1k00dkuxlpmreca9n2"
local PRIVY_CLIENT_ID = "client-WY5i1UjWoFXHDzfFAvjJsK2NKbGAkZUJEK9ypaY1DLX9y"
local PRIVY_CLIENT    = "react-auth:3.22.2"

local PRIVY_INIT_ENDPOINT = PRIVY_BASE .. "/api/v1/passwordless/init"
local PRIVY_AUTH_ENDPOINT = PRIVY_BASE .. "/api/v1/passwordless/authenticate"
local TRPC_BASE           = BASE .. "/api/trpc/"

-- The server rejects pageSize > 50 (MAX_PAGE_SIZE in the web app).
local PAGE_SIZE = 50
-- Upper bound on list pages, so a server that keeps reporting a larger
-- totalCount cannot keep the sync looping.
local MAX_PAGES = 40

-- A cached token is only reused if it stays valid at least this long.
local TOKEN_MIN_REMAINING = 300

-- Token amounts (shareAmount) are integers with 18 implied decimals.
local TOKEN_DECIMALS = 18

-- Currency amounts (pricePerToken.value) are integers whose implied decimals
-- depend on the ticker: Circle stablecoins 6, Monerium EURe 18, fiat 2.
local CURRENCY_DECIMALS = {USDC = 6, EUROC = 6, EURe = 18}
local CURRENCY_ISO = {["€"] = "EUR", EUROC = "EUR", EURe = "EUR", USDC = "USD", ["$"] = "USD"}

-- List item statuses that mean the investor holds the tokens. Pending,
-- cancelled, rejected, expired, failed and burned items are skipped.
local HOLDING_STATUSES = {
  Accepted   = true,  -- PrivateOffer
  Successful = true,  -- PublicFundraising
  Active     = true,  -- EmployeeParticipationPlan
  Fulfilled  = true,  -- EmployeeParticipationPlan
}

-- ─────────────────────────────────────────────────────────────────────────────
-- Session state (module-level; persists across InitializeSession2 steps)
-- ─────────────────────────────────────────────────────────────────────────────

local g_email = nil   -- login email from step 1, reused for the code exchange
local g_me    = nil   -- customer.getMe result of the authenticated session
local g_ca_id = nil   -- per-session Privy client analytics id (random UUID)

WebBanking {
  version     = 1.0,
  url         = BASE,
  services    = {"beel"},
  description = "beel (ehemals tokenize.it) Investments via E-Mail-Code",
}

local connection = Connection()

function SupportsBank(protocol, bankCode)
  return protocol == ProtocolWebBanking and bankCode == "beel"
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Helpers
-- ─────────────────────────────────────────────────────────────────────────────

local function trim(s)
  return (tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function json_str(s)
  return '"' .. tostring(s):gsub('[%c"\\]', function(c)
    if c == '"' then return '\\"' end
    if c == "\\" then return "\\\\" end
    return string.format("\\u%04x", c:byte())
  end) .. '"'
end

local function uuid4()
  return (string.gsub("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx", "[xy]", function(c)
    local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
    return string.format("%x", v)
  end))
end

-- Parses a JSON body; returns nil instead of raising on a non-JSON body.
local function parse_json(body)
  if type(body) ~= "string" or body == "" then return nil end
  local ok, dict = pcall(function() return JSON(body):dictionary() end)
  if ok and type(dict) == "table" then return dict end
  return nil
end

-- Reads the exp claim of a JWT. Returns nil if the token is malformed.
local function jwt_exp(token)
  local payload = type(token) == "string" and token:match("^[^.]+%.([^.]+)%.")
  if not payload then return nil end
  payload = payload:gsub("-", "+"):gsub("_", "/")
  payload = payload .. string.rep("=", (4 - #payload % 4) % 4)
  local ok, decoded = pcall(MM.base64decode, payload)
  if not ok or type(decoded) ~= "string" then return nil end
  return tonumber(decoded:match('"exp"%s*:%s*(%d+)'))
end

-- Converts an integer string with `decimals` implied decimal places
-- ("23809523809523809523", 18) to a number (23.809523809523809523).
-- Converting via string keeps 20-digit values exact up to double precision.
local function fixed_to_number(s, decimals)
  if type(s) == "number" then s = string.format("%.0f", s) end
  if type(s) ~= "string" or not s:match("^%-?%d+$") then return nil end
  local negative = s:sub(1, 1) == "-"
  if negative then s = s:sub(2) end
  local n
  if decimals == 0 then
    n = tonumber(s)
  else
    if #s <= decimals then s = string.rep("0", decimals - #s + 1) .. s end
    n = tonumber(s:sub(1, -decimals - 1) .. "." .. s:sub(-decimals))
  end
  return negative and -n or n
end

-- Decodes a serialized Currency ('{"tickerName":"€","value":"21000"}').
-- Returns amount, ISO currency (nil if the ticker is unknown).
local function parse_currency(serialized)
  local c = type(serialized) == "table" and serialized or parse_json(serialized)
  if not c then return nil, nil end
  local ticker = c["tickerName"]
  local decimals = CURRENCY_DECIMALS[ticker] or 2
  return fixed_to_number(c["value"], decimals), CURRENCY_ISO[ticker]
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Privy (authentication)
-- ─────────────────────────────────────────────────────────────────────────────

local function privy_headers()
  g_ca_id = g_ca_id or uuid4()
  return {
    ["Accept"]          = "application/json",
    ["Origin"]          = BASE,
    ["Referer"]         = BASE .. "/",
    ["privy-app-id"]    = PRIVY_APP_ID,
    ["privy-client-id"] = PRIVY_CLIENT_ID,
    ["privy-client"]    = PRIVY_CLIENT,
    ["privy-ca-id"]     = g_ca_id,
  }
end

-- POSTs JSON to Privy. Returns the parsed response, or raises with a message
-- naming `what` if the request fails or the body is not JSON.
local function privy_post(url, body, what)
  local ok, resp = pcall(function()
    return connection:request("POST", url, body, "application/json", privy_headers())
  end)
  if not ok then
    error(what .. ": Verbindung zu Privy fehlgeschlagen (" .. tostring(resp) .. ").")
  end
  local dict = parse_json(resp)
  if not dict then
    error(what .. ": unerwartete Antwort von Privy (kein JSON).")
  end
  return dict
end

local function privy_error_text(dict)
  local e = dict["error"]
  if type(e) == "table" then e = e["message"] or e["error"] end
  return tostring(e or dict["message"] or "unbekannter Fehler")
end

local function set_session_cookies(token, id_token)
  connection:setCookie("privy-token=" .. token .. "; Domain=" .. COOKIE_DOMAIN .. "; Path=/; Secure")
  if id_token then
    connection:setCookie("privy-id-token=" .. id_token .. "; Domain=" .. COOKIE_DOMAIN .. "; Path=/; Secure")
  end
  connection:setCookie("privy-session=t; Domain=" .. COOKIE_DOMAIN .. "; Path=/; Secure")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- beel tRPC API
-- ─────────────────────────────────────────────────────────────────────────────

local TRPC_NULL_INPUT = '{"json":null,"meta":{"values":["undefined"],"v":1}}'

-- Calls a tRPC query (batch of one). Returns data on success, or nil plus an
-- error table {code = "...", message = "..."} on a tRPC or transport error.
local function trpc_query(procedure, input_json)
  local url = TRPC_BASE .. procedure .. "?batch=1&input="
    .. MM.urlencode('{"0":' .. (input_json or TRPC_NULL_INPUT) .. '}')
  local ok, resp = pcall(function()
    return connection:request("GET", url, nil, nil, {
      ["Accept"]  = "*/*",
      ["Referer"] = BASE .. "/investor/dashboard/investments",
    })
  end)
  if not ok then
    return nil, {code = "TRANSPORT", message = tostring(resp)}
  end
  local dict = parse_json(resp)
  local entry = dict and dict[1]
  if type(entry) ~= "table" then
    return nil, {code = "BAD_RESPONSE", message = "keine gültige tRPC-Antwort"}
  end
  if entry["error"] then
    local e = entry["error"]["json"] or entry["error"]
    local data = type(e["data"]) == "table" and e["data"] or {}
    return nil, {code = tostring(data["code"] or "ERROR"), message = tostring(e["message"] or "")}
  end
  local result = entry["result"]
  local data = result and result["data"]
  return data and data["json"], nil
end

local function is_unauthorized(err)
  return err and (err.code == "UNAUTHORIZED" or err.code == "FORBIDDEN"
                  or err.message:find("401", 1, true) ~= nil)
end

-- Loads the current customer; true if the session cookies are accepted.
local function load_me()
  local me, err = trpc_query("customer.getMe")
  if type(me) == "table" and me["customerId"] then
    g_me = me
    return true
  end
  return false, err
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Token cache (LocalStorage)
-- ─────────────────────────────────────────────────────────────────────────────

local function clear_cached_token()
  LocalStorage.privyToken   = nil
  LocalStorage.privyIdToken = nil
  LocalStorage.privyEmail   = nil
end

-- Reuses a stored token for `email` if it is valid long enough and beel still
-- accepts it. Returns true on success.
local function try_cached_session(email)
  local token = LocalStorage.privyToken
  if not token or LocalStorage.privyEmail ~= email then return false end
  local exp = jwt_exp(token)
  if not exp or exp - os.time() < TOKEN_MIN_REMAINING then
    clear_cached_token()
    return false
  end
  set_session_cookies(token, LocalStorage.privyIdToken)
  if load_me() then return true end
  clear_cached_token()
  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MoneyMoney extension
-- ─────────────────────────────────────────────────────────────────────────────

-- Step 1: username = login email. Reuses a cached token or requests a code.
-- Step 2: credentials[1] = the 6-digit code from the email.
function InitializeSession2(protocol, bankCode, step, credentials, interactive)
  if step == 1 then
    local email = trim(credentials and credentials[1]):lower()
    if not email:match("^[^@%s]+@[^@%s]+%.[^@%s]+$") then
      return "Bitte die E-Mail-Adresse des beel-Kontos als Benutzername eintragen."
    end
    g_email = email

    if try_cached_session(email) then return nil end

    if interactive == false then
      return "beel benötigt einen neuen Code per E-Mail. "
          .. "Bitte das Konto manuell aktualisieren."
    end

    local dict = privy_post(PRIVY_INIT_ENDPOINT, '{"email":' .. json_str(email) .. '}',
                            "Code anfordern")
    if dict["success"] ~= true then
      return "Code anfordern fehlgeschlagen: " .. privy_error_text(dict)
    end

    return {
      title     = "beel Login",
      challenge = "beel hat einen 6-stelligen Code an " .. email .. " gesendet. "
               .. "Bitte den Code aus der E-Mail eingeben.",
      label     = "Code",
    }
  end

  local code = trim(credentials and credentials[1]):gsub("%s", "")
  if not code:match("^%d%d%d%d%d%d$") then
    return "Der Code muss aus 6 Ziffern bestehen."
  end

  local dict = privy_post(PRIVY_AUTH_ENDPOINT,
    '{"email":' .. json_str(g_email or "") .. ',"code":' .. json_str(code)
      .. ',"mode":"login-or-sign-up"}',
    "Code prüfen")
  local token = dict["token"]
  if type(token) ~= "string" or token == "" then
    return "Code prüfen fehlgeschlagen: " .. privy_error_text(dict)
  end
  if dict["is_new_user"] == true then
    return "Zu dieser E-Mail-Adresse gibt es kein beel-Konto."
  end

  set_session_cookies(token, dict["identity_token"])
  local ok, err = load_me()
  if not ok then
    return "beel hat die Anmeldung nicht akzeptiert"
        .. (err and err.message ~= "" and (": " .. err.message) or ".")
  end

  LocalStorage.privyToken   = token
  LocalStorage.privyIdToken = dict["identity_token"]
  LocalStorage.privyEmail   = g_email
  return nil
end

function ListAccounts(knownAccounts)
  if not g_me then
    local ok, err = load_me()
    if not ok then error("customer.getMe fehlgeschlagen: " .. tostring(err and err.message)) end
  end
  local owner = trim((g_me["name"] or "") .. " " .. (g_me["surname"] or ""))
  return {{
    name          = "beel",
    owner         = owner ~= "" and owner or nil,
    accountNumber = tostring(g_me["customerId"]),
    currency      = "EUR",
    portfolio     = true,
    type          = AccountTypePortfolio,
  }}
end

local function list_input(page_index)
  return '{"json":{"paginationAndSearchInput":{"pageIndex":' .. page_index
      .. ',"pageSize":' .. PAGE_SIZE .. ',"searchQuery":""},'
      .. '"productTypeFilter":"All","statusFilter":"all"}}'
end

-- Fetches all investment list items across pages.
local function fetch_list_items()
  local items = {}
  for page = 0, MAX_PAGES - 1 do
    local data, err = trpc_query("investor.getFundraiseListItems", list_input(page))
    if not data then
      if is_unauthorized(err) then clear_cached_token() end
      error("Investments konnten nicht geladen werden: " .. tostring(err and err.message))
    end
    local records = data["records"] or {}
    for _, r in ipairs(records) do items[#items + 1] = r end
    local total = tonumber(data["totalCount"]) or 0
    if #records == 0 or #items >= total then break end
  end
  return items
end

local function security_from_item(item)
  local quantity = fixed_to_number(item["shareAmount"], TOKEN_DECIMALS)
  local price, price_currency = parse_currency(item["pricePerToken"])
  local ticker = item["tokenTickerName"]
  local name = tostring(item["companyName"] or ticker or "beel Investment")
  if ticker and ticker ~= "" then name = name .. " (" .. ticker .. ")" end

  -- beel publishes no market price; the issue price is the only valuation.
  -- amount is in account currency (EUR), so it is only set for EUR prices.
  local amount
  if quantity and price and (price_currency == "EUR" or price_currency == nil) then
    amount = quantity * price
  end

  return {
    name                    = name,
    securityNumber          = ticker,
    market                  = "beel",
    quantity                = quantity,
    price                   = price,
    currencyOfPrice         = price_currency,
    purchasePrice           = price,
    currencyOfPurchasePrice = price_currency,
    amount                  = amount,
  }
end

function RefreshAccount(account, since)
  local securities = {}
  local balance = 0
  for _, item in ipairs(fetch_list_items()) do
    if HOLDING_STATUSES[item["status"]] then
      local sec = security_from_item(item)
      securities[#securities + 1] = sec
      balance = balance + (sec.amount or 0)
    end
  end
  return {
    balance    = balance,
    currency   = "EUR",
    securities = securities,
  }
end

function EndSession()
  -- The Privy token stays valid server-side and in LocalStorage on purpose,
  -- so the next sync within the hour needs no new code.
  g_email = nil
  g_me    = nil
  g_ca_id = nil
end
