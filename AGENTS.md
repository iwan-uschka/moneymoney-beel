# MoneyMoney beel project notes

Single-file MoneyMoney WebBanking extension (`Beel.lua`, Lua 5.3+).
Syntax check: `luac -p Beel.lua`. Offline tests: `lua tests/run.lua` (stubs
the MoneyMoney API and replays synthetic responses). A live sync in
MoneyMoney with a beel account is still the only end-to-end check.

Test fixtures must stay synthetic. Never copy names, emails, addresses,
IBANs, wallet addresses or tokens from a recorded HAR into this repo.

## beel / Privy API (from a recorded browser session, 2026-10-04)

- Login is Privy passwordless email (Privy app id `cm8epvw1k00dkuxlpmreca9n2`,
  custom API host `privy.app.beel.com`):
  - `POST /api/v1/passwordless/init` with `{"email": ...}` returns `{"success":true}`.
    Rate limit header says 5 requests per window.
  - `POST /api/v1/passwordless/authenticate` with
    `{"email","code","mode":"login-or-sign-up"}` returns `token` (access JWT,
    ES256, `exp` = `iat` + 3600), `identity_token`, `is_new_user`.
    `refresh_token` is the literal `"deprecated"`, so there is no refresh.
  - Requests carry `privy-app-id`, `privy-client-id`, `privy-client`,
    `privy-ca-id` (random UUID per client) and `Origin: https://app.beel.com`.
- The tRPC API at `app.beel.com/api/trpc/` gets no `Authorization` header in
  the browser. The HAR export stripped cookies, so the auth cookie is
  inferred: the app bundle defines `PRIVY_TOKEN_NAME = "privy-token"` and
  `PRIVY_ID_TOKEN_NAME = "privy-id-token"`. The extension sets both plus
  `privy-session=t`. A live sync confirmed this works (2026-10-04).
- After login the browser also calls `login.addPrivyUser` (syncs the Privy
  user into beel's DB; returned `existingLogin:null` for an existing user).
  The extension skips it; the live sync worked without it for an existing user.
- tRPC uses superjson. Batched GET: `?batch=1&input={"0":{"json":...}}`;
  null input is `{"json":null,"meta":{"values":["undefined"],"v":1}}`.
  Errors come back as `[{"error":{"json":{"message","data":{"code","httpStatus"}}}}]`.
- `investor.getFundraiseListItems` takes `paginationAndSearchInput`
  (`pageIndex`, `pageSize` max 50, `searchQuery`), `productTypeFilter`
  (`"All"`) and `statusFilter` (`"all"`). Records hold `companyName`,
  `tokenTickerName`, `productType`, `status`, `shareAmount`, `pricePerToken`.
- Custom superjson types (from the app bundle):
  - `Token`: bigint string, 18 decimals.
  - `Currency`: JSON string `{"tickerName","value"}`; decimals 6 for Circle
    coins (USDC, EUROC), 18 for EURe, otherwise 2 (`€` = cents).
- Status enums: PrivateOffer `Accepted|Burned|Cancelled|Expired|Failed|
  NeedConfirmation|Pending|PendingForInvestor|RejectedByInvestor`;
  PublicFundraisingInvestment `PendingForConcedusApproval|RejectedByConcedus|
  ReadyToBeSigned|WaitingForFunds|Successful|Failed|Expired|Cancelled`;
  EmployeeParticipationPlan `Active|Failed|Fulfilled|NeedConfirmation|
  PendingForEmployee|RejectedByEmployee|RejectedByFounder|Stopped|
  WaitingForInclusion`. The extension treats `Accepted`, `Successful`,
  `Active`, `Fulfilled` as holdings.
- beel exposes no market price; positions are valued at `pricePerToken`.

## MoneyMoney Lua API gotchas

- `Connection:get`/`Connection:post` take no headers argument. Custom headers
  only work via `Connection:request(method, url, postContent, postContentType, headers)`.
- Cookie storage is per script execution and shared by all Connections.
  `connection:setCookie` takes `Set-Cookie` syntax.
- Two-step login uses `InitializeSession2(protocol, bankCode, step,
  credentials, interactive)`. Step 1 gets username/password, later steps get
  the challenge answer in `credentials[1]`. Returning a table
  `{title, challenge, label}` shows a text-input dialog; returning a string
  shows it as an error. With `interactive == false` the extension must not
  ask for input.
- `LocalStorage` persists per account across syncs; the extension keeps the
  Privy token there (`privyToken`, `privyIdToken`, `privyEmail`).
- Security table fields: WKN is `securityNumber`, exchange name is `market`.
  MoneyMoney ignores unknown fields, so a misspelled field fails without error.
- MoneyMoney may keep serving a cached copy of the extension after the `.lua`
  file is replaced. Restart MoneyMoney before judging which version ran.
