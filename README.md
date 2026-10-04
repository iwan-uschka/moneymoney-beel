# MoneyMoney beel extension

Adds your [beel](https://beel.com) (formerly tokenize.it) investments to [MoneyMoney](https://moneymoney-app.com) as a portfolio account. beel signs you in with a 6-digit code sent to your email, and MoneyMoney asks for that code during sync.

## Prerequisites

- MoneyMoney 5.x
- A beel investor account that logs in by email (Google or wallet logins are not supported)

## Installation

1. Download `Beel.lua`
2. Open MoneyMoney → **Help → Show Database in Finder**
3. Copy the file into the `Extensions` folder
4. Restart MoneyMoney
5. Add a new account → search for **beel**
6. Enter your beel email address as the username and any value as the password

## Login flow

1. MoneyMoney starts a sync. The extension asks beel's login provider (Privy) to email you a code.
2. A dialog asks for the code. Enter the 6 digits from the email.
3. The extension exchanges the code for a session token and fetches your investments.

The session token is valid for one hour. The extension stores it in MoneyMoney's encrypted database, and syncs within that hour run without a new code. After the hour, the next sync needs a new code.

## Known limitations

- **Unsigned extension.** MoneyMoney warns that the extension is not from a verified developer. Allow unsigned extensions under MoneyMoney → Preferences → Extensions.
- **Dummy password.** MoneyMoney always shows a password field. The extension never uses or sends it. Check "Save password" so MoneyMoney stops asking for it.
- **No automatic background sync.** An automatic sync can't ask for a code, so it fails once the one-hour token has expired. Refresh the account manually instead.
- **Issue price only.** beel publishes no market price for its tokens. Positions are valued at the price per token you paid.
- **Holdings only.** The extension lists accepted private offers, successful public fundraising investments and active or fulfilled employee participation plans. Pending, cancelled and burned items are skipped. There is no transaction history.
- **Non-euro positions.** Positions priced in USDC show their price, but the extension can't convert them to EUR, so they don't count toward the account balance.

## Technical reference

| Component | Detail |
|---|---|
| Auth | Privy passwordless email login (`privy.app.beel.com/api/v1/passwordless/*`) |
| Session | Privy access token sent as the `privy-token` cookie to `app.beel.com` |
| Data | tRPC query `investor.getFundraiseListItems`, 50 items per page |
| Token amounts | Integer strings with 18 implied decimals |
| Prices | Integer strings: 2 decimals for €, 6 for USDC/EUROC, 18 for EURe |

## Development

```sh
luac -p Beel.lua     # syntax check
lua tests/run.lua    # offline tests against stubbed MoneyMoney API
```
