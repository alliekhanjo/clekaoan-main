# Terminal Miner

This folder contains a separate terminal miner so you do not need to open the browser UI.

## Requirements

- Node.js `22+` (recommended), or
- Node.js with `ws` package installed (`npm i ws`)

## Files

- `terminal-miner/config.json`: your miner settings (wallet, pool/proxy, algo, threads)
- `terminal-miner/cli.cjs`: CLI entry point
- `terminal-miner/core.cjs`: stratum + worker control
- `terminal-miner/worker-bridge.cjs`: runs the browser worker in Node worker threads
- `terminal-miner/public/power2b.worker.js`: wrapper worker that delegates legacy algos and adds JS-only algos
- `terminal-miner/public/power2b.legacy.worker.js`: original bundled worker code required by CLI
- `terminal-miner/algorithms.cjs`: supported algo list and aliases

## Configure Wallet And Pool

Edit `terminal-miner/config.json`.

Example:

```json
{
    "host": "wss://ratty-adoree-ananta512-4abadf1a.koyeb.app/c3RyYXR1bS1ldS5ycGxhbnQueHl6OjcwMjI=",
    "port": 7022,
    "user": "BbDqruSg7LdJfXsxJQD9j3phupdBdLihVe",
    "pass": "x",
    "threads": 1,
    "algo": "cwm_power2B",
    "clientVersion": "webminer/1.0",
    "reuseWorkersOnDirtyJobs": true,
    "hashrateSmoothing": 0.25,
    "hashrateHoldMs": 10000,
    "proxy": "",
    "statsIntervalMs": 1000,
    "reconnectMaxAttempts": 3,
    "reconnectDelayMs": 300000
}
```

Field meaning:

- `host`: either a full websocket proxy URL (`wss://...`) or a raw pool host (like `stratum-eu.rplant.xyz`)
- `port`: pool port (used when `host` is a raw host)
- `user`: wallet / wallet.worker login
- `pass`: pool password (usually `x`)
- `threads`: number of CPU threads
- `algo`: algorithm value from the supported list below
- `clientVersion`: value sent in `mining.subscribe` (default `webminer/1.0`)
- `reuseWorkersOnDirtyJobs`: keep workers alive when `clean_jobs=false` to reduce respawn overhead
- `hashrateSmoothing`: smoothing factor `0..1` for displayed hashrate (`0.25` default)
- `hashrateHoldMs`: ignore brief zero reports for this long (default `10000`)
- `proxy`: websocket proxy base URL (only needed when `host` is not already a full `ws/wss` URL)
- `statsIntervalMs`: terminal refresh interval
- `reconnectMaxAttempts`: max reconnect tries after disconnect (`3` default)
- `reconnectDelayMs`: wait time between reconnect tries in milliseconds (`300000` = 5 minutes default)

Config aliases also supported:

- `wallet` or `worker` can be used instead of `user`
- `password` can be used instead of `pass`
- `workers` can be used instead of `threads`
- `algorithm` can be used instead of `algo`
- `version` can be used instead of `clientVersion`

## Run

From project root:

```bash
npm run mine
```

From project root with explicit paths:

```bash
node terminal-miner/cli.cjs --config terminal-miner/config.json
```

From inside `terminal-miner` folder:

```bash
npm install
node cli.cjs --config config.json
```

If you are on Node `22+`, `npm install` is optional (global WebSocket is already available).

This folder is now self-contained. You can upload only `terminal-miner/` to GitHub and run from that folder.

List supported algorithms:

```bash
npm run mine:list-algos
```

Or from inside `terminal-miner`:

```bash
node cli.cjs --list-algos
```

## Supported Algo Values

- `cwm_minotaurx`
- `cwm_yespower`
- `cwm_yespowerR16`
- `cwm_yespowerR32`
- `cwm_yespowerTIDE`
- `cwm_yespowerADVC`
- `cwm_ghostrider`
- `cwm_power2B`
- `cwm_qubit`
- `cwm_rinhash`
- `cwm_verushash`
- `cwm_yescrypt`
- `cwm_yescryptR8`
- `cwm_yescryptR16`
- `cwm_yescryptR32`

`cwm_rinhash` and `cwm_qubit` are implemented in the wrapper worker with vendored browser-compatible hash libraries. All other algorithms still delegate to the original `public/power2b.legacy.worker.js` bundle.

## Live Output

CLI shows one live line:

`Status | Hashrate | Accepted | Rejected`

Press `Ctrl+C` to stop.