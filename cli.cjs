#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const CliMiner = require("./core.cjs");
const { SUPPORTED_ALGOS, ALGO_LABELS, normalizeAlgo } = require("./algorithms.cjs");

const DEFAULT_CONFIG_PATH = path.resolve(__dirname, "config.json");

function printHelp() {
    console.log("Usage: node terminal-miner/cli.cjs [--config path] [--list-algos]");
    console.log("");
    console.log("Options:");
    console.log(`  --config <path>   Path to JSON config file (default: ${DEFAULT_CONFIG_PATH})`);
    console.log("  --list-algos      Print supported algorithm values");
    console.log("  --help            Show this help");
}

function parseArgs(argv) {
    const options = {
        configPath: DEFAULT_CONFIG_PATH,
        listAlgos: false,
        help: false
    };

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === "--help" || arg === "-h") {
            options.help = true;
            continue;
        }
        if (arg === "--list-algos") {
            options.listAlgos = true;
            continue;
        }
        if (arg === "--config" || arg === "-c") {
            const value = argv[i + 1];
            if (!value) {
                throw new Error("--config requires a file path.");
            }
            options.configPath = path.resolve(process.cwd(), value);
            i++;
            continue;
        }
        throw new Error(`Unknown argument: ${arg}`);
    }

    return options;
}

function printAlgoList() {
    console.log("Supported algorithms:");
    for (const algo of SUPPORTED_ALGOS) {
        console.log(`- ${algo}: ${ALGO_LABELS[algo] || ""}`.trimEnd());
    }
}

function readConfig(configPath) {
    const raw = fs.readFileSync(configPath, "utf8");
    const config = JSON.parse(raw);
    if (!config.user && config.wallet) config.user = config.wallet;
    if (!config.user && config.worker) config.user = config.worker;
    if (config.pass == null && config.password != null) config.pass = config.password;
    if (config.threads == null && config.workers != null) config.threads = config.workers;
    config.algo = normalizeAlgo(config.algo || config.algorithm, { strict: true });
    return config;
}

function validateConfig(config) {
    const missing = [];
    if (!config.host) missing.push("host");
    if (!config.user) missing.push("user");
    if (config.pass == null) missing.push("pass");
    if (!Number.isFinite(Number(config.threads))) missing.push("threads");

    if (missing.length > 0) {
        throw new Error(`Missing/invalid required config fields: ${missing.join(", ")}`);
    }
}

function formatHashrate(hashrate) {
    const value = Number(hashrate) || 0;
    if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)} MH/s`;
    if (value >= 1_000) return `${(value / 1_000).toFixed(2)} kH/s`;
    return `${value.toFixed(2)} H/s`;
}

function createLine(state) {
    return `Status: ${state.status} | Hashrate: ${formatHashrate(state.hashrate)} | Accepted: ${state.accepted} | Rejected: ${state.rejected}`;
}

function main() {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
        printHelp();
        return;
    }

    if (options.listAlgos) {
        printAlgoList();
        return;
    }

    const config = readConfig(options.configPath);
    validateConfig(config);
    const alphaRaw = Number(config.hashrateSmoothing);
    const hashrateSmoothing = Number.isFinite(alphaRaw)
        ? Math.max(0, Math.min(1, alphaRaw))
        : 0.25;
    const holdRaw = Number(config.hashrateHoldMs);
    const hashrateHoldMs = Number.isFinite(holdRaw) && holdRaw >= 0 ? holdRaw : 10000;

    const state = {
        status: "Idle",
        hashrate: 0,
        accepted: 0,
        rejected: 0
    };

    const miner = new CliMiner(config);
    const statsIntervalMs = Number(config.statsIntervalMs) || 1000;
    let lastLineLength = 0;
    let isShuttingDown = false;
    let outputBroken = false;
    let smoothedHashrate = 0;
    let lastNonZeroRawHashrate = 0;
    let lastNonZeroAt = 0;
    let lastHashrateUpdateAt = 0;

    function updateDisplayHashrate(rawValue) {
        const now = Date.now();
        const raw = Number(rawValue) || 0;
        lastHashrateUpdateAt = now;

        if (raw > 0) {
            lastNonZeroRawHashrate = raw;
            lastNonZeroAt = now;
        } else if (lastNonZeroRawHashrate > 0 && (now - lastNonZeroAt) <= hashrateHoldMs) {
            // Ignore brief 0 reports from worker handoff/report gaps.
            return;
        }

        if (smoothedHashrate <= 0 || hashrateSmoothing >= 1) {
            smoothedHashrate = raw;
        } else {
            smoothedHashrate = (hashrateSmoothing * raw) + ((1 - hashrateSmoothing) * smoothedHashrate);
        }

        if (raw === 0 && smoothedHashrate < 0.5) {
            smoothedHashrate = 0;
        }

        state.hashrate = smoothedHashrate;
    }

    function safeWrite(text) {
        if (outputBroken) return;
        if (!process.stdout || process.stdout.destroyed || !process.stdout.writable) {
            outputBroken = true;
            return;
        }
        try {
            process.stdout.write(text);
        } catch (err) {
            if (err && err.code === "EPIPE") {
                outputBroken = true;
                clearInterval(renderTimer);
                return;
            }
            throw err;
        }
    }

    function render() {
        if (outputBroken) return;

        if (smoothedHashrate > 0) {
            const idleMs = Date.now() - lastHashrateUpdateAt;
            if (idleMs > hashrateHoldMs) {
                smoothedHashrate *= 0.97;
                if (smoothedHashrate < 0.5) smoothedHashrate = 0;
                state.hashrate = smoothedHashrate;
            }
        }

        const line = createLine(state);
        const padded = line.padEnd(Math.max(lastLineLength, line.length), " ");
        safeWrite(`\r${padded}`);
        lastLineLength = line.length;
    }

    function log(message) {
        if (outputBroken) {
            console.log(message);
            return;
        }
        const clear = " ".repeat(lastLineLength || 0);
        safeWrite(`\r${clear}\r`);
        console.log(message);
    }

    function shutdown(code = 0) {
        if (isShuttingDown) return;
        isShuttingDown = true;
        clearInterval(renderTimer);
        try {
            miner.stop();
        } catch (_) {
            // Ignore shutdown errors.
        }
        render();
        safeWrite("\n");
        process.exit(code);
    }

    miner.on("status", (status) => {
        state.status = status;
    });

    miner.on("hashrate", (value) => {
        updateDisplayHashrate(value);
    });

    miner.on("stats", (stats) => {
        state.accepted = Number(stats.accepted) || 0;
        state.rejected = Number(stats.rejected) || 0;
        updateDisplayHashrate(stats.hashrate);
    });

    miner.on("error", (err) => {
        const message = err && err.message ? err.message : String(err);
        log(`[error] ${message}`);
    });

    miner.on("close", () => {
        log("[info] Socket closed.");
    });

    const renderTimer = setInterval(render, statsIntervalMs);
    process.stdout.on("error", (err) => {
        if (err && err.code === "EPIPE") {
            outputBroken = true;
            clearInterval(renderTimer);
        }
    });

    log(`[info] Starting miner with algo=${config.algo}, threads=${config.threads}`);
    log(`[info] Config path: ${options.configPath}`);
    miner.start();
    render();

    process.on("SIGINT", () => shutdown(0));
    process.on("SIGTERM", () => shutdown(0));
}

try {
    main();
} catch (err) {
    const message = err && err.message ? err.message : String(err);
    console.error(`[fatal] ${message}`);
    process.exit(1);
}
