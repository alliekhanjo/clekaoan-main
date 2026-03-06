const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parentPort } = require("worker_threads");
const { performance } = require("perf_hooks");

function resolvePublicDir() {
    const candidates = [];
    const seen = new Set();
    const addCandidate = (dir) => {
        const normalized = path.resolve(dir);
        if (!seen.has(normalized)) {
            seen.add(normalized);
            candidates.push(normalized);
        }
    };

    if (process.env.MINER_PUBLIC_DIR) {
        addCandidate(process.env.MINER_PUBLIC_DIR);
    }

    // Prefer local self-contained folder first.
    addCandidate(path.resolve(__dirname, "public"));
    // Usual layout in monorepo: terminal-miner/* with ../public/*
    addCandidate(path.resolve(__dirname, "..", "public"));
    // Fallback to runtime cwd/public
    addCandidate(path.resolve(process.cwd(), "public"));

    for (const dir of candidates) {
        if (fs.existsSync(path.join(dir, "power2b.worker.js"))) {
            return dir;
        }
    }

    throw new Error(
        `Could not find public directory with power2b.worker.js. Checked: ${candidates.join(", ")}`
    );
}

const PUBLIC_DIR = resolvePublicDir();
const POWER2B_WORKER_PATH = path.join(PUBLIC_DIR, "power2b.worker.js");

function resolveImportPath(scriptPath) {
    if (/^https?:\/\//i.test(scriptPath)) {
        throw new Error(`importScripts URL is not supported in CLI mode: ${scriptPath}`);
    }

    if (scriptPath.startsWith("/")) {
        return path.resolve(PUBLIC_DIR, scriptPath.replace(/^\/+/, ""));
    }

    if (path.isAbsolute(scriptPath)) {
        return scriptPath;
    }

    return path.resolve(path.dirname(POWER2B_WORKER_PATH), scriptPath);
}

function importScriptsShim(...scripts) {
    for (const script of scripts) {
        const absolute = resolveImportPath(script);
        const source = fs.readFileSync(absolute, "utf8");
        vm.runInThisContext(source, { filename: absolute });
    }
}

globalThis.self = globalThis;
globalThis.location = {
    href: `file://${POWER2B_WORKER_PATH.replace(/\\/g, "/")}`
};
globalThis.performance = globalThis.performance || performance;
globalThis.importScripts = importScriptsShim;
globalThis.atob = globalThis.atob || ((value) => Buffer.from(value, "base64").toString("binary"));
globalThis.btoa = globalThis.btoa || ((value) => Buffer.from(value, "binary").toString("base64"));
globalThis.postMessage = (message) => parentPort.postMessage(message);
globalThis.onmessage = null;

// Force the bundled worker to run its browser-worker code path instead of Node path.
globalThis.process = undefined;

parentPort.on("message", (data) => {
    if (typeof globalThis.onmessage === "function") {
        globalThis.onmessage({ data });
    }
});

const workerSource = fs.readFileSync(POWER2B_WORKER_PATH, "utf8");
vm.runInThisContext(workerSource, { filename: POWER2B_WORKER_PATH });
