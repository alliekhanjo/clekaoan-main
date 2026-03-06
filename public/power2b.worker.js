"use strict";

importScripts("./power2b.legacy.worker.js");

const legacyOnMessage = self.onmessage;

importScripts("./vendor/hash-wasm/index.umd.min.js");
importScripts("./vendor/x11-hash-js/x11-hash.min.js");

const HASH_WASM = self.hashwasm;
const X11_HASH = typeof self.require === "function" ? self.require("x11hash") : null;

const CUSTOM_ALGOS = new Set(["cwm_rinhash", "cwm_qubit"]);
const UINT32_MAX = 0xffffffff;
const HASHRATE_REPORT_MS = 1000;
const ARGON_SALT = "RinCoinSalt";
const FULL_128 = (1n << 128n) - 1n;
const MAX_256 = (1n << 256n) - 1n;

function ensureLegacyHandler() {
    if (typeof legacyOnMessage !== "function") {
        throw new Error("Legacy worker handler was not initialized.");
    }
}

function ensureCustomDeps() {
    if (!HASH_WASM) {
        throw new Error("hash-wasm failed to load in worker context.");
    }
    if (!X11_HASH) {
        throw new Error("x11-hash-js failed to load in worker context.");
    }
}

function postLog(message) {
    postMessage({ type: "log", message: String(message) });
}

function normalizeWork(work) {
    const normalized = { ...(work || {}) };
    if (!normalized.extraNonce2Size) normalized.extraNonce2Size = 4;
    if (normalized.ntime === true) normalized.ntime = "00000001";
    if (normalized.ntime === false) normalized.ntime = "00000000";
    return normalized;
}

function hexToBytes(hex) {
    const clean = String(hex || "").trim();
    if (clean.length % 2 !== 0) {
        throw new Error(`Invalid hex length: ${clean.length}`);
    }

    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i += 1) {
        hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
}

function swapWordHex(hex) {
    const clean = String(hex || "").trim();
    if (clean.length % 8 !== 0) {
        throw new Error(`Invalid 32-bit word hex length: ${clean.length}`);
    }

    let swapped = "";
    for (let i = 0; i < clean.length; i += 8) {
        const word = clean.slice(i, i + 8);
        swapped += word.slice(6, 8) + word.slice(4, 6) + word.slice(2, 4) + word.slice(0, 2);
    }
    return swapped;
}

function swapWordBytes(input) {
    const output = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i += 4) {
        output[i] = input[i + 3];
        output[i + 1] = input[i + 2];
        output[i + 2] = input[i + 1];
        output[i + 3] = input[i];
    }
    return output;
}

async function doubleSha256Hex(hex) {
    const first = await HASH_WASM.sha256(hexToBytes(hex));
    return HASH_WASM.sha256(hexToBytes(first));
}

function setNonceLittleEndian(buffer, nonce) {
    buffer[76] = nonce & 0xff;
    buffer[77] = (nonce >>> 8) & 0xff;
    buffer[78] = (nonce >>> 16) & 0xff;
    buffer[79] = (nonce >>> 24) & 0xff;
}

function setNonceBigEndian(buffer, nonce) {
    buffer[76] = (nonce >>> 24) & 0xff;
    buffer[77] = (nonce >>> 16) & 0xff;
    buffer[78] = (nonce >>> 8) & 0xff;
    buffer[79] = nonce & 0xff;
}

function randomBytes(length) {
    const bytes = new Uint8Array(length);
    if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function") {
        globalThis.crypto.getRandomValues(bytes);
        return bytes;
    }

    for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
}

function randomUint32() {
    const bytes = randomBytes(4);
    return (
        bytes[0]
        | (bytes[1] << 8)
        | (bytes[2] << 16)
        | (bytes[3] << 24)
    ) >>> 0;
}

function nowMs() {
    return Date.now();
}

function formatSubmitHashrate(startNonce, endNonce, maxNonce, endMs, startMs) {
    const elapsedSeconds = (endMs - startMs) / 1000;
    if (elapsedSeconds <= 0) return 0;
    const hashes = endNonce >= startNonce
        ? (endNonce - startNonce + 1)
        : (maxNonce - startNonce + endNonce + 2);
    return hashes / elapsedSeconds / 1000;
}

function reportHashrate(scanned, startedAtMs) {
    const elapsedMs = nowMs() - startedAtMs;
    if (scanned <= 0 || elapsedMs <= 0) return;
    postMessage({
        type: "hashrate",
        value: (scanned / (elapsedMs / 1000)) / 1000
    });
}

function decimalToFraction(value) {
    let raw = String(value ?? "").trim().toLowerCase();
    if (!raw || raw === "nan" || raw === "infinity" || raw === "+infinity" || raw === "-infinity") {
        throw new Error(`Invalid difficulty value: ${value}`);
    }

    if (raw.startsWith("+")) {
        raw = raw.slice(1);
    }
    if (raw.startsWith("-")) {
        throw new Error(`Difficulty must be positive: ${value}`);
    }

    let exponent = 0;
    const exponentIndex = raw.indexOf("e");
    if (exponentIndex !== -1) {
        exponent = Number.parseInt(raw.slice(exponentIndex + 1), 10);
        if (!Number.isFinite(exponent)) {
            throw new Error(`Invalid difficulty exponent: ${value}`);
        }
        raw = raw.slice(0, exponentIndex);
    }

    const parts = raw.split(".");
    if (parts.length > 2) {
        throw new Error(`Invalid difficulty format: ${value}`);
    }

    const integerPart = parts[0] || "0";
    const fractionalPart = parts[1] || "";
    if (!/^\d+$/.test(integerPart) || (fractionalPart && !/^\d+$/.test(fractionalPart))) {
        throw new Error(`Invalid difficulty format: ${value}`);
    }

    let digits = `${integerPart}${fractionalPart}`.replace(/^0+(?=\d)/, "");
    let scale = fractionalPart.length - exponent;

    if (!digits) {
        digits = "0";
    }

    if (scale < 0) {
        digits += "0".repeat(-scale);
        scale = 0;
    }

    const numerator = BigInt(digits);
    if (numerator <= 0n) {
        throw new Error(`Difficulty must be positive: ${value}`);
    }

    return {
        numerator,
        denominator: 10n ** BigInt(scale)
    };
}

function difficultyToTarget(diff) {
    const { numerator, denominator } = decimalToFraction(diff);
    const highWords = (denominator << 96n) / numerator;
    const target = (highWords << 128n) + FULL_128;
    return target > MAX_256 ? MAX_256 : target;
}

function littleEndianBytesToBigInt(bytes) {
    let value = 0n;
    for (let i = bytes.length - 1; i >= 0; i -= 1) {
        value = (value << 8n) + BigInt(bytes[i]);
    }
    return value;
}

function hashMeetsTarget(hashBytes, target) {
    return littleEndianBytesToBigInt(hashBytes) <= target;
}

async function buildHeaderTemplate(work, extranonce2Hex) {
    let merkleRoot = await doubleSha256Hex(
        `${work.coinb1}${work.extraNonce1}${extranonce2Hex}${work.coinb2}`
    );

    for (const branch of (work.merkle_branch || [])) {
        merkleRoot = await doubleSha256Hex(`${merkleRoot}${branch}`);
    }

    const headerHex = (
        swapWordHex(work.version)
        + swapWordHex(work.prevhash)
        + merkleRoot
        + swapWordHex(work.ntime)
        + swapWordHex(work.nbits)
        + "00000000"
    );

    return hexToBytes(headerHex);
}

async function rinhashBytes(headerBytes) {
    const blake3Hex = await HASH_WASM.blake3(headerBytes);
    const argonOutput = await HASH_WASM.argon2d({
        password: hexToBytes(blake3Hex),
        salt: ARGON_SALT,
        iterations: 2,
        memorySize: 64,
        parallelism: 1,
        hashLength: 32,
        outputType: "binary"
    });
    return hexToBytes(await HASH_WASM.sha3(argonOutput, 256));
}

function qubitBytes(headerBytes) {
    let value = X11_HASH.luffa(Array.from(headerBytes), 1, 2);
    value = X11_HASH.cubehash(value, 2, 2);
    value = X11_HASH.shavite(value, 2, 2);
    value = X11_HASH.simd(value, 2, 2);
    const output = X11_HASH.echo(value, 2, 1);
    return Uint8Array.from(output.slice(0, 32));
}

async function mineCustomAlgo(algo, work) {
    ensureCustomDeps();

    const normalizedWork = normalizeWork(work);
    const target = difficultyToTarget(normalizedWork.miningDiff);

    for (;;) {
        const extranonce2Hex = bytesToHex(randomBytes(normalizedWork.extraNonce2Size));
        const startNonce = randomUint32();
        const batchStartedAt = nowMs();
        let lastReportAt = batchStartedAt;
        let lastReportedNonce = startNonce;

        const baseHeader = await buildHeaderTemplate(normalizedWork, extranonce2Hex);
        const rinhashHeader = algo === "cwm_rinhash" ? baseHeader : null;
        const qubitHeader = algo === "cwm_qubit" ? swapWordBytes(baseHeader) : null;
        let foundShare = false;

        for (let nonce = startNonce; nonce <= UINT32_MAX; nonce += 1) {
            if (rinhashHeader) {
                setNonceLittleEndian(rinhashHeader, nonce >>> 0);
                const hash = await rinhashBytes(rinhashHeader);
                if (hashMeetsTarget(hash, target)) {
                    const endedAt = nowMs();
                    postMessage({
                        type: "submit",
                        hashrate: formatSubmitHashrate(startNonce, nonce >>> 0, UINT32_MAX, endedAt, batchStartedAt),
                        data: {
                            job_id: normalizedWork.jobId,
                            extranonce2: extranonce2Hex,
                            ntime: normalizedWork.ntime,
                            nonce: (nonce >>> 0).toString(16).padStart(8, "0")
                        }
                    });
                    foundShare = true;
                    break;
                }
            } else if (qubitHeader) {
                setNonceBigEndian(qubitHeader, nonce >>> 0);
                const hash = qubitBytes(qubitHeader);
                if (hashMeetsTarget(hash, target)) {
                    const endedAt = nowMs();
                    postMessage({
                        type: "submit",
                        hashrate: formatSubmitHashrate(startNonce, nonce >>> 0, UINT32_MAX, endedAt, batchStartedAt),
                        data: {
                            job_id: normalizedWork.jobId,
                            extranonce2: extranonce2Hex,
                            ntime: normalizedWork.ntime,
                            nonce: (nonce >>> 0).toString(16).padStart(8, "0")
                        }
                    });
                    foundShare = true;
                    break;
                }
            }

            const now = nowMs();
            if ((now - lastReportAt) >= HASHRATE_REPORT_MS) {
                reportHashrate((nonce >>> 0) - (lastReportedNonce >>> 0) + 1, lastReportAt);
                lastReportAt = now;
                lastReportedNonce = (nonce + 1) >>> 0;
            }
        }

        if (!foundShare) {
            reportHashrate(UINT32_MAX - (lastReportedNonce >>> 0) + 1, lastReportAt);
        }
    }
}

self.onmessage = (event) => {
    const payload = event && event.data ? event.data : {};
    const algo = payload.algo;

    if (!CUSTOM_ALGOS.has(algo)) {
        ensureLegacyHandler();
        legacyOnMessage(event);
        return;
    }

    mineCustomAlgo(algo, payload.work).catch((error) => {
        postLog(error && error.stack ? error.stack : error);
        postMessage({ type: "submit", data: null });
    });
};